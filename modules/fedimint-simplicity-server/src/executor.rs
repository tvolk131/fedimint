//! Runs program decoding and execution on dedicated threads, so this work never
//! occupies the async runtime that serves the API and drives consensus.
//!
//! Agreed transactions and API submissions use separate pools, so agreed
//! transactions never queue behind submissions. The pools still share the
//! machine's cores with each other and with the runtime.
//!
//! Neither pool refuses work, since clients would read a refusal as an invalid
//! transaction. Instead each submission waits for an [`Admission`] before it
//! decodes anything, and keeps it until its decoded programs are freed. This
//! bounds how many submissions hold decoded programs at once. Connection limits
//! do not bound this, because API requests outlive their connections.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::{Arc, OnceLock};

use anyhow::Context as _;
use fedimint_server_core::TxProcessingMode;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::metrics;

/// Far more than decoding or execution of a bounded program needs, and
/// generous next to an async worker thread. The OS only commits the pages a
/// thread touches.
const STACK_BYTES: usize = 64 * 1024 * 1024;

static POOLS: OnceLock<Pools> = OnceLock::new();

struct Pools {
    /// Consensus applies one transaction at a time.
    consensus: rayon::ThreadPool,
    submission: rayon::ThreadPool,
    admission: Arc<Semaphore>,
}

impl Pools {
    fn new() -> anyhow::Result<Self> {
        let threads = submission_threads();
        Ok(Self {
            consensus: pool("simplicity-consensus", 1)?,
            submission: pool("simplicity-submission", threads)?,
            admission: Arc::new(Semaphore::new(admission_permits(threads))),
        })
    }

    fn pool(&self, mode: TxProcessingMode) -> &rayon::ThreadPool {
        match mode {
            TxProcessingMode::Consensus => &self.consensus,
            TxProcessingMode::Submission => &self.submission,
        }
    }
}

/// Leave capacity for the consensus thread and the async runtime.
fn submission_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |threads| threads.get() / 2)
        .clamp(1, 8)
}

/// Lets each submission thread have a job queued while the next submission
/// reads the database.
fn admission_permits(submission_threads: usize) -> usize {
    2 * submission_threads
}

fn pool(name: &'static str, threads: usize) -> anyhow::Result<rayon::ThreadPool> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .stack_size(STACK_BYTES)
        .thread_name(move |index| format!("{name}-{index}"))
        .build()
        .with_context(|| format!("failed to start the {name} worker threads"))
}

/// Start the worker threads during module start-up, so a failure stops the
/// guardian there instead of at its first Simplicity transaction.
pub(crate) fn start() -> anyhow::Result<()> {
    if POOLS.get().is_none() {
        // If another caller won the race, its pools are kept and these exit.
        let _ = POOLS.set(Pools::new()?);
    }
    Ok(())
}

fn pools() -> &'static Pools {
    // Module start-up has already started them, except in tests and benchmarks.
    POOLS.get_or_init(|| Pools::new().expect("the OS can start the Simplicity worker threads"))
}

/// Permission for one transaction attempt to decode and execute programs on
/// its mode's pool. A submission's admission holds a permit, which is released
/// when the last clone drops. Consensus is never limited.
#[derive(Clone)]
pub(crate) struct Admission {
    mode: TxProcessingMode,
    /// Held only to be released on drop.
    _permit: Option<Arc<OwnedSemaphorePermit>>,
}

impl Admission {
    /// Wait until this attempt may hold decoded programs. Submissions are
    /// admitted in arrival order. Dropping the future gives up the place in
    /// line without taking a permit.
    pub(crate) async fn acquire(mode: TxProcessingMode) -> Self {
        Self::acquire_from(&pools().admission, mode).await
    }

    async fn acquire_from(permits: &Arc<Semaphore>, mode: TxProcessingMode) -> Self {
        let permit = match mode {
            TxProcessingMode::Consensus => None,
            TxProcessingMode::Submission => {
                let _waiting = Waiting::start();
                let permit = permits
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("the admission semaphore is never closed");
                Some(Arc::new(permit))
            }
        };
        Self {
            mode,
            _permit: permit,
        }
    }

    /// For an attempt that decodes nothing, such as a transaction without
    /// Simplicity inputs.
    pub(crate) fn unlimited(mode: TxProcessingMode) -> Self {
        Self {
            mode,
            _permit: None,
        }
    }

    /// Run `job` on this attempt's pool and wait for its result. The job keeps
    /// the admission until it is done, even if the caller stops waiting. A
    /// panic in `job` resumes in the caller, as if the job had run inline.
    pub(crate) async fn run<T, F>(&self, job: F) -> T
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (sender, receiver) = futures::channel::oneshot::channel();
        let admission = self.clone();
        pools().pool(self.mode).spawn_fifo(move || {
            // Skip work nobody waits for anymore, e.g. after a websocket
            // request timed out. A client disconnecting does not cancel it.
            if sender.is_canceled() {
                drop(job);
            } else {
                // If the caller has gone meanwhile, the result drops here.
                let _ = sender.send(catch_unwind(AssertUnwindSafe(job)));
            }
            drop(admission);
        });
        match receiver
            .await
            .expect("the pool answers every job whose caller is still waiting")
        {
            Ok(value) => value,
            Err(panic) => resume_unwind(panic),
        }
    }

    /// Free `value` on a worker thread, then release this admission. Freeing a
    /// deeply nested program recurses, and worker threads have much larger
    /// stacks than the async runtime's.
    pub(crate) fn release<T: Send + 'static>(self, value: T) {
        pools().pool(self.mode).spawn_fifo(move || {
            drop(value);
            drop(self);
        });
    }
}

/// Counts a submission waiting for admission until it is admitted or gives up.
struct Waiting;

impl Waiting {
    fn start() -> Self {
        metrics::ADMISSION_WAITING.inc();
        Self
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        metrics::ADMISSION_WAITING.dec();
    }
}

/// Every submission permit but a few, held so tests can observe submissions
/// waiting.
#[cfg(test)]
pub(crate) struct HeldPermits {
    _permits: OwnedSemaphorePermit,
    _turn: tokio::sync::OwnedMutexGuard<()>,
}

/// Hold every submission permit but `free`. Callers take turns, so two tests
/// cannot each hold part of the permits while waiting for the rest.
#[cfg(test)]
pub(crate) async fn hold_permits(free: usize) -> HeldPermits {
    static TURN: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
        std::sync::LazyLock::new(Arc::default);
    let turn = TURN.clone().lock_owned().await;
    let pools = pools();
    // The pool's actual size, in case the available parallelism has changed.
    let held = admission_permits(pools.submission.current_num_threads())
        .checked_sub(free)
        .expect("tests leave fewer permits free than exist");
    let permits = pools
        .admission
        .clone()
        .acquire_many_owned(u32::try_from(held).expect("at most 16 permits"))
        .await
        .expect("the admission semaphore is never closed");
    HeldPermits {
        _permits: permits,
        _turn: turn,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use futures::FutureExt;

    use super::*;

    async fn eventually(condition: impl Fn() -> bool) {
        for _ in 0..500 {
            if condition() {
                return;
            }
            fedimint_core::runtime::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached within 5 s");
    }

    #[tokio::test]
    async fn runs_jobs_on_named_worker_threads() {
        for (mode, name) in [
            (TxProcessingMode::Consensus, "simplicity-consensus-"),
            (TxProcessingMode::Submission, "simplicity-submission-"),
        ] {
            let thread = Admission::unlimited(mode)
                .run(|| {
                    std::thread::current()
                        .name()
                        .expect("pool threads are named")
                        .to_owned()
                })
                .await;
            assert!(thread.starts_with(name), "{thread}");
        }
    }

    #[tokio::test]
    async fn panics_resume_in_the_caller_and_the_pool_survives() {
        let consensus = Admission::unlimited(TxProcessingMode::Consensus);
        let panic = AssertUnwindSafe(consensus.run(|| {
            panic!("job panicked");
        }))
        .catch_unwind()
        .await
        .expect_err("the panic reaches the awaiting caller");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"job panicked"));
        assert_eq!(consensus.run(|| 7).await, 7);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_jobs_leave_the_runtime_free() {
        let ticks = async {
            for _ in 0..5 {
                fedimint_core::runtime::sleep(Duration::from_millis(10)).await;
            }
        };
        let submission = Admission::unlimited(TxProcessingMode::Submission);
        // Run inline, the job would block the only runtime thread and win.
        tokio::select! {
            biased;
            () = submission.run(|| {
                std::thread::sleep(Duration::from_millis(500));
            }) => panic!("the job blocked the runtime"),
            () = ticks => {}
        }
    }

    #[tokio::test]
    async fn jobs_get_a_large_stack() {
        fn depth(remaining: u32) -> u32 {
            let frame = std::hint::black_box([0u8; 1024]);
            if remaining == 0 {
                u32::from(frame[0])
            } else {
                depth(remaining - 1) + u32::from(frame[1])
            }
        }
        // About 16 MiB of frames, well past an 8 MiB default thread stack.
        let submission = Admission::unlimited(TxProcessingMode::Submission);
        assert_eq!(submission.run(|| depth(16_000)).await, 0);
    }

    #[tokio::test]
    async fn submissions_beyond_the_limit_wait_and_consensus_does_not() {
        let permits = Arc::new(Semaphore::new(2));
        let first = Admission::acquire_from(&permits, TxProcessingMode::Submission).await;
        let _second = Admission::acquire_from(&permits, TxProcessingMode::Submission).await;
        // Giving up a place in line takes no permit.
        assert!(
            Admission::acquire_from(&permits, TxProcessingMode::Submission)
                .now_or_never()
                .is_none()
        );
        assert!(
            Admission::acquire_from(&permits, TxProcessingMode::Consensus)
                .now_or_never()
                .is_some()
        );
        let clone = first.clone();
        drop(first);
        assert_eq!(permits.available_permits(), 0);
        drop(clone);
        assert_eq!(permits.available_permits(), 1);
    }

    #[tokio::test]
    async fn jobs_keep_their_admission_after_the_caller_stops_waiting() {
        let permits = Arc::new(Semaphore::new(1));
        let admission = Admission::acquire_from(&permits, TxProcessingMode::Submission).await;
        let (started, wait_started) = mpsc::channel();
        let (finish, wait_finish) = mpsc::channel::<()>();
        let mut caller = Box::pin(admission.run(move || {
            started.send(()).expect("test is waiting");
            let _ = wait_finish.recv();
        }));
        assert!(futures::poll!(&mut caller).is_pending());
        wait_started.recv().expect("job starts");
        drop(caller);
        drop(admission);
        assert_eq!(permits.available_permits(), 0);
        finish.send(()).expect("job is waiting");
        eventually(|| permits.available_permits() == 1).await;
    }

    #[tokio::test]
    async fn released_values_are_freed_on_a_worker_before_the_admission() {
        struct Probe(Arc<Semaphore>, mpsc::Sender<(String, usize)>);
        impl Drop for Probe {
            fn drop(&mut self) {
                let thread = std::thread::current().name().map(str::to_owned);
                let _ = self
                    .1
                    .send((thread.unwrap_or_default(), self.0.available_permits()));
            }
        }
        let permits = Arc::new(Semaphore::new(1));
        let admission = Admission::acquire_from(&permits, TxProcessingMode::Submission).await;
        let (sender, receiver) = mpsc::channel();
        admission.release(Probe(permits.clone(), sender));
        let (thread, available) = receiver.recv().expect("probe is freed");
        assert!(thread.starts_with("simplicity-submission-"), "{thread}");
        assert_eq!(available, 0);
        eventually(|| permits.available_permits() == 1).await;
    }

    #[tokio::test]
    async fn consensus_jobs_do_not_queue_behind_submissions() {
        let threads = submission_threads();
        let (started, wait_started) = mpsc::channel();
        let (finish, wait_finish) = mpsc::channel::<()>();
        let wait_finish = Arc::new(std::sync::Mutex::new(wait_finish));
        let submission = Admission::unlimited(TxProcessingMode::Submission);
        let mut blocked = Vec::new();
        for _ in 0..threads {
            let started = started.clone();
            let wait_finish = wait_finish.clone();
            let mut job = Box::pin(submission.run(move || {
                started.send(()).expect("test is waiting");
                let _ = wait_finish.lock().expect("not poisoned").recv();
            }));
            assert!(futures::poll!(&mut job).is_pending());
            blocked.push(job);
        }
        for _ in 0..threads {
            wait_started
                .recv()
                .expect("every submission thread is busy");
        }
        let consensus = Admission::unlimited(TxProcessingMode::Consensus);
        assert_eq!(consensus.run(|| 7).await, 7);
        for _ in 0..threads {
            finish.send(()).expect("a job is waiting");
        }
        futures::future::join_all(blocked).await;
    }
}
