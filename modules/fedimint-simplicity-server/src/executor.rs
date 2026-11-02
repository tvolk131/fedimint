//! Runs program decoding and execution on dedicated threads, so this work never
//! occupies the async runtime that serves the API and drives consensus.
//!
//! Agreed transactions and API submissions use separate pools, so queued
//! submissions never delay consensus. Neither pool refuses work. Clients would
//! read a refusal as an invalid transaction, and the API's connection limits
//! already bound how many submissions can wait.

use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::LazyLock;

use fedimint_server_core::TxProcessingMode;

/// Far more than decoding or execution of a bounded program needs, and
/// generous next to an async worker thread. The OS only commits the pages a
/// thread touches.
const STACK_BYTES: usize = 64 * 1024 * 1024;

/// Consensus applies one transaction at a time.
static CONSENSUS: LazyLock<rayon::ThreadPool> = LazyLock::new(|| pool("simplicity-consensus", 1));

static SUBMISSION: LazyLock<rayon::ThreadPool> =
    LazyLock::new(|| pool("simplicity-submission", submission_threads()));

/// Leave capacity for the consensus thread and the async runtime.
fn submission_threads() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |threads| threads.get() / 2)
        .clamp(1, 8)
}

fn pool(name: &'static str, threads: usize) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .stack_size(STACK_BYTES)
        .thread_name(move |index| format!("{name}-{index}"))
        .build()
        .expect("the OS can start the Simplicity worker threads")
}

/// Run `job` on the pool for `mode` and wait for its result. A panic in `job`
/// resumes in the caller, as if the job had run inline.
pub(crate) async fn run<T, F>(mode: TxProcessingMode, job: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = futures::channel::oneshot::channel();
    let pool = match mode {
        TxProcessingMode::Consensus => &*CONSENSUS,
        TxProcessingMode::Submission => &*SUBMISSION,
    };
    pool.spawn_fifo(move || {
        // Skip work nobody waits for anymore, e.g. after an API client
        // disconnected while its submission was queued.
        if sender.is_canceled() {
            return;
        }
        let _ = sender.send(catch_unwind(AssertUnwindSafe(job)));
    });
    match receiver
        .await
        .expect("the pool answers every job whose caller is still waiting")
    {
        Ok(value) => value,
        Err(panic) => resume_unwind(panic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_jobs_on_named_worker_threads() {
        for (mode, name) in [
            (TxProcessingMode::Consensus, "simplicity-consensus-"),
            (TxProcessingMode::Submission, "simplicity-submission-"),
        ] {
            let thread = run(mode, || {
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
        use futures::FutureExt;

        let panic = AssertUnwindSafe(run(TxProcessingMode::Consensus, || {
            panic!("job panicked");
        }))
        .catch_unwind()
        .await
        .expect_err("the panic reaches the awaiting caller");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"job panicked"));
        assert_eq!(run(TxProcessingMode::Consensus, || 7).await, 7);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_jobs_leave_the_runtime_free() {
        use std::time::Duration;

        let ticks = async {
            for _ in 0..5 {
                fedimint_core::runtime::sleep(Duration::from_millis(10)).await;
            }
        };
        // Run inline, the job would block the only runtime thread and win.
        tokio::select! {
            biased;
            () = run(TxProcessingMode::Submission, || {
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
        assert_eq!(run(TxProcessingMode::Submission, || depth(16_000)).await, 0);
    }
}
