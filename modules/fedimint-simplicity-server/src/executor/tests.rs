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
