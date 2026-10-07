//! Control individual authenticated responses to exercise ordered prefetch,
//! cancellation, and recovery checkpoints independently of network timing.
use std::sync::Mutex;

use tokio::sync::Semaphore;

use super::*;

#[derive(Debug)]
struct RangeApi {
    peers: BTreeSet<PeerId>,
    sessions: Vec<SessionOutcome>,
    gates: Vec<Semaphore>,
    requested: Mutex<Vec<u64>>,
    completed: Mutex<Vec<u64>>,
    active: AtomicUsize,
    maximum: AtomicUsize,
    fail_one: AtomicBool,
}

impl RangeApi {
    fn new(sessions: Vec<SessionOutcome>, paused: bool) -> Arc<Self> {
        Arc::new(Self {
            peers: public_keys().into_keys().collect(),
            gates: (0..sessions.len())
                .map(|_| Semaphore::new(if paused { 0 } else { 100 }))
                .collect(),
            sessions,
            requested: Mutex::new(vec![]),
            completed: Mutex::new(vec![]),
            active: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
            fail_one: AtomicBool::new(false),
        })
    }

    fn history(self: &Arc<Self>) -> SessionHistory {
        SessionHistory::new(
            GlobalFederationApiWithCache::new(RangeTransport(self.clone())).into(),
            ModuleDecoderRegistry::from_iter([(
                MODULE,
                crate::common::KIND,
                crate::common::SimplicityCommonInit::decoder(),
            )]),
            VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
            Some(public_keys()),
        )
    }
}

#[derive(Debug)]
struct RangeTransport(Arc<RangeApi>);

#[async_trait::async_trait]
impl IRawFederationApi for RangeTransport {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        &self.0.peers
    }
    fn self_peer(&self) -> Option<PeerId> {
        None
    }
    fn with_module(&self, _: u16) -> DynModuleApi {
        panic!("unexpected module query")
    }
    async fn request_raw(
        &self,
        _: PeerId,
        method: &str,
        params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        if method == "session_count" {
            return Ok(serde_json::json!(self.0.sessions.len() - 1));
        }
        assert_eq!(method, SESSION_STATUS_V2_ENDPOINT);
        let index: u64 = serde_json::from_value(params.params.clone()).unwrap();
        self.0.requested.lock().unwrap().push(index);
        let active = self.0.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.0.maximum.fetch_max(active, Ordering::SeqCst);
        struct Active<'a>(&'a AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _active = Active(&self.0.active);
        self.0.gates[index as usize]
            .acquire()
            .await
            .unwrap()
            .forget();
        let mut outcome = signed(self.0.sessions[index as usize].clone(), index);
        if index == 1 && self.0.fail_one.load(Ordering::SeqCst) {
            outcome.signatures.clear();
        }
        self.0.completed.lock().unwrap().push(index);
        Ok(
            serde_json::to_value(SerdeModuleEncodingBase64::from(&SessionStatusV2::Complete(
                outcome,
            )))
            .unwrap(),
        )
    }
    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, PeerStatus>> {
        Box::pin(futures::stream::empty())
    }
    async fn wait_for_initialized_connections(&self) {}
    async fn get_peer_connection(&self, _: PeerId) -> ServerResult<DynGuaridianConnection> {
        panic!("unexpected connection")
    }
}

#[tokio::test]
async fn prefetch_is_bounded_ordered_and_canceled_when_dropped() {
    let api = RangeApi::new(vec![session(&[]); 8], true);
    let history = api.history();
    let mut stream = Box::pin(history.sessions(0..8));
    assert!(futures::poll!(stream.next()).is_pending());
    assert_eq!(*api.requested.lock().unwrap(), vec![0, 1, 2, 3]);
    for index in [3, 2, 1] {
        api.gates[index].add_permits(1);
        assert!(futures::poll!(stream.next()).is_pending());
    }
    assert_eq!(*api.completed.lock().unwrap(), vec![3, 2, 1]);
    // Faster later responses cannot advance the consumer past a slow prefix.
    api.gates[0].add_permits(1);
    let (index, status) = stream.next().await.unwrap();
    assert_eq!(index, 0);
    assert!(status.is_ok());
    for expected in 1..4 {
        let (index, status) = stream.next().await.unwrap();
        assert_eq!(index, expected);
        assert!(status.is_ok());
    }
    assert!(futures::poll!(stream.next()).is_pending());
    assert_eq!(api.active.load(Ordering::SeqCst), 4);
    assert_eq!(api.maximum.load(Ordering::SeqCst), 4);
    drop(stream);
    assert_eq!(api.active.load(Ordering::SeqCst), 0);
    for gate in &api.gates {
        gate.add_permits(1);
    }
    let remaining = history.sessions(4..8).collect::<Vec<_>>().await;
    assert_eq!(
        remaining.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        vec![4, 5, 6, 7]
    );
    assert!(remaining.into_iter().all(|(_, status)| status.is_ok()));
}

#[tokio::test]
async fn failed_authentication_never_applies_a_prefetched_successor() {
    let store = wallet(database()).await;
    let receive = tx(
        1,
        &[],
        vec![output(&store, &ContractDescriptor::owner([3; 32]))],
    );
    let spend = tx(2, &[point(&receive)], vec![]);
    let api = RangeApi::new(
        vec![
            session(std::slice::from_ref(&receive)),
            session(&[]),
            session(std::slice::from_ref(&spend)),
        ],
        false,
    );
    api.fail_one.store(true, Ordering::SeqCst);
    let history = api.history();
    let progress = Mutex::new(vec![]);
    assert!(
        store
            .sync(&history, |next, end| progress
                .lock()
                .unwrap()
                .push((next, end)))
            .await
            .is_err()
    );
    assert_eq!(store.next_session().await, 1);
    assert!(store.is_recovering().await);
    assert_eq!(store.history().await.len(), 1);
    assert!(
        store
            .contracts()
            .await
            .iter()
            .all(|(_, c)| c.spent_by.is_none())
    );
    assert_eq!(*progress.lock().unwrap(), vec![(0, 3), (1, 3)]);
    api.fail_one.store(false, Ordering::SeqCst);
    // Resume with the same persisted prefix. Cached later authenticated
    // responses may be reused, but the missing prefix must first authenticate.
    let reopened = wallet(store.db.clone()).await;
    reopened.sync(&history, |_, _| {}).await.unwrap();
    assert!(!reopened.is_recovering().await);
    let expected = wallet(database()).await;
    expected.sync(&api.history(), |_, _| {}).await.unwrap();
    assert_eq!(reopened.history().await, expected.history().await);
    assert_eq!(reopened.contracts().await, expected.contracts().await);
    assert_eq!(reopened.history().await.len(), 2);
    assert_eq!(
        reopened.contracts().await[0].1.spent_by,
        Some(spend.tx_hash())
    );
}
