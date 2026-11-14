//! Judging failed runs from their members' evidence.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use mpc::direct;
use mpc::engine::{Params, Transport};
use mpc::replay::{Evidence, Received, Verdict, judge, replay};
use tokio::sync::mpsc;

type Message = (u64, Vec<u8>);

/// How party 0 misbehaves.
#[derive(Clone, Copy)]
enum Fault {
    None,
    /// Flip a bit in what it sends party 1 in this round.
    Tamper(u64),
    /// Stop before sending anything in this round.
    Silent(u64),
}

/// A transport that, like the guardians' API channels, records every message
/// as it arrives, so a party that gives up mid-round still has evidence of
/// what it got.
struct Lossy {
    party: usize,
    fault: Fault,
    senders: Vec<Option<mpsc::UnboundedSender<Message>>>,
    receivers: Vec<Option<mpsc::UnboundedReceiver<Message>>>,
    received: Arc<Mutex<Received>>,
}

fn mesh(parties: usize, fault: Fault) -> Vec<Lossy> {
    let mut transports: Vec<_> = (0..parties)
        .map(|party| Lossy {
            party,
            fault: if party == 0 { fault } else { Fault::None },
            senders: (0..parties).map(|_| None).collect(),
            receivers: (0..parties).map(|_| None).collect(),
            received: Arc::new(Mutex::new(vec![])),
        })
        .collect();

    for from in 0..parties {
        for to in 0..parties {
            if from != to {
                let (sender, receiver) = mpsc::unbounded_channel();

                transports[from].senders[to] = Some(sender);
                transports[to].receivers[from] = Some(receiver);
            }
        }
    }

    transports
}

impl Transport for Lossy {
    async fn exchange(&mut self, round: u64, mut outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        match self.fault {
            Fault::Silent(at) if at == round => bail!("Gone silent"),
            Fault::Tamper(at) if at == round => {
                if let Some(byte) = outgoing[1].first_mut() {
                    *byte ^= 2;
                }
            }
            _ => {}
        }

        for (sender, message) in self.senders.iter().zip(outgoing) {
            if let Some(sender) = sender {
                // A departed peer simply misses the message.
                let _ = sender.send((round, message));
            }
        }

        let parties = self.senders.len();

        self.received
            .lock()
            .expect("not poisoned")
            .push(vec![None; parties]);

        let mut incoming = vec![Vec::new(); parties];

        for (from, receiver) in self.receivers.iter_mut().enumerate() {
            let Some(receiver) = receiver else {
                continue;
            };

            let message = tokio::time::timeout(Duration::from_secs(20), receiver.recv()).await;

            let Ok(Some((received_round, message))) = message else {
                continue;
            };

            ensure!(received_round == round, "A peer is in another round");

            self.received.lock().expect("not poisoned")[usize::try_from(round)?][from] =
                Some(message.clone());

            incoming[from] = message;
        }

        let complete = self.received.lock().expect("not poisoned")[usize::try_from(round)?]
            .iter()
            .enumerate()
            .all(|(from, message)| from == self.party || message.is_some());

        ensure!(complete, "A peer went quiet");

        Ok(incoming)
    }
}

struct Run {
    params: Params,
    circuit: Arc<mpc::circuit::Circuit>,
    evidence: Vec<Evidence>,
    completed: Vec<bool>,
}

const CONTEXT: &[u8] = b"replay test";

fn seed(party: usize) -> [u8; 32] {
    [u8::try_from(party).expect("small") + 1; 32]
}

async fn run(fault: Fault) -> Run {
    let params = Params::new(3, 1).expect("valid");
    let circuit = Arc::new(direct::circuit(params, 1).expect("valid"));

    let tasks: Vec<_> = mesh(3, fault)
        .into_iter()
        .map(|mut transport| {
            let circuit = circuit.clone();

            fedimint_core::runtime::spawn("mpc party", async move {
                let party = transport.party;
                let result = direct::generate(
                    &mut transport,
                    params,
                    party,
                    1,
                    &circuit,
                    &seed(party),
                    CONTEXT,
                )
                .await;

                let received = transport.received.lock().expect("not poisoned").clone();

                (result.is_ok(), received)
            })
        })
        .collect();

    let mut evidence = vec![];
    let mut completed = vec![];

    for (party, task) in tasks.into_iter().enumerate() {
        let (ok, received) = task.await.expect("task completes");

        completed.push(ok);
        evidence.push(Evidence {
            seed: seed(party),
            received,
        });
    }

    Run {
        params,
        circuit,
        evidence,
        completed,
    }
}

async fn verdict(run: &Run, evidence: Vec<Option<Evidence>>, submitted: &[bool]) -> Verdict {
    judge(run.params, 1, &run.circuit, CONTEXT, &evidence, submitted)
        .await
        .expect("well-formed evidence")
}

fn all(run: &Run) -> Vec<Option<Evidence>> {
    run.evidence.iter().cloned().map(Some).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_honest_run_replays_exactly() {
    let run = run(Fault::None).await;

    assert_eq!(run.completed, vec![true; 3]);

    for party in 0..3 {
        let replay = replay(
            run.params,
            party,
            1,
            &run.circuit,
            CONTEXT,
            &run.evidence[party],
        )
        .await;

        assert!(replay.completed);
        assert!(replay.stalled.is_none());

        // What the replay sends is exactly what the others received.
        for recipient in (0..3).filter(|&r| r != party) {
            for (round, sent) in replay.sent.iter().enumerate() {
                assert_eq!(
                    run.evidence[recipient].received[round][party].as_ref(),
                    Some(&sent[recipient])
                );
            }
        }
    }

    // Nobody is to blame for a run everyone submitted; a member that
    // finished and did not submit is.
    assert_eq!(
        verdict(&run, all(&run), &[true; 3]).await,
        Verdict::default()
    );

    let verdict = verdict(&run, all(&run), &[true, true, false]).await;

    assert_eq!(verdict.culprits.into_iter().collect::<Vec<_>>(), vec![2]);
    assert!(verdict.disputes.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_message_convicts_its_sender() {
    for round in [0, 5, 400] {
        let run = run(Fault::Tamper(round)).await;

        assert!(!run.completed[1], "the victim aborts");

        let verdict = verdict(&run, all(&run), &[false; 3]).await;

        assert_eq!(
            verdict.culprits.into_iter().collect::<Vec<_>>(),
            vec![0],
            "tampering in round {round}"
        );
        assert!(verdict.disputes.is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_member_is_disputed_by_everyone_it_left_waiting() {
    let run = run(Fault::Silent(7)).await;

    assert_eq!(run.completed, vec![false; 3]);

    let verdict = verdict(&run, all(&run), &[false; 3]).await;

    assert!(verdict.culprits.is_empty());
    assert_eq!(
        verdict.disputes.into_iter().collect::<Vec<_>>(),
        vec![(0, 1), (0, 2)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hiding_evidence_convicts() {
    let run = run(Fault::None).await;

    // Withholding all evidence.
    let mut evidence = all(&run);

    evidence[2] = None;

    assert_eq!(
        verdict(&run, evidence, &[false; 3])
            .await
            .culprits
            .into_iter()
            .collect::<Vec<_>>(),
        vec![2]
    );

    // Truncating it to look like it was left waiting, while the others hold
    // what it sent afterwards.
    let mut evidence = all(&run);

    evidence[1].as_mut().expect("present").received.truncate(10);

    assert_eq!(
        verdict(&run, evidence, &[false; 3])
            .await
            .culprits
            .into_iter()
            .collect::<Vec<_>>(),
        vec![1]
    );
}
