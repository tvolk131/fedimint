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
        evidence.push(Evidence::new(seed(party), received));
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
async fn a_completely_silent_member_is_convicted_and_one_on_one_silence_without_relays_disputes() {
    // Party 0 stops sending to BOTH honest peers (1 and 2) in round 7:
    // `f + 1 = 2` distinct stalled victims prove party 0 is at fault.
    let run = run(Fault::Silent(7)).await;

    assert_eq!(run.completed, vec![false; 3]);

    let v = verdict(&run, all(&run), &[false; 3]).await;
    assert_eq!(v.culprits.into_iter().collect::<Vec<_>>(), vec![0]);
    assert!(v.disputes.is_empty());

    // Conversely, if only ONE peer (party 1) lacks party 0's round 7 message
    // and no relay witnessed it, `|accusers| = 1 <= f`, so it records a
    // pairwise dispute `(0, 1)` rather than convicting party 0.
    let honest = self::run(Fault::None).await;
    let mut ev = all(&honest);
    for (party, item) in ev.iter_mut().enumerate() {
        let rec = &mut item.as_mut().expect("present").received;
        rec.truncate(8);
        if party == 1 {
            rec[7][0] = None;
        }
    }
    let v_one = verdict(&honest, ev, &[false; 3]).await;
    assert!(v_one.culprits.is_empty());
    assert_eq!(v_one.disputes.into_iter().collect::<Vec<_>>(), vec![(0, 1)]);
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

#[tokio::test(flavor = "multi_thread")]
async fn relay_witnesses_convict_silent_sender_and_resist_framing() {
    // m = 3, f = 1: party 0 goes silent in round 7; party 2 relays for party 1
    // and witnesses `(sender = 0, recipient = 1, round = 7)` missing -> 1 >= f
    // convicts party 0 instead of recording a 1-on-1 dispute.
    let run = run(Fault::Silent(7)).await;
    let mut evidence = all(&run);

    evidence[2]
        .as_mut()
        .expect("present")
        .relay_missing
        .insert((0, 1, 7));

    let v = verdict(&run, evidence, &[false; 3]).await;
    assert_eq!(v.culprits.into_iter().collect::<Vec<_>>(), vec![0]);
    assert!(v.disputes.is_empty());

    // Framing resistance on m = 7, f = 3: suppose party 0 is honest, party 1
    // is malicious and truncates its evidence at round 7 to fake a stall on
    // party 0, and f - 1 = 2 other malicious parties (2 and 3) falsely claim
    // relay_missing((0, 1, 7)). With only 2 < f = 3 witnesses, honest party 0
    // must NEVER be convicted as a culprit.
    let params = Params::new(7, 3).expect("valid");
    let circuit = Arc::new(direct::circuit(params, 1).expect("valid"));
    let tasks: Vec<_> = mesh(7, Fault::None)
        .into_iter()
        .map(|mut transport| {
            let circuit = circuit.clone();
            fedimint_core::runtime::spawn("mpc party", async move {
                let party = transport.party;
                let _ = direct::generate(
                    &mut transport,
                    params,
                    party,
                    1,
                    &circuit,
                    &seed(party),
                    CONTEXT,
                )
                .await
                .expect("honest run succeeds");
                transport.received.lock().expect("not poisoned").clone()
            })
        })
        .collect();

    let mut ev7 = Vec::with_capacity(7);
    for (party, task) in tasks.into_iter().enumerate() {
        let received = task.await.expect("task completes");
        ev7.push(Some(Evidence::new(seed(party), received)));
    }

    // Also strip party 1's subsequent sent messages from honest parties? No:
    // truncate ALL parties' transcripts at round 7 except keep party 0's
    // message to party 1 missing at round 7 so party 1 looks genuinely stalled
    // at round 7 waiting for party 0 without having sent later rounds.
    for (party, ev) in ev7.iter_mut().enumerate() {
        let rec = &mut ev.as_mut().expect("present").received;
        rec.truncate(8);
        if party == 1 {
            rec[7][0] = None;
        }
    }

    // f - 1 = 2 colluding malicious relays (parties 2 and 3) lie about party 0.
    for colluder in [2usize, 3] {
        ev7[colluder]
            .as_mut()
            .expect("present")
            .relay_missing
            .insert((0, 1, 7));
    }

    let v_frame = judge(params, 1, &circuit, CONTEXT, &ev7, &[false; 7])
        .await
        .expect("well-formed");
    assert!(
        !v_frame.culprits.contains(&0),
        "f - 1 colluding relays must not convict an honest sender"
    );

    // Now add a 3rd witness (reaching f = 3, which requires at least one
    // honest relay when party 1 is honest) -> convicts party 0.
    ev7[4]
        .as_mut()
        .expect("present")
        .relay_missing
        .insert((0, 1, 7));

    let v_convict = judge(params, 1, &circuit, CONTEXT, &ev7, &[false; 7])
        .await
        .expect("well-formed");
    assert_eq!(v_convict.culprits.into_iter().collect::<Vec<_>>(), vec![0]);
    assert!(v_convict.disputes.is_empty());
}
