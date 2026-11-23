//! Finding who made a run fail.
//!
//! A party's messages are a deterministic function of its seed and what it
//! received, so once an aborted run's results are void, its members can
//! reveal their seeds and the signed messages they received, and anyone can
//! replay each member and compare what it should have sent with what the
//! others hold, signed by it.
//!
//! Signature checks are the caller's job: [`Evidence`] must only contain
//! messages whose sender's signature verified.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};

use crate::circuit::Circuit;
use crate::direct;
use crate::engine::{Params, Transport};

/// What one party received: `received[round][sender]`, `None` where the
/// message never arrived. The party's own slot is ignored.
pub type Received = Vec<Vec<Option<Vec<u8>>>>;

/// A member's revealed state from an aborted run.
#[derive(Clone, Debug)]
pub struct Evidence {
    pub seed: [u8; 32],
    pub received: Received,
    /// `(sender, recipient, round)` triples where this member was asked to
    /// relay `sender`'s encrypted packet for `recipient` in `round` and
    /// `sender` failed to serve a valid signed packet.
    pub relay_missing: BTreeSet<(usize, usize, u64)>,
}

impl Evidence {
    pub fn new(seed: [u8; 32], received: Received) -> Self {
        Self {
            seed,
            received,
            relay_missing: BTreeSet::new(),
        }
    }
}

/// How a replayed party's run went.
#[derive(Debug)]
pub struct Replay {
    /// What it sent: `sent[round][recipient]`.
    pub sent: Vec<Vec<Vec<u8>>>,
    /// The round it was waiting in when its evidence ran out, and from whom
    /// it lacked a message.
    pub stalled: Option<(u64, Vec<usize>)>,
    /// Whether its run completed.
    pub completed: bool,
}

struct ReplayTransport<'a> {
    party: usize,
    received: &'a Received,
    sent: Vec<Vec<Vec<u8>>>,
    stalled: Option<(u64, Vec<usize>)>,
}

impl Transport for ReplayTransport<'_> {
    async fn exchange(&mut self, round: u64, outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        let parties = outgoing.len();

        self.sent.push(outgoing);

        let messages = usize::try_from(round)
            .ok()
            .and_then(|round| self.received.get(round));

        let missing: Vec<usize> = (0..parties)
            .filter(|&sender| sender != self.party)
            .filter(|&sender| {
                messages
                    .and_then(|messages| messages.get(sender))
                    .is_none_or(Option::is_none)
            })
            .collect();

        if !missing.is_empty() {
            self.stalled = Some((round, missing));

            anyhow::bail!("Evidence ends in round {round}");
        }

        let messages = messages.expect("checked above");

        // Clamp to `parties` so an oversized untrusted row cannot make the
        // engine abort inside `exchange` with `stalled = None`.
        Ok((0..parties)
            .map(|sender| {
                messages
                    .get(sender)
                    .and_then(Option::as_ref)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect())
    }
}

/// Replay `party` from its evidence.
pub async fn replay(
    params: Params,
    party: usize,
    batch: usize,
    circuit: &Circuit,
    context: &[u8],
    evidence: &Evidence,
) -> Replay {
    let mut transport = ReplayTransport {
        party,
        received: &evidence.received,
        sent: vec![],
        stalled: None,
    };

    let completed = direct::generate(
        &mut transport,
        params,
        party,
        batch,
        circuit,
        &evidence.seed,
        context,
    )
    .await
    .is_ok();

    Replay {
        sent: transport.sent,
        stalled: transport.stalled,
        completed,
    }
}

/// Who to hold responsible for a failed run.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct Verdict {
    /// Parties that provably deviated, hid evidence, or finished without
    /// submitting their result.
    pub culprits: BTreeSet<usize>,
    /// Pairs, lower index first, of which one party claims the other never
    /// sent it a message. One of each pair is at fault, but not provably
    /// which; they should not share a committee for a while.
    pub disputes: BTreeSet<(usize, usize)>,
}

/// Judge a failed run of the generator from its members' evidence.
///
/// `evidence[p]` is `None` if party `p` revealed nothing; `submitted[p]`
/// says whether `p` submitted a result. Culprits are judged first; disputes
/// are only reported when nobody is provably at fault, and only for the
/// earliest round in which a message is missing, because later gaps follow
/// from it.
pub async fn judge(
    params: Params,
    batch: usize,
    circuit: &Circuit,
    context: &[u8],
    evidence: &[Option<Evidence>],
    submitted: &[bool],
) -> Result<Verdict> {
    let parties = params.parties();

    ensure!(
        evidence.len() == parties && submitted.len() == parties,
        "One entry per party"
    );

    let mut verdict = Verdict::default();
    let mut replays = Vec::with_capacity(parties);

    for (party, evidence) in evidence.iter().enumerate() {
        match evidence {
            Some(evidence) => {
                replays.push(Some(
                    replay(params, party, batch, circuit, context, evidence).await,
                ));
            }
            None => {
                verdict.culprits.insert(party);
                replays.push(None);
            }
        }
    }

    // Compare what each sender should have sent with what each recipient
    // holds under the sender's signature.
    for (sender, replay) in replays.iter().enumerate() {
        let Some(replay) = replay else {
            continue;
        };

        for (recipient, evidence) in evidence.iter().enumerate() {
            let Some(evidence) = evidence.as_ref().filter(|_| recipient != sender) else {
                continue;
            };

            for (round, messages) in evidence.received.iter().enumerate() {
                let Some(Some(held)) = messages.get(sender) else {
                    continue;
                };

                // A sender only reaches a round after receiving everything
                // before it, so holding a message the replay never produced
                // means the sender withheld evidence or kept going after it
                // should have aborted.
                let deviated = replay
                    .sent
                    .get(round)
                    .and_then(|sent| sent.get(recipient))
                    .is_none_or(|expected| expected != held);

                if deviated {
                    verdict.culprits.insert(sender);
                }
            }
        }
    }

    if !verdict.culprits.is_empty() {
        return Ok(verdict);
    }

    // Everyone followed the protocol; a member that finished and still did
    // not submit its result is at fault.
    for (party, replay) in replays.iter().enumerate() {
        if replay.as_ref().is_some_and(|r| r.completed) && !submitted[party] {
            verdict.culprits.insert(party);
        }
    }

    if !verdict.culprits.is_empty() {
        return Ok(verdict);
    }

    let first_stall = replays
        .iter()
        .flatten()
        .filter_map(|replay| replay.stalled.as_ref().map(|(round, _)| *round))
        .min();

    // At `first_stall`, convict any `sender` accused by at least `f + 1`
    // distinct committee members (`!= sender`) across the union of:
    // - members stalled at `first_stall` waiting for `sender`, and
    // - members that witnessed `relay_missing(sender, victim, first_stall)`
    //   for a stalled `victim`.
    //
    // Soundness: an honest `sender` never causes honest members to stall and
    // never triggers an honest `relay_missing` witness, so at most `f`
    // malicious members can appear in the union (strictly `< f + 1`).
    // Completeness: if a malicious `sender` drops `h >= 1` honest members and
    // delivers to the other `s = (f + 1) - h` honest members, all `h` stall
    // and all `s` witness `relay_missing`, giving `h + s = f + 1` accusers.
    if let Some(stall_round) = first_stall {
        let mut stalled_by_sender: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); parties];
        for (party, replay) in replays.iter().enumerate() {
            if let Some((round, missing)) = replay.as_ref().and_then(|r| r.stalled.as_ref())
                && *round == stall_round
            {
                for &sender in missing {
                    if sender < parties && sender != party {
                        stalled_by_sender[sender].insert(party);
                    }
                }
            }
        }

        for (sender, stalled) in stalled_by_sender.iter().enumerate() {
            if stalled.len() > params.degree() {
                verdict.culprits.insert(sender);
                continue;
            }

            for &victim in stalled {
                let mut accusers = stalled.clone();
                for (witness, ev) in evidence.iter().enumerate() {
                    if witness != sender
                        && ev.as_ref().is_some_and(|ev| {
                            ev.relay_missing.contains(&(sender, victim, stall_round))
                        })
                    {
                        accusers.insert(witness);
                    }
                }

                if accusers.len() > params.degree() {
                    verdict.culprits.insert(sender);
                    break;
                }
            }
        }
    }

    if !verdict.culprits.is_empty() {
        return Ok(verdict);
    }

    for (party, replay) in replays.iter().enumerate() {
        if let Some((round, missing)) = replay.as_ref().and_then(|r| r.stalled.as_ref())
            && Some(*round) == first_stall
        {
            for &sender in missing {
                verdict
                    .disputes
                    .insert((party.min(sender), party.max(sender)));
            }
        }
    }

    Ok(verdict)
}

/// Wraps a transport and records what it receives, as evidence for a replay.
pub struct Recorder<T> {
    inner: T,
    party: usize,
    received: Received,
}

impl<T> Recorder<T> {
    pub fn new(inner: T, party: usize) -> Self {
        Self {
            inner,
            party,
            received: vec![],
        }
    }

    pub fn received(&self) -> &Received {
        &self.received
    }

    pub fn into_received(self) -> Received {
        self.received
    }
}

impl<T: Transport> Transport for Recorder<T> {
    async fn exchange(&mut self, round: u64, outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        let incoming = self.inner.exchange(round, outgoing).await?;

        self.received.push(
            incoming
                .iter()
                .enumerate()
                .map(|(sender, message)| (sender != self.party).then(|| message.clone()))
                .collect(),
        );

        Ok(incoming)
    }
}
