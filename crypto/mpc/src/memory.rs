//! An in-process transport for tests.

use anyhow::{Context as _, Result, ensure};
use tokio::sync::mpsc;

use crate::engine::Transport;

type Message = (u64, Vec<u8>);

/// One party's end of a fully connected in-memory network. Dropping it closes
/// its links, so peers waiting on it fail instead of hanging.
pub struct MemoryTransport {
    party: usize,
    senders: Vec<Option<mpsc::UnboundedSender<Message>>>,
    receivers: Vec<Option<mpsc::UnboundedReceiver<Message>>>,
}

/// Connect `parties` transports, in party order.
pub fn mesh(parties: usize) -> Vec<MemoryTransport> {
    let mut transports: Vec<_> = (0..parties)
        .map(|party| MemoryTransport {
            party,
            senders: (0..parties).map(|_| None).collect(),
            receivers: (0..parties).map(|_| None).collect(),
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

impl MemoryTransport {
    pub fn party(&self) -> usize {
        self.party
    }
}

impl Transport for MemoryTransport {
    async fn exchange(&mut self, round: u64, outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        ensure!(
            outgoing.len() == self.senders.len(),
            "One message per party"
        );

        for (sender, message) in self.senders.iter().zip(outgoing) {
            if let Some(sender) = sender {
                sender
                    .send((round, message))
                    .ok()
                    .context("A peer left the run")?;
            }
        }

        let mut incoming = Vec::with_capacity(self.receivers.len());

        for receiver in &mut self.receivers {
            let Some(receiver) = receiver else {
                incoming.push(Vec::new());
                continue;
            };

            let (received_round, message) = receiver.recv().await.context("A peer left the run")?;

            ensure!(received_round == round, "A peer is in another round");

            incoming.push(message);
        }

        Ok(incoming)
    }
}
