//! PTLC examples through the real core transaction processor and Mint v2.
//! External Lightning settlement is simulated by a second adaptor transcript.
use fedimint_core::secp256k1::{Message, SecretKey};
use fedimint_simplicity_client::pruning::PruningSnapshot;
use fedimint_simplicity_client::ptlc::{AdaptorSignature, Ptlc, SpendPath};
use simplicity::dag::DagLike as _;

use super::*;

struct Fixture {
    fed: Harness,
    terms: Ptlc,
    program: ContractProgram,
    point: OutPoint,
    funder: Keypair,
    refund: Keypair,
    claimant: Keypair,
    payment_secret: SecretKey,
}

struct Payout {
    tx: Transaction,
    requests: Vec<MintRequest>,
    fee: u64,
}

impl Fixture {
    fn outer_key(&self, path: SpendPath) -> Keypair {
        match path {
            SpendPath::Claim => self.claimant,
            SpendPath::Refund => self.refund,
        }
    }

    async fn new() -> Self {
        let fed = Harness::new();
        let funder = key();
        let refund = key();
        let claimant = key();
        let payment_secret = key().secret_key();
        let request = MintRequest::new(Denomination(20));
        let issue = fed.fund(vec![request.output()]).await;
        let note = fed
            .note(
                &request,
                OutPoint {
                    txid: issue.tx_hash(),
                    out_idx: 0,
                },
            )
            .await;
        let mut terms = Ptlc {
            funder: funder.x_only_public_key().0,
            refund: refund.x_only_public_key().0,
            claimant: claimant.x_only_public_key().0,
            payment_point: payment_secret.public_key(SECP256K1),
            amount: note.amount(),
            expiry_block_count: 100,
        };
        terms.amount.msats -= output_fee(&terms.output(vec![]).unwrap()).msats;
        let output = terms.output(vec![]).unwrap();
        let program = terms.program().unwrap();
        let mut deposit = transaction(
            vec![DynInput::from_typed(MINT, MintInput::new_v0(note))],
            vec![DynOutput::from_typed(SIMP, output)],
        );
        sign_transaction(&mut deposit, &[request.key]).unwrap();
        fed.process(&deposit, 1).await.unwrap();
        let point = OutPoint {
            txid: deposit.tx_hash(),
            out_idx: 0,
        };
        terms
            .validate_output(&fed.contract(point).await.unwrap().output)
            .unwrap();
        fed.vote(99).await;
        Self {
            fed,
            terms,
            program,
            point,
            funder,
            refund,
            claimant,
            payment_secret,
        }
    }

    async fn payout(&self, path: SpendPath) -> Payout {
        let input = self
            .program
            .input(
                self.point,
                self.outer_key(path).public_key(),
                Ptlc::placeholder_witnesses(path),
            )
            .unwrap();
        let mut tx = transaction(vec![DynInput::from_typed(SIMP, input)], vec![]);
        // Fixture pruning skips signatures/assertions only to measure the exact
        // branch fee. Final positive spends below use ordinary SDK pruning.
        self.fed.prune(&mut tx, 2).await;
        let fee = common_fee(&tx);
        let amount = self.terms.amount.msats - fee;
        let requests: Vec<_> = (0..64)
            .filter(|bit| amount & (1u64 << bit) != 0)
            .map(|bit| MintRequest::new(Denomination(bit)))
            .collect();
        tx.outputs = requests.iter().map(MintRequest::output).collect();
        Payout { tx, requests, fee }
    }

    fn digest(&self, tx: &Transaction) -> [u8; 32] {
        fedimint_simplicity_common::signature_hash(federation_id(), SIMP, tx).unwrap()
    }

    fn extract_from_claim(&self, adaptor: &AdaptorSignature, tx: &Transaction) -> SecretKey {
        let input = tx.inputs[0]
            .as_any()
            .downcast_ref::<ContractInput>()
            .unwrap();
        let program = fedimint_simplicity_common::runtime::decode_program(input).unwrap();
        // Recover from actual published witnesses, not a signature passed back
        // by the claimant. The retained off-chain transcript identifies it.
        program
            .post_order_iter::<simplicity::dag::InternalSharing>()
            .find_map(|node| {
                let simplicity::node::Inner::Witness(value) = node.node.inner() else {
                    return None;
                };
                let bytes = value.raw_byte_iter().collect::<Vec<_>>();
                let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&bytes).ok()?;
                adaptor
                    .extract(
                        self.terms.funder,
                        self.terms.payment_point,
                        self.digest(tx),
                        &signature,
                    )
                    .ok()
            })
            .expect("claim publishes the completed adaptor signature")
    }

    async fn authorize(
        &self,
        tx: &mut Transaction,
        path: SpendPath,
        funder_signature: Value,
        claimant_signature: Value,
    ) {
        let database = self.fed.db.with_prefix_module_id(SIMP).0;
        let mut dbtx = database.begin_transaction_nc().await;
        let count = self
            .fed
            .modules
            .get_expect(SIMP)
            .as_any()
            .downcast_ref::<Simplicity>()
            .unwrap()
            .consensus_block_count(&mut dbtx)
            .await;
        let snapshot = PruningSnapshot {
            session_index: 2,
            block_count: count,
            contracts: BTreeMap::from([(self.point, self.fed.contract(self.point).await.unwrap())]),
            ..Default::default()
        };
        let env = snapshot.environment(federation_id(), SIMP, tx, 0).unwrap();
        let input = self
            .program
            .input_with_environment(
                self.point,
                self.outer_key(path).public_key(),
                Ptlc::witnesses(path, funder_signature, claimant_signature),
                &env,
            )
            .unwrap();
        tx.inputs[0] = DynInput::from_typed(SIMP, input);
        sign_transaction(tx, &[self.outer_key(path)]).unwrap();
    }

    async fn claim(
        &self,
        payout: &mut Payout,
    ) -> (AdaptorSignature, bitcoin::secp256k1::schnorr::Signature) {
        let digest = self.digest(&payout.tx);
        let adaptor = AdaptorSignature::encrypt(&self.funder, self.terms.payment_point, digest);
        assert!(adaptor.verify(self.terms.funder, self.terms.payment_point, digest));
        let completed = adaptor
            .complete(
                self.terms.funder,
                self.terms.payment_point,
                digest,
                &self.payment_secret,
            )
            .unwrap();
        let claimant_signature =
            signature_value(federation_id(), SIMP, &payout.tx, &self.claimant).unwrap();
        self.authorize(
            &mut payout.tx,
            SpendPath::Claim,
            Value::byte_array(*completed.as_ref()),
            claimant_signature,
        )
        .await;
        assert_eq!(common_fee(&payout.tx), payout.fee);
        (adaptor, completed)
    }

    async fn redeem(&self, payout: &Payout) {
        assert!(self.fed.contract(self.point).await.is_none());
        assert_eq!(self.fed.audit().await, 0);
        let mut notes = Vec::new();
        for (index, request) in payout.requests.iter().enumerate() {
            notes.push(
                self.fed
                    .note(
                        request,
                        OutPoint {
                            txid: payout.tx.tx_hash(),
                            out_idx: index as u64,
                        },
                    )
                    .await,
            );
        }
        let amount = notes.iter().map(|note| note.amount().msats).sum::<u64>();
        assert_eq!(amount + payout.fee, self.terms.amount.msats);
        let mut spend = transaction(
            notes
                .into_iter()
                .map(|note| DynInput::from_typed(MINT, MintInput::new_v0(note)))
                .collect(),
            vec![DynOutput::from_typed(
                DUMMY,
                DummyOutput {
                    amount: Amount::from_msats(amount),
                    unit: AmountUnit::BITCOIN,
                },
            )],
        );
        sign_transaction(
            &mut spend,
            &payout
                .requests
                .iter()
                .map(|request| request.key)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        self.fed.process(&spend, 3).await.unwrap();
    }
}

fn common_fee(tx: &Transaction) -> u64 {
    let input = tx.inputs[0]
        .as_any()
        .downcast_ref::<ContractInput>()
        .unwrap();
    fedimint_simplicity_common::runtime::input_fee(input)
        .unwrap()
        .msats
}

#[tokio::test]
async fn outgoing_ptlc_claim_extracts_payment_scalar_and_redeems_real_ecash() {
    let fixture = Fixture::new().await;
    // Funder = payer; claimant = gateway. The external payee supplies the
    // scalar only when the simulated external PTLC settles.
    let mut payout = fixture.payout(SpendPath::Claim).await;
    let (adaptor, _) = fixture.claim(&mut payout).await;
    let mut competitor = fixture.payout(SpendPath::Claim).await;
    fixture.claim(&mut competitor).await;
    fixture.fed.check_submission(&payout.tx, 2).await.unwrap();
    fixture.fed.process(&payout.tx, 2).await.unwrap();
    let extracted = fixture.extract_from_claim(&adaptor, &payout.tx);
    assert_eq!(extracted, fixture.payment_secret);
    assert!(fixture.fed.process(&payout.tx, 2).await.is_err());
    assert!(fixture.fed.process(&competitor.tx, 2).await.is_err());
    fixture.redeem(&payout).await;
}

#[tokio::test]
async fn interactive_ptlc_receive_releases_scalar_to_gateway() {
    let fixture = Fixture::new().await;
    // Funder = gateway; claimant = online recipient, who knows the scalar. A
    // second adaptor models the gateway's incoming Lightning settlement.
    let external_signer = key();
    let external_digest = [42; 32];
    let external = AdaptorSignature::encrypt(
        &external_signer,
        fixture.terms.payment_point,
        external_digest,
    );
    let mut payout = fixture.payout(SpendPath::Claim).await;
    let (adaptor, _) = fixture.claim(&mut payout).await;
    fixture.fed.process(&payout.tx, 2).await.unwrap();
    let extracted = fixture.extract_from_claim(&adaptor, &payout.tx);
    let settled = external
        .complete(
            external_signer.x_only_public_key().0,
            fixture.terms.payment_point,
            external_digest,
            &extracted,
        )
        .unwrap();
    SECP256K1
        .verify_schnorr(
            &settled,
            &Message::from_digest(external_digest),
            &external_signer.x_only_public_key().0,
        )
        .unwrap();
    fixture.redeem(&payout).await;
}

#[tokio::test]
async fn ptlc_claim_requires_both_authorizations_and_exact_payout() {
    let fixture = Fixture::new().await;
    let mut payout = fixture.payout(SpendPath::Claim).await;
    let (adaptor, completed) = fixture.claim(&mut payout).await;
    for (funder, claimant) in [
        (
            placeholder_signature(),
            signature_value(federation_id(), SIMP, &payout.tx, &fixture.claimant).unwrap(),
        ),
        (
            Value::byte_array(*completed.as_ref()),
            placeholder_signature(),
        ),
    ] {
        let mut invalid = payout.tx.clone();
        invalid.inputs[0] = DynInput::from_typed(
            SIMP,
            fixture
                .program
                .input(
                    fixture.point,
                    fixture.claimant.public_key(),
                    Ptlc::witnesses(SpendPath::Claim, funder, claimant),
                )
                .unwrap(),
        );
        fixture
            .fed
            .sign(&mut invalid, &[fixture.claimant])
            .await
            .unwrap();
        assert!(fixture.fed.check_submission(&invalid, 2).await.is_err());
        assert!(fixture.fed.process(&invalid, 2).await.is_err());
        assert!(fixture.fed.contract(fixture.point).await.is_some());
    }
    let mut redirected = payout.tx.clone();
    redirected.outputs[0] = MintRequest::new(payout.requests[0].denomination).output();
    // Neither claimant nor funder can redirect the other's authorized payout,
    // even when refreshing their own inner and outer signatures.
    assert!(!adaptor.verify(
        fixture.terms.funder,
        fixture.terms.payment_point,
        fixture.digest(&redirected)
    ));
    for (funder, claimant) in [
        (
            Value::byte_array(*completed.as_ref()),
            signature_value(federation_id(), SIMP, &redirected, &fixture.claimant).unwrap(),
        ),
        (
            signature_value(federation_id(), SIMP, &redirected, &fixture.funder).unwrap(),
            signature_value(federation_id(), SIMP, &payout.tx, &fixture.claimant).unwrap(),
        ),
    ] {
        redirected.inputs[0] = DynInput::from_typed(
            SIMP,
            fixture
                .program
                .input(
                    fixture.point,
                    fixture.claimant.public_key(),
                    Ptlc::witnesses(SpendPath::Claim, funder, claimant),
                )
                .unwrap(),
        );
        fixture
            .fed
            .sign(&mut redirected, &[fixture.claimant])
            .await
            .unwrap();
        assert!(fixture.fed.process(&redirected, 2).await.is_err());
    }
    let mut unfunded = payout.tx.clone();
    unfunded.outputs[0] =
        MintRequest::new(Denomination(payout.requests[0].denomination.0 + 1)).output();
    let funder = signature_value(federation_id(), SIMP, &unfunded, &fixture.funder).unwrap();
    let claimant = signature_value(federation_id(), SIMP, &unfunded, &fixture.claimant).unwrap();
    fixture
        .authorize(&mut unfunded, SpendPath::Claim, funder, claimant)
        .await;
    assert!(fixture.fed.process(&unfunded, 2).await.is_err());
    assert!(fixture.fed.contract(fixture.point).await.is_some());
    fixture.fed.process(&payout.tx, 2).await.unwrap();
    fixture.redeem(&payout).await;
}

#[tokio::test]
async fn ptlc_claim_and_refund_signatures_cannot_be_reused_across_paths() {
    let fixture = Fixture::new().await;
    let mut claim = fixture.payout(SpendPath::Claim).await;
    let (_, completed) = fixture.claim(&mut claim).await;
    fixture.fed.check_submission(&claim.tx, 2).await.unwrap();

    // Even before expiry, a refund signature cannot substitute for the
    // encrypted funder-claim signature, regardless of claimant cooperation.
    let mut invalid_claim = claim.tx.clone();
    let refund_signature =
        signature_value(federation_id(), SIMP, &invalid_claim, &fixture.refund).unwrap();
    let claimant_signature =
        signature_value(federation_id(), SIMP, &invalid_claim, &fixture.claimant).unwrap();
    invalid_claim.inputs[0] = DynInput::from_typed(
        SIMP,
        fixture
            .program
            .input(
                fixture.point,
                fixture.claimant.public_key(),
                Ptlc::witnesses(SpendPath::Claim, refund_signature, claimant_signature),
            )
            .unwrap(),
    );
    fixture
        .fed
        .sign(&mut invalid_claim, &[fixture.claimant])
        .await
        .unwrap();
    assert!(fixture.fed.process(&invalid_claim, 2).await.is_err());

    // The inner digest excludes REFUND and other witnesses. Flipping only that
    // selector must not turn an expired claim authorization into a refund to
    // the claimant's original payout destinations. Fee overpayment is allowed,
    // so neither the smaller refund fee nor pruning protects this boundary.
    fixture.fed.vote(100).await;
    let mut forged_refund = claim.tx.clone();
    forged_refund.inputs[0] = DynInput::from_typed(
        SIMP,
        fixture
            .program
            .input(
                fixture.point,
                fixture.claimant.public_key(),
                Ptlc::witnesses(
                    SpendPath::Refund,
                    Value::byte_array(*completed.as_ref()),
                    placeholder_signature(),
                ),
            )
            .unwrap(),
    );
    fixture
        .fed
        .sign(&mut forged_refund, &[fixture.claimant])
        .await
        .unwrap();
    assert_eq!(fixture.digest(&forged_refund), fixture.digest(&claim.tx));
    assert!(
        fixture
            .fed
            .check_submission(&forged_refund, 2)
            .await
            .is_err()
    );
    assert!(fixture.fed.process(&forged_refund, 2).await.is_err());
    assert!(fixture.fed.contract(fixture.point).await.is_some());
}

#[tokio::test]
async fn ptlc_expiry_revalidates_admitted_claim_and_allows_only_funder_refund() {
    let fixture = Fixture::new().await;
    let mut claim = fixture.payout(SpendPath::Claim).await;
    let (adaptor, _) = fixture.claim(&mut claim).await;
    fixture.fed.check_submission(&claim.tx, 2).await.unwrap();

    let mut refund = fixture.payout(SpendPath::Refund).await;
    let signature = signature_value(federation_id(), SIMP, &refund.tx, &fixture.refund).unwrap();
    refund.tx.inputs[0] = DynInput::from_typed(
        SIMP,
        fixture
            .program
            .input(
                fixture.point,
                fixture.refund.public_key(),
                Ptlc::witnesses(
                    SpendPath::Refund,
                    signature.clone(),
                    placeholder_signature(),
                ),
            )
            .unwrap(),
    );
    fixture
        .fed
        .sign(&mut refund.tx, &[fixture.refund])
        .await
        .unwrap();
    assert!(fixture.fed.process(&refund.tx, 2).await.is_err());

    // Ordered clock advancement, including within the same session, closes
    // claims. An earlier admission is not a reservation or inclusion promise.
    fixture.fed.vote(100).await;
    assert!(fixture.fed.process(&claim.tx, 2).await.is_err());
    assert_eq!(
        fixture.extract_from_claim(&adaptor, &claim.tx),
        fixture.payment_secret,
        "publishing the signature discloses the scalar even when consensus rejects the claim"
    );
    assert!(fixture.fed.contract(fixture.point).await.is_some());
    let wrong = signature_value(federation_id(), SIMP, &refund.tx, &fixture.claimant).unwrap();
    let mut invalid = refund.tx.clone();
    invalid.inputs[0] = DynInput::from_typed(
        SIMP,
        fixture
            .program
            .input(
                fixture.point,
                fixture.refund.public_key(),
                Ptlc::witnesses(SpendPath::Refund, wrong, placeholder_signature()),
            )
            .unwrap(),
    );
    fixture
        .fed
        .sign(&mut invalid, &[fixture.refund])
        .await
        .unwrap();
    assert!(fixture.fed.process(&invalid, 2).await.is_err());
    fixture
        .authorize(
            &mut refund.tx,
            SpendPath::Refund,
            signature,
            placeholder_signature(),
        )
        .await;
    assert_eq!(common_fee(&refund.tx), refund.fee);
    fixture.fed.process(&refund.tx, 2).await.unwrap();
    assert!(fixture.fed.process(&claim.tx, 2).await.is_err());
    fixture.redeem(&refund).await;
}
