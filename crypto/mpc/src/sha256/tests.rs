use sha2::{Digest as _, Sha256};

use crate::circuit::{SHA256_AND_GATES, bits, bytes, direct};

#[test]
fn low_depth_circuit_matches_sha2() {
    let circuit = direct(3, 1).expect("valid low-depth circuit");
    let sched = circuit.schedule();

    assert!(
        sched.depth() <= 500,
        "expected low multiplicative depth: {}",
        sched.depth()
    );
    assert!(
        sched.and_count <= SHA256_AND_GATES,
        "AND count {} exceeded SHA256_AND_GATES ({SHA256_AND_GATES})",
        sched.and_count
    );

    let mut cases: Vec<[u8; 32]> = vec![
        [0u8; 32],
        [0xffu8; 32],
        std::array::from_fn(|i| u8::try_from(i).expect("fits")),
        std::array::from_fn(|i| u8::try_from(255 - i).expect("fits")),
    ];

    // Add 32 single-bit and 64 pseudorandom cases.
    for bit in 0..32 {
        let mut msg = [0u8; 32];
        msg[bit] = 1 << (bit % 8);
        cases.push(msg);
    }
    let mut state = [0x42u8; 32];
    for _ in 0..64 {
        state = Sha256::digest(state).into();
        cases.push(state);
    }

    for msg in cases {
        let expected: [u8; 32] = Sha256::digest(msg).into();
        // Split msg across 3 parties via XOR: p0 = msg ^ p1 ^ p2.
        let p1 = [0x5au8; 32];
        let p2 = [0xa5u8; 32];
        let p0: [u8; 32] = std::array::from_fn(|i| msg[i] ^ p1[i] ^ p2[i]);
        let inputs = vec![bits(&p0), bits(&p1), bits(&p2)];

        let out = circuit.evaluate(&inputs);
        assert_eq!(bytes(&out).as_slice(), expected.as_slice());
    }
}
