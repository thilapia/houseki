//! Exact experimental withdrawal configuration retained independently of untrusted proofs.

use super::{ExpectedIdentity, Relation};
use crate::{backend::Layout, circuits::reward_withdrawal::WithdrawalAir, gadgets::Opening};
use houseki_types::{BodyCodecLimits, PaymentCountLimits, ProofProfileId};
use sha3::{Digest, Sha3_512};

/// Qualification profile for the complete withdrawal relation, available only by explicit opt-in.
///
/// This identifier does not claim the composed security argument or production profile review
/// is complete, and applications must obtain network activation policy independently.
pub const EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE: ProofProfileId = ProofProfileId::new(0xffff0007);

/// Fixed trace and quotient geometry for the complete withdrawal relation without preprocessing.
pub(crate) const LAYOUT: Layout = Layout {
    log_rows: WithdrawalAir::ROWS.ilog2() as usize,
    width: Opening::WIDTH,
    quotient_chunks: 8,
    main_next: true,
};

/// Exact retained candidate recipe whose bytes enter every transcript through their SHA3-512 digest.
///
/// Changes to relation equations, source maps or backend rules require a new experimental identity.
///
/// Production admission additionally requires reviewed source provenance and a complete security argument.
const MANIFEST: &[u8] = concat!(
    "houseki/reward-withdrawal/experimental/7/v1\n",
    "protocol=1;relation=2;shape=1;body-codec=1;statement=1;envelope=1\n",
    "field=goldilocks:18446744069414584321;extension=cubic:x^3-x-1\n",
    "backend=plonky3-0.8.0;pcs=HidingFriPcs;dft=Radix2DitParallel;serial=true\n",
    "challenger=SerializingChallenger64:HashChallenger:SHA3-512\n",
    "statement-domain=houseki/proofs/statement/v1;binding=identity,canonical-body,semantic-values\n",
    "leaf-domain=houseki/proofs/leaf/v1;node-domain=houseki/proofs/node/v1;digest-bits=512\n",
    "hiding-codewords=3;salt-elements=4;queries=128;blowup=8;fold-arity=2;final-poly=1;cap-height=0;grinding=0\n",
    "trace-rows=512;trace-columns=1493;cycle=128;selectors=78;degree=4;quotient-chunks=8;preprocessed=none\n",
    "main-next=0..203,219..221,268..284,1084;ood-points=random:1,trace:2,quotient:1\n",
    "public=network[64],amount-le[16],commitment[64];public-values=144\n",
    "private=ownership[64],amount[16],blinding[32],recipient-digest[64];work-start=176;key-aux-start=1085\n",
    "schedule=recipient-absorb:0..35,squeeze:35,extract:36..52,note-absorb:52..59,squeeze:59,extract:60..76,amount:76,idle:77..128\n",
    "selectors=one-hot:0..77,cycle-end:127;private-continuity=within-cycle;unused-work=zero\n",
    "note-version=1;address-version=1;suite=1;key-bytes=1568;key-coefficients=1024;key-coefficient-max=3328\n",
    "amount=1..100000000000000000000000000000;public-amount-equality=all-16-bytes;fee=separate\n",
    "application-hash=houseki-v1-poseidon2-goldilocks-width16-seven-byte-packing-64-byte-extraction\n",
    "recipient-domain=houseki/v1/recipient/kem-key;note-domain=houseki/v1/note/commitment\n",
    "payload=canonical-fixed-layout-v1;degree-bits=10;fri-rounds=10;input-height=13;zero-pow;no-preprocessed\n",
    "proof-bytes-max=2097152;decoded-vector-bytes-max=16777216;body-bytes-max=16384;payload-bytes-max=4096\n",
    "source-authority,nonce,balance,fee-policy,delivery-correctness,activation=external\n",
    "qualification=experimental;composed-security-review=pending\n",
).as_bytes();

/// Resolves one exact identity without allowing proof bytes to select backend parameters.
pub(crate) fn identity() -> ExpectedIdentity {
    ExpectedIdentity {
        profile: EXPERIMENTAL_REWARD_WITHDRAWAL_PROFILE,
        relation: Relation::RewardWithdrawal,
        shape: 1,
        manifest: Sha3_512::digest(MANIFEST).into(),
    }
}

/// Withdrawal representation bounds applied before body encoding or statement allocation.
pub(crate) fn body_limits() -> BodyCodecLimits {
    BodyCodecLimits::new(
        PaymentCountLimits::new(2, 2).expect("nonzero fixed counts"),
        4096,
        16384,
    )
}

/// Trusted geometry must agree with symbolic constraints before any encoded proof is accepted.
#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::{
        BaseAir,
        symbolic::{AirLayout, get_max_constraint_degree},
    };
    use p3_uni_stark::get_log_num_quotient_chunks;

    /// The canonical decoder expects exactly the dimensions derived from the complete AIR.
    #[test]
    fn reward_withdrawal_layout_matches_symbolic_air() {
        let air = WithdrawalAir::new();
        let symbolic = AirLayout::from_air(&air);

        assert_eq!(LAYOUT.width, air.width());
        assert_eq!(1 << LAYOUT.log_rows, WithdrawalAir::ROWS);
        assert_eq!(
            get_max_constraint_degree(&air, symbolic, WithdrawalAir::ROWS),
            4
        );
        assert_eq!(
            1 << (get_log_num_quotient_chunks(&air, symbolic, WithdrawalAir::ROWS, 1) + 1),
            LAYOUT.quotient_chunks
        );
        assert_eq!(air.num_public_values(), 144);
        assert_eq!(LAYOUT.main_next, !air.main_next_row_columns().is_empty());
    }
}
