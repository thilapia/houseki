//! Frozen identity for the complete bounded payment relation.

use super::SupportedPaymentShape;
use crate::profile::{ExpectedIdentity, Relation};
use houseki_types::ProofProfileId;
use sha3::{Digest, Sha3_512};

/// Experimental complete payments with one to four inputs and one or two outputs.
///
/// Availability requires explicit build opt-in and does not establish production security or activation.
pub const EXPERIMENTAL_PAYMENT_PROFILE: ProofProfileId = ProofProfileId::new(0xffff0008);

/// Exact relation, source provenance and backend rules frozen before profile admission.
const RECIPE: &[u8] = concat!(
    "houseki/payment/experimental/8/v1\n",
    "protocol=1;relation=1;shape=(inputs<<8)|outputs;inputs=1..4;outputs=1..2;body-codec=1;statement=1;envelope=1\n",
    "field=goldilocks:18446744069414584321;extension=cubic:x^3-x-1\n",
    "backend=plonky3-0.8.0;pcs=HidingFriPcs;dft=Radix2DitParallel;serial=true\n",
    "challenger=SerializingChallenger64:HashChallenger:SHA3-512\n",
    "statement-domain=houseki/proofs/statement/v1;binding=identity,canonical-body,anchor-count,semantic-values\n",
    "leaf-domain=houseki/proofs/leaf/v1;node-domain=houseki/proofs/node/v1;digest-bits=512\n",
    "hiding-codewords=3;salt-elements=4;queries=128;blowup=8;fold-arity=2;final-poly=1;cap-height=0;grinding=0\n",
    "preprocessed=none;mask-height=original-rows;committed-height=2*rows;lde-height=16*rows;committed-width=1188\n",
    "main-next=0..515,608,624,632;ood-points=random:1,trace:2,quotient:1\n",
    "public=network[64],root[64],count-le[16],fee-le[16],ordered-nullifiers[64*I],ordered-commitments[64*O]\n",
    "registers=input-total:0..16,output-total:16..32,amount:32..48,ownership:48..112,commitment:112..176,position:176..184;work-start=184\n",
    "input-cycle=opening:128,authority-nullifier:88,membership:1516,accumulate:1;output-cycle=opening:128,accumulate:1;fee-rows=1\n",
    "schedule=trusted-count-derived;slot-selectors=301..301+I+O;input-add=298;output-add=299;fee=300;occurrences=exactly-once\n",
    "padding=zero-work-and-note-registers,hold-final-totals;transition=exclude-final-row;initial-totals=zero;terminal=input-total==output-total+fee\n",
    "opening-width=1001;opening-cycle=128;recipient-blocks=35;commitment-blocks=7;private-prefix=176;hash-width=791;key-helpers=34\n",
    "note-version=1;address-version=1;suite=1;key-bytes=1568;key-coefficients=1024;key-coefficient-max=3328\n",
    "coefficient-bound=h=b11*b10,h*b9=0,h*b8*sum(b0..b7)=0;bits=absorbed-canonical-byte-bits\n",
    "amount=1..100000000000000000000000000000;fee=0..100000000000000000000000000000;totals=16-byte-exact;carry=boolean-per-byte;overflow=forbidden\n",
    "spend-width=983;spend-phases=21,21,23,23;secrets=spending-key32,nullifier-key32;inner-digests=64,64\n",
    "spend-domains=houseki/v1/ownership/spend-key,houseki/v1/ownership/nullifier-key,houseki/v1/ownership/commitment,houseki/v1/note/nullifier\n",
    "membership-width=991;depth=64;count=1..2^64;position=0..count-1;position-shared-with-nullifier=true\n",
    "membership-phases=occupancy:1,leaf:21,parents:64*23,root:22;directions=trusted-level-selected-original-position-byte;occupancy=position+1+difference==count\n",
    "membership-domains=houseki/v1/note-tree/leaf,houseki/v1/note-tree/node,houseki/v1/note-tree/root\n",
    "application-hash=houseki-v1-poseidon2-goldilocks-width16-seven-byte-packing-64-byte-extraction\n",
    "hash-extraction=11-canonical-samples-over16-rows,88-bytes-copy-constrained,16-exact-word-equations,final-carry-constrained\n",
    "recipient-domain=houseki/v1/recipient/kem-key;note-domain=houseki/v1/note/commitment\n",
    "fingerprints=air-polynomials/v1-ordered-canonical-expression-hashes,schedule/v1-row-major-boolean-bytes\n",
    "proof-bytes-max=2097152;decoded-vector-bytes-max=16777216;body-bytes-max=16384;payload-bytes-max=4096;largest-body=11924\n",
    "frontier-bound=k*(height-log2(k)),k=min(128,2^(height-1));largest-valid-encoding=2095060;largest-decoded-bound=2306396\n",
    "fee-policy,unspentness,eligible-anchor,delivery-correctness,tree-capacity,atomic-execution,activation=external\n",
    "qualification=experimental;composed-security-review=pending;necessary-hiding-budget=rows>=2*(128+3*points)\n",
    "relation-source-origin=43078720a6b79b56bd6d17cf8b9dedb2adfd6187\n",
    "cargo-lock-sha3-512=38c8da89423b5e43ca31c565e3350da10823596b78f2ba5f5dc4a39de82cfdf7677ada0b2fd02efe019c8b3ed348a6d9dbf8c9947bd3e31526af07661336cd32\n",
    "vendor-plonky3-bundle-sha3-512=19011d6707c0dd4a66bec27d5c92d5bbcbb427a8d658eba91f86e8fb86e06017f065dd84abfa26066204ffc956175aef45b57ea4795ce5ab48b028231a27b0dd\n",
).as_bytes();

/// All eight ordered schedule and polynomial records with numeric geometry and codec bounds.
const RECORDS: [&str; 8] = [
    "shape=0101;inputs=1;outputs=1;active=1863;rows=2048;width=1185;next=518;public=288;periodic=303;period=2048;degree=4;quotient=8;encoded-max=1892172;decoded-max=2084868;air=33688c387ad6aded1022c1abcf51490c718260f7cfde3f5ecb0e0c208a8539f7b8c69b8f29972de9dfc550c32a7ae627771b07bbddb2367bca16ae6f0cdc3736;schedule=83a884fdc67b47962fbd570f60af3ac391780445ea779780833104ebad87f7e8e5403ec2cfc552766387c069ad545883c40f5cf284c58bfef8b8f08ed253d4c0\n",
    "shape=0102;inputs=1;outputs=2;active=1992;rows=2048;width=1185;next=518;public=352;periodic=304;period=2048;degree=4;quotient=8;encoded-max=1892172;decoded-max=2084868;air=3af5a77bcbf7bc16d6f7cfa906c59cabb1bb9ceae9389a47be46565133e23ac9340c8385aa2959a1249345ab3f41092452bb8a3ae59625bf9d57e31bfdf2696d;schedule=f29f6fe0503657f5205c9c26dbface1ac9830c6836e49c288f5892adc50c4d23e085dc19c07c9ca52ecbb8016e490ea721db533c64c4e98378bd83edab1758a9\n",
    "shape=0201;inputs=2;outputs=1;active=3596;rows=4096;width=1185;next=518;public=352;periodic=304;period=4096;degree=4;quotient=8;encoded-max=1989520;decoded-max=2191536;air=ba95ffddb7d62b1b0907afd7ee54b08fd5e3d3fe1c2d0ccf9f2fad1b98bda0d0c7d4080dc8cc2c76a94c9aee13b2e82d79ee111e16b4ace50a02e2a5167d72b0;schedule=0a166d899972328636116934e71281646133c5241e239fe258c5f2c5b93357b0f2dc31375b38151a748918813d17b681ff71ac3ff6091c78c25d70f5a32efdce\n",
    "shape=0202;inputs=2;outputs=2;active=3725;rows=4096;width=1185;next=518;public=416;periodic=305;period=4096;degree=4;quotient=8;encoded-max=1989520;decoded-max=2191536;air=8b69dbe688bf1143d1fbcf56f4cb2f7ece9554825d5ea5326ff53de12a998725cf270ad3ab884befdadcf54a13fa22783648bb050a6cdd3d0b724538adf6497a;schedule=5e468ba93484068d57b4d114ecded7d5d338b1296d8c05b5b79e122320ec8ed7ca2794f89695bb5973396c4b5e204928721f9f595627a49b1f1c77f63444d4f1\n",
    "shape=0301;inputs=3;outputs=1;active=5329;rows=8192;width=1185;next=518;public=416;periodic=305;period=8192;degree=4;quotient=8;encoded-max=2095060;decoded-max=2306396;air=ff169d4ee6d4ff620885d76a7e42f6675399544c07a0517e669263c0d7c70793e33c2097d02bf74bb935cec6e5bd1230b92726d2982af59b331243cd689e2275;schedule=93846cfdce46d3b3fb8d5f08c79f1c162fb3b48cc029713c816cba8be84ddce98b50176e73a36cbdc2f93f7d9be652906ad955b6c5ffb038cf212ac6bc1e9b2a\n",
    "shape=0302;inputs=3;outputs=2;active=5458;rows=8192;width=1185;next=518;public=480;periodic=306;period=8192;degree=4;quotient=8;encoded-max=2095060;decoded-max=2306396;air=053d1e7657de467a8db83bd5fadb0f47c93181a052522ad16289dca9f46a253e71c74adb9b44d0fa1643650619b558367eebcfc0b0bce63660d9c26b895d45ed;schedule=01ddc69865f9f41e9c62cccccd37b770083ccdb65397f50f4c47546f8bc0a9daef994339d5741b0a9f0a37070255fa24f3878379f56e02cd37d1a7b82c8c37c9\n",
    "shape=0401;inputs=4;outputs=1;active=7062;rows=8192;width=1185;next=518;public=480;periodic=306;period=8192;degree=4;quotient=8;encoded-max=2095060;decoded-max=2306396;air=22be1425a6c5fc91882751ae808a669a5f3663e82294b9c144927519bb3feaaf61b653c68c76935e2c2c38a94c8be62915baa87850da3e1cc4159303ea7f9c99;schedule=d589e02e9affa0ea51cf4af263fa653c550fd4690001b8f3236905826a5635e102e2d47810cb0b2c4afa1af90091354c6664243b64a6fe3574447aafffccbe25\n",
    "shape=0402;inputs=4;outputs=2;active=7191;rows=8192;width=1185;next=518;public=544;periodic=307;period=8192;degree=4;quotient=8;encoded-max=2095060;decoded-max=2306396;air=3dd13e1d27dfb921417774240f18f41d3929ea8d84f4a23f80da56fc698373f0f443d93448cec15a203046b607931fe84f78ab8fa5c8b6157074e0b496a907e8;schedule=cf4a85e08042dde293b21b961bf7eda913fb0fd1c157cae192c6f7c602a1d060222cc80fc27b9525c6c3729831a33ee7f166624a1c01c9f62ac1a4e916dd3a24\n",
];

/// Resolves the complete identity from checked counts before decoding any proof bytes.
pub(crate) fn identity(shape: SupportedPaymentShape) -> ExpectedIdentity {
    ExpectedIdentity {
        profile: EXPERIMENTAL_PAYMENT_PROFILE,
        relation: Relation::Payment,
        shape: shape.code(),
        manifest: manifest_digest(),
    }
}

/// Hashes the canonical recipe followed by the complete ordered shape records without allocation.
fn manifest_digest() -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(RECIPE);
    for record in RECORDS {
        hash.update(record.as_bytes());
    }

    hash.finalize().into()
}

/// Checks metadata independently from any supplied proof header.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Relation, payment::SupportedPaymentShape};
    use p3_air::BaseAir;

    /// All supported identities bind the same family manifest and their exact ordered counts.
    #[test]
    fn payment_manifest_binds_all_eight_shapes() {
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let shape = SupportedPaymentShape::new(inputs, outputs).unwrap();
                let actual = identity(shape);
                assert_eq!(actual.profile, EXPERIMENTAL_PAYMENT_PROFILE);
                assert_eq!(actual.relation, Relation::Payment);
                assert_eq!(actual.shape, shape.code());
                assert_ne!(actual.manifest, [0; 64]);
            }
        }
    }

    /// Requires the current complete AIR and schedule to match every frozen record and manifest vector.
    #[test]
    fn payment_manifest_fingerprints() {
        use super::super::fingerprint;
        use crate::circuits::payment::{PaymentAir, PaymentLayout};
        for inputs in 1..=4 {
            for outputs in 1..=2 {
                let shape = SupportedPaymentShape::new(inputs, outputs).unwrap();
                let layout = PaymentLayout::for_shape(shape).unwrap();
                let air = PaymentAir::new(&layout);
                let encoded = layout.codec().encoded_upper_bound().unwrap();
                let decoded = layout.codec().decoded_upper_bound().unwrap();
                let actual = format!(
                    "shape={:04x};inputs={inputs};outputs={outputs};active={};rows={};width={};next={};public={};periodic={};period={};degree=4;quotient=8;encoded-max={encoded};decoded-max={decoded};air={};schedule={}\n",
                    shape.code(),
                    inputs * 1733 + outputs * 129 + 1,
                    layout.rows(),
                    layout.width(),
                    air.main_next_row_columns().len(),
                    air.num_public_values(),
                    air.num_periodic_columns(),
                    layout.rows(),
                    fingerprint::hex(fingerprint::polynomials(&air)),
                    fingerprint::hex(fingerprint::schedule(&air))
                );
                assert_eq!(actual, RECORDS[(inputs - 1) * 2 + outputs - 1]);
            }
        }

        assert_eq!(
            fingerprint::hex(manifest_digest()),
            "5f902560521bf59e5a029f498cc91b93220d05a49d6b2e2553b5d7145143cd0b0dd8aa7d396a0190cf9092d6889f7b7637989f728582cf65f3cbb007c99e7a4f"
        );
    }
}
