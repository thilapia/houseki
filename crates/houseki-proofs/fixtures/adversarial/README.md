# Public adversarial conformance corpus

These public artifacts cover all eight experimental payment shapes and the complete experimental withdrawal output relation. They contain canonical bodies, encoded hiding proofs and independently retained payment anchors. They contain no wallet keys, openings or private traces.

The payment artifacts are the first Apple M4 desktop sample for each shape from source revision `12fdcddc66608663477e8be8a31002c258ee8f83`. The withdrawal artifacts are the first desktop consumer sample retained by Stage 07 and accepted by the final Stage 08 verifier. Payment uses profile `0xffff0008` and withdrawal uses `0xffff0007`. Both require explicit experimental admission.

`manifest.sha3` lists SHA3-512 digests relative to this directory. The mutation campaign supervisor checks every digest before execution. Proofs are randomized fixed conformance vectors. Regeneration produces different bytes and requires an intentional corpus update.

Run the standalone harness in `../../fuzz` to verify the originals before mutation. Its conformance campaign changes every body field occurrence, both ends of each opaque envelope region, all header bytes, ordered inputs and outputs, anchor count endpoints and cross-family or cross-shape proof identities. Its bounded campaigns also change nested Merkle frontiers, canonical field words, dimensions and complete envelope lengths through the 2 MiB boundary. The campaign generator is part of the reproducible corpus.

These artifacts establish test inputs and interoperability under the recorded experimental profiles. They do not establish composed soundness, zero knowledge, source authorization, ledger eligibility or production qualification.
