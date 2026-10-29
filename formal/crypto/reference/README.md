# Pre-adoption Java reference

These are byte-identical copies of the handwritten `Shake` and `MlKem768`
implementations before adoption of Dafny-generated Java. `provenance.json` records
the original paths, commit and SHA256 digests. The Go attribution in ML-KEM is
retained verbatim.

They are an independent comparison baseline for isolated formal harnesses. They
must not be added to Maven's source path or packaged in the proxy. A harness using
this directory checks agreement with that fixed baseline; it does not by itself
prove the delivered production facade or artifact. The generated delivery check,
production tests and independent Go/hashlib vectors cover those separate layers.
