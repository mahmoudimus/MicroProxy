# Ghost observation vocabulary

This Dafny component proves that a typed source-observation vocabulary retains
its event kinds and payloads when encoded. It proves event and arbitrary-list
injectivity, prefix unambiguity and decoding of emitted encodings. Buffer roles,
addresses, branch outcomes, loop checks, calls and provider metadata remain
distinguishable. `Ops` records counts, not an ordered instruction trace.

The vocabulary does not prove that source instrumentation observes the actual
operations. Binding identities and covering executable source remain separate
obligations. Compiler/runtime/JDK behavior and physical timing remain outside
these proofs.

From the repository root:

```sh
python3 -m unittest discover -s formal/source/vocabulary -p 'test_*.py' -v
python3 formal/source/vocabulary/replay.py --output /fresh/vocabulary-replay
```

The runner freezes every input before loading shared Python tools, uses the pinned Dafny parser to validate
the complete include graph, installs the official checksum-pinned Dafny 4.9.1
distribution, audits all nine source files and verifies 29 kernel checks under
the existing 30-second / 50,000,000-resource / `case_split=0` policy. Six defective
encodings must fail their exact named assertions. The erasure clients must pass
their reviewed 2/3 checks and generate identical complete file inventories at
the same basename. The ghost-only vocabulary emits no Java classes.

The finite erasure experiment is evidence about this pinned compiler invocation;
the compiler remains trusted. Source, manifest and complete tool-distribution
checks run again before the replay can succeed. Legitimate proof changes require
reviewing the new obligations before changing the expected counts.
