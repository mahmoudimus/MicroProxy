# Pinned upstream HKDF replay

This records a separate provenance replay of AWS's HKDF reference at
[`c787ad12612ac0f35975afe9209e5dbe6b546654`](https://github.com/aws/aws-cryptographic-material-providers-library/blob/c787ad12612ac0f35975afe9209e5dbe6b546654/AwsCryptographyPrimitives/src/HKDF/HKDF.dfy).
Our [standalone implementation](../../dafny/README.md) has stronger local
functional contracts and is verified independently; it does not import this
upstream dependency graph.

| Replay | Recorded result | Scope |
| --- | --- | --- |
| HKDF target | 9 verified, zero errors, exit 0 | HKDF declarations, with included contracts trusted |
| All 71 transitive include files | Failed, exit 134 | Resource failures, timeouts, failed dependency obligations and a verifier backend exception; no full-graph success |

[Target receipt](TARGET-RECEIPT.json) and [log](target.log) record the successful
target replay. [Closure receipt](CLOSURE-RECEIPT.json) and [log](closure-failed.log)
retain the failed full-graph attempt. A tool crash or resource failure proves
nothing about the affected obligations. The failure does not establish a
counterexample to HKDF's functional behavior either.

The pinned source graph includes 51 `extern` annotations and 11 `axiom`
annotations. These are a syntactic inventory, not 62 distinct security
assumptions. The replay does not discharge those provider/library assumptions.

The upstream verifier pin is Dafny 4.9.1. The runner uses our checksum-pinned
installer to validate the official archive and every extracted assembly and
solver before and after verification. It requires the exact reviewed build;
an executable printing a matching version is insufficient. Its makefile supplies legacy function
syntax 3, 16-bit characters, deterministic compilation, a 100-second per-obligation
limit and resource limit 10000000. The replay retains those settings and uses
two verifier cores. We did not edit upstream bodies or increase their resource
budget to obtain a successful graph result.

To reproduce from an external checkout:

```sh
git clone https://github.com/aws/aws-cryptographic-material-providers-library.git /path/to/aws-mpl
git -C /path/to/aws-mpl checkout --detach c787ad12612ac0f35975afe9209e5dbe6b546654
git -C /path/to/aws-mpl submodule update --init libraries smithy-dafny
python3 -m unittest discover -s formal/reference/aws-hkdf -p 'test_*.py' -v
python3 formal/reference/aws-hkdf/replay.py \
  --checkout /path/to/aws-mpl --dafny /path/to/dafny-4.9.1/dafny \
  --scope target --output /fresh/target-replay
python3 formal/reference/aws-hkdf/replay.py \
  --checkout /path/to/aws-mpl --dafny /path/to/dafny-4.9.1/dafny \
  --scope closure --output /fresh/closure-replay
```

`inputs.json` pins the complete include inventory, upstream revisions and build
recipe inputs. The runner rejects changed, missing, redirected or added include
inputs, changed revisions and failed or inconclusive verifier results. Target
success always records `full_dependency_graph_verified: false`.
The full graph has no successful reviewed baseline, so its obligation-count
policy remains unset. A closure run cannot set the full-graph claim until that
policy is established by reviewing a successful complete replay. The failed
historical closure receipt retains its original
[execution manifest](EXECUTION-INPUTS.json).

This replay does not prove Java refinement, cryptographic hardness, provider
correctness or JVM timing. Upstream AWS material retains its Apache-2.0
attribution; the credited recurrence adaptation is described in
[the HKDF notice](../../dafny/NOTICE).
