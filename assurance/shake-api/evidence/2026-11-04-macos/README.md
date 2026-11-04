# Actual macOS qualification snapshot

These are byte-identical copies of the actual replay report and its 24 raw command
logs from the 2026-11-04 invocation. `index.json` records their file digests. The
report retains original argv/cwd paths as provenance; later replays use their own
fresh output directory. The source/tool identities, exact accepted diagnostics
and before/after guards are in the report. It is a snapshot, not a claim about
arbitrary future sources, tools, releases or JVM execution.

The invocation preceded the source commit. Match its exact 13 input digests to the
checked-in files; do not infer source identity merely from a branch name. The
canonical reproduction command is in the component README. These evidence outputs
are not inputs to the replay, avoiding an input/output digest cycle.

No operation-trace, constant-time, hardness, Java-refinement or external-review
claim is made by this snapshot. CI retains fresh reports for its own invocation.
