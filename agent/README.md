# Scan Insertion Agent starter

## Latest status (2026-10-06)

The local Bailian Key has passed a real `deepseek-v4-pro` request. A live-model baseline ran all 11 Public cases and passed none of the current Agent checks. Revised images are being retested and have passed several small cases. See [LIVE_VALIDATION.md](../LIVE_VALIDATION.md) for measured results and remaining work. The earlier Golden replay described below is historical tool validation, not an autonomous Agent pass.

The runtime now uses build-time official command help, bounded structural context with actual Liberty pin names, command preflight, report redirection normalization, live tool logs, process-group timeouts, and indexed audit evidence. Task 1 mappings must refer to literal executed Tcl. A bounded private Pre-scan editing/EQY workflow is implemented and has passed small real proofs, including sky130 cells; see [NETLIST_REPAIR.md](NETLIST_REPAIR.md) for its restrictions. Some ICGs still lack usable functional models, and complete Public and semantic validation remain unfinished. Do not upload this development version for evaluation.

This package runs inside `scan-agent-base:ubuntu24`. It calls the real `dftexp_scan` binary, saves each attempt, and refuses to fabricate a successful netlist or report. The current implementation has been replay-checked against all 11 Public cases using each case's `golden.dofile` as an offline test fixture. This verifies tool execution and artifact checks, but does not validate live LLM-generated Dofiles.

The original contest guide is included as [赛题指南_广立微.docx](赛题指南_广立微.docx). See [CONTEST_REQUIREMENTS.md](CONTEST_REQUIREMENTS.md) for the requirements audit and remaining implementation gaps. Add documentation from updated handoff bundles individually; extracting an older starter over this folder overwrites the developed source.

The contest presentation is also included as [EDA精英挑战赛_Scan_Insertion_赛题线上宣讲.pptx](EDA精英挑战赛_Scan_Insertion_赛题线上宣讲.pptx). Its guidance and the difference concerning tool-call limits are recorded in the requirements audit.

The repository root now includes VS Code and Dev Container configurations, development tasks, and [environment notes](../ENVIRONMENT.md). The Dockerfiles install GNU Make, which is missing from the official base image and is required for EQY's proof stage. Open the repository root for these development settings.

## Build

```bash
docker build -t my-scan-agent:dev .
```

Copy `.env.example` to `.env` and enter your own DashScope API key locally. Keep `.env` private; the image does not copy it.

## Run

Provide `LLM_API_KEY` at runtime. The contest reference package documents `8273@121.40.209.111` as the local ScanInsertion license server. Do not bake credentials into the image.

```bash
docker run --rm \
  --env-file .env \
  -v "$PWD/input:/input:ro" -v "$PWD/output:/output:rw" \
  my-scan-agent:dev -input /input -output /output
```

## Important behavior

- `golden.dofile` and `preset_issues.json` are never read by the runtime agent.
- Task 1 starts from a generated Dofile; task 2 starts from `original.dofile`.
- The agent uses actual tool exit status and output files. It does not synthesize deliverables.
- Tool calls are bounded by the case time limit and `AGENT_MAX_TOOL_CALLS` (default 4).
- Task 2 may propose localized edits when the case allows them and Dofile settings are insufficient. The runtime edits a private copy and requires actual EQY PASS before use. Task 1 and explicit no-edit cases always refuse edits. Proof failures remain incomplete; input netlists are never overwritten.

## Validation status (2026-10-04)

- All 11 Public cases were exercised with the real ScanInsertion binary through an offline replay harness that returns the case's `golden.dofile`. The runtime agent itself never reads `golden.dofile` or `preset_issues.json`.
- The final saved artifacts passed the current independent DRC/artifact/scan-chain checks. Task 2 case 3 required two tool calls; its first run exposed DRC failures and the replayed second run passed.
- The offline harness bypasses the live LLM API. Live model response quality, hidden cases, automatic pre-scan netlist repair, and LEC-backed edits remain unverified or unimplemented. Do not treat this as a platform-ready submission or upload it for evaluation.
- Large-case tool runs took about 486 seconds (Task 1 case 5) and 298 seconds (Task 2 case 5); keep the configured case time budget in mind.

The original Word review prompted fixes to evidence run references, change IDs, positive verification, full final-log copying, input paths, and post-generation tool budgets. Task 2 now keeps actual tool success separate from issue audit completion; an empty issue list produces an incomplete audit.

The 12 audit regression checks use local test fixtures and do not call the LLM or ScanInsertion binary. Run them from the repository root:

```bash
python3 tests/test_audit_regressions.py
```

These checks passed, the Docker image rebuilt successfully, and the 11 previously saved real tool outputs still passed the output checker. No additional live model or full Public-case tool runs were performed for this audit update.
