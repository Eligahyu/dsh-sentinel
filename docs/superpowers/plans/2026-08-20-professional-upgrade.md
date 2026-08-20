# Professional Scanner Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade `dsh-sentinel` from a hardened single-file/static DSH scanner into a professional-grade, evidence-producing scanner with cross-file analysis, dependency/SBOM intelligence, Agent capability analysis, reproducible public benchmarks, and verifiable GitHub/npm delivery.

**Architecture:** Preserve the existing `scan()`/`scanProfile()` APIs, report schema v2, rule IDs, CLI, plugin entry, and read-only safety guarantees. Add isolated analysis layers: a module graph and cross-file semantic engine, a normalized dependency graph/SBOM layer, a capability graph layer, and a corpus/benchmark harness. Each layer emits structured evidence consumed by the existing report, SARIF, HTML, baseline, and exit-code paths.

**Tech Stack:** Node.js ESM, Node test runner, Acorn/Babel parser already present, JSON/YAML lockfile parsers kept dependency-light, CycloneDX 1.6 and SPDX 2.3 JSON output, SARIF 2.1.0, GitHub Actions OIDC/Trusted Publishing, fixture and downloaded-corpus benchmark scripts.

**Spec:** `docs/upgrade-spec.md`

## Global Constraints

- Never execute or import scanned plugin code; only read source, manifests, lockfiles, tarballs, and metadata.
- Do not upload scanned source; external advisory/provenance requests may send only package name, version, ecosystem, and hash.
- Preserve existing public CLI, plugin tools, report schema v2, rule IDs, exit codes, and safe/review/risky/dangerous semantics.
- A skipped, failed, truncated, or unparsed analysis must be visible and must not produce a clean verdict.
- New production behavior must have a failing test observed before implementation.
- New public report fields must have JSON/SARIF/HTML coverage and backward-compatible defaults.
- Use explicit versioned fixtures and deterministic benchmark manifests; never silently replace real-corpus evidence with synthetic fixtures.

### Task 1: Establish the professional report contracts

**Files:**
- Create: `engine/report/schema.js`
- Create: `test/professional-contract.test.js`
- Modify: `engine/report.js`
- Modify: `engine/output/sarif.js`
- Modify: `engine/output/html.js`
- Modify: `docs/upgrade-spec.md`

**Interfaces:**
- `assertReportContract(report)` validates report schema version, analysis layers, evidence, and incomplete-state invariants.
- `emptyAnalysisLayers()` returns `{ moduleGraph, dependencyGraph, capabilityGraph, sbom, provenance }` with stable defaults.
- Existing reports without the new fields remain readable; new reports always expose the fields.

- [ ] Write failing tests for stable layer defaults, incomplete-layer propagation, and a finding with module/capability evidence.
- [ ] Run `node --test test/professional-contract.test.js`; confirm failure is caused by missing contract fields.
- [ ] Implement the schema helpers and thread defaults through `buildReport`.
- [ ] Extend SARIF properties and HTML summary without changing existing finding IDs.
- [ ] Run the focused test and then the full existing suite.
- [ ] Commit `feat: define professional analysis report contracts`.

### Task 2: Build a safe cross-file module graph

**Files:**
- Create: `engine/semantic/module-graph.js`
- Create: `test/module-graph.test.js`
- Modify: `engine/index.js`
- Modify: `engine/scanner.js`
- Modify: `engine/report.js`

**Interfaces:**
- `buildModuleGraph(root, files, options)` returns `{ nodes, edges, unresolved, failures, complete }`.
- Nodes contain normalized relative path, parser status, exports, imports, and content hash; edges contain import kind, resolved target, and source location.
- Resolution supports relative `.js/.mjs/.cjs/.ts/.tsx`, directory `index` files, package `exports`, and unresolved external package names without reading outside containment.

- [ ] Add tests for relative imports, extensionless imports, directory index resolution, package exports, unresolved imports, and traversal escape rejection.
- [ ] Run the focused tests and confirm they fail before adding graph code.
- [ ] Implement deterministic resolution and failure accounting with no plugin imports.
- [ ] Integrate graph construction into `scan()` and mark `scanComplete=false` on graph failures that affect requested files.
- [ ] Run focused and full tests; inspect graph JSON on a multi-file fixture.
- [ ] Commit `feat: add safe cross-file module graph`.

### Task 3: Add cross-file taint and reachability analysis

**Files:**
- Create: `engine/semantic/cross-file-taint.js`
- Create: `test/cross-file-taint.test.js`
- Modify: `engine/semantic/index.js`
- Modify: `engine/semantic/taint.js`
- Modify: `engine/index.js`
- Modify: `engine/report.js`
- Modify: `docs/rules.md`

**Interfaces:**
- `analyzeCrossFileTaint(graph, parsedModules, options)` returns `{ findings, attackChains, reachability, failures, complete }`.
- Each attack chain contains source, ordered module/function hops, sink, confidence, and a stable chain fingerprint.
- Cross-file findings reuse `SEN-AGENT-*`/`SEN-TAINT-*` IDs and add `crossFile=true`, `modulePath`, `flowSteps`, and `attackChainId`.

- [ ] Add malicious and safe tests where `execute(args)` reaches shell, file, and network sinks through separate modules.
- [ ] Add negative tests for unrelated same-name functions, unresolved modules, and safe wrappers.
- [ ] Run focused tests and verify the new tests fail before implementation.
- [ ] Implement bounded interprocedural propagation with configurable depth and explicit incomplete evidence when the bound is hit.
- [ ] Integrate attack-chain deduplication so one chain is not scored once per intermediate hop.
- [ ] Run the full suite and benchmark; record cross-file precision/recall separately.
- [ ] Commit `feat: add cross-file taint and reachability analysis`.

### Task 4: Replace dependency counts with a normalized dependency graph

**Files:**
- Create: `engine/supplychain/dependency-graph.js`
- Create: `test/dependency-graph.test.js`
- Modify: `engine/supplychain/lockfile.js`
- Modify: `engine/package/audit.js`
- Modify: `engine/index.js`
- Modify: `engine/report.js`

**Interfaces:**
- `buildDependencyGraph(dir, options)` returns nodes with `{name, version, ecosystem, direct, dev, optional, integrity, resolved, parents, children, scripts}` and graph completeness metadata.
- Parsers support npm package-lock v2/v3 and npm-shrinkwrap exactly; yarn/pnpm/bun parsers return normalized nodes or explicit unsupported/incomplete evidence rather than guessed counts.
- `findDependencyPaths(graph, packageName)` returns shortest direct-to-vulnerable paths for remediation and reachability output.

- [ ] Add lockfile fixtures for npm v2/v3, workspace packages, optional/peer/dev dependencies, duplicate versions, and malformed files.
- [ ] Run focused tests and observe failures.
- [ ] Implement normalized graph construction and preserve the old count fields for compatibility.
- [ ] Add dependency graph to install audit and profile reports.
- [ ] Run full tests and verify malformed lockfiles are visible as incomplete.
- [ ] Commit `feat: add normalized dependency graph`.

### Task 5: Emit CycloneDX and SPDX SBOMs

**Files:**
- Create: `engine/supplychain/sbom.js`
- Create: `test/sbom.test.js`
- Modify: `engine/report.js`
- Modify: `engine/output/sarif.js`
- Modify: `bin/sentinel.mjs`
- Modify: `docs/integration-github-action.md`

**Interfaces:**
- `toCycloneDx(graph, metadata)` emits deterministic CycloneDX JSON with purl, hashes, dependency edges, and tool metadata.
- `toSpdx(graph, metadata)` emits deterministic SPDX JSON with package relationships and checksums.
- CLI accepts `--format cyclonedx|spdx` and `--out`; scan reports include an SBOM summary and hash, not the entire SBOM by default.

- [ ] Add tests validating required fields, deterministic ordering, purl generation, hashes, and relationship direction.
- [ ] Run focused tests to observe failure.
- [ ] Implement serializers with stable timestamps or an explicit deterministic mode for benchmark output.
- [ ] Add CLI output and documentation examples.
- [ ] Run schema-oriented assertions and full tests.
- [ ] Commit `feat: emit deterministic CycloneDX and SPDX SBOMs`.

### Task 6: Add provenance and artifact verification

**Files:**
- Create: `engine/supplychain/provenance.js`
- Create: `test/provenance.test.js`
- Modify: `engine/package/acquire.js`
- Modify: `engine/package/audit.js`
- Modify: `bin/sentinel.mjs`
- Modify: `.github/workflows/publish.yml`
- Modify: `package.json`
- Modify: `docs/roadmap.md`

**Interfaces:**
- `verifyPackageProvenance(metadata, options)` returns `{ status, issuer, sourceRepository, sourceCommit, workflow, verified, reasons }` and never downloads source code.
- `compareArtifactToSource(sourceDir, tarball)` reports extra/modified files, scripts, hashes, unexpected binaries, and a stable artifact digest.
- Publish workflow uses pinned action SHAs where practical, least-privilege permissions, npm trusted publishing, and a provenance verification smoke step.

- [ ] Add fixture tests for valid, missing, mismatched, malformed, and unavailable attestations.
- [ ] Run focused tests and confirm failure.
- [ ] Implement metadata-only verification and explicit unavailable vs invalid states.
- [ ] Update release workflow and package repository metadata to match the GitHub repository exactly.
- [ ] Run workflow YAML checks available locally and package dry-run verification.
- [ ] Commit `feat: verify package provenance and release artifacts`.

### Task 7: Add Agent capability graph and policy analysis

**Files:**
- Create: `engine/semantic/capability-graph.js`
- Create: `engine/semantic/policy.js`
- Create: `test/capability-graph.test.js`
- Modify: `engine/semantic/harness.js`
- Modify: `engine/report.js`
- Modify: `engine/rules.js`
- Modify: `docs/rules.md`

**Interfaces:**
- `buildCapabilityGraph(modules, findings)` returns tool nodes, input sources, capabilities, sinks, and attack paths.
- `evaluateCapabilityPolicy(graph, policy)` emits mismatch findings when declared tool behavior is narrower than observed behavior.
- Capabilities include shell, filesystem-read, filesystem-write, network, credentials, memory, persistence, and package-install.

- [ ] Add tests for declared-safe vs observed-shell, workspace-contained file access, credential reads, network-controlled URLs, persistence, and tool-to-tool chains.
- [ ] Run focused tests and observe failure.
- [ ] Implement capability extraction from tool metadata and semantic findings, then policy evaluation with evidence.
- [ ] Add capability graph to JSON/SARIF/HTML and CLI text output.
- [ ] Run regression tests against existing SEN-AGENT-006 behavior.
- [ ] Commit `feat: add Agent capability graph and policy analysis`.

### Task 8: Build a reproducible public DSH corpus and benchmark

**Files:**
- Create: `test/fixtures/bench/public/manifest.json`
- Create: `scripts/fetch-public-corpus.mjs`
- Create: `scripts/verify-corpus.mjs`
- Create: `scripts/benchmark-public.mjs`
- Create: `docs/public-benchmark.md`
- Modify: `package.json`
- Modify: `.github/workflows/test.yml`
- Modify: `README.md`

**Interfaces:**
- Corpus manifest entries contain repository, commit SHA, license, fetched files, expected labels, annotation source, and content hashes.
- Fetching is opt-in, rate-limited, reproducible by pinned commit, and stores only permitted source snapshots in git/LFS or release artifacts.
- Benchmark reports per-rule precision/recall/F1, finding-level location accuracy, flow-level accuracy, cross-file accuracy, and safe-edge false positives.

- [ ] Add manifest validation tests and a small checked-in public sample before scaling up.
- [ ] Run manifest tests and observe failure.
- [ ] Implement pinned fetch/verify tooling with no floating branch references.
- [ ] Add annotations for benign build scripts, real DSH tools, malicious fixtures, evasions, and cross-file flows.
- [ ] Run public benchmark and publish machine-readable results plus methodology.
- [ ] Commit `test: add reproducible public DSH benchmark corpus`.

### Task 9: Add performance, fuzz, and release gates

**Files:**
- Create: `test/fuzz/semantic-fuzz.test.js`
- Create: `scripts/benchmark-performance.mjs`
- Create: `docs/release-gate.md`
- Modify: `package.json`
- Modify: `.github/workflows/test.yml`
- Modify: `.github/workflows/action-smoke.yml`
- Modify: `README.md`

**Interfaces:**
- `npm run verify:professional` runs tests, public benchmark, SBOM contract checks, performance budget, package dry-run, and action smoke fixtures.
- Performance report records cold/warm scan time, peak memory, files/sec, and behavior at resource limits.
- Fuzz tests assert no uncaught parser exceptions, path escapes, secret leaks, or nontermination within the configured budget.

- [ ] Add failing release-gate assertions and performance budget fixtures.
- [ ] Run them to observe failure.
- [ ] Implement gates and deterministic machine-readable evidence.
- [ ] Add CI matrix, SARIF upload permissions, artifact retention, and package provenance checks.
- [ ] Run the full professional gate locally and in CI-equivalent commands.
- [ ] Commit `ci: add professional release gates and robustness tests`.

### Task 10: Final audit, versioning, and GitHub delivery

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `README.md`
- Modify: `docs/roadmap.md`
- Modify: `SECURITY.md`
- Modify: `package.json`
- Modify: `package-lock.json`

- [ ] Re-read this plan and verify every requirement against files and command output.
- [ ] Run `npm run verify:professional` and capture fresh evidence.
- [ ] Run `npm pack --dry-run` and inspect the exact package file list.
- [ ] Review `git diff`, repository status, branch, remote, and generated reports for secrets or unintended files.
- [ ] Bump version only after the release gate passes and update all version sources.
- [ ] Commit the complete upgrade with a release note.
- [ ] Push the branch/tag to the configured GitHub remote only after verification.
- [ ] Verify remote commit, workflow status, and published artifact/provenance where credentials permit.

