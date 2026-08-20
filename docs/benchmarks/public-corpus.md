# Public DSH corpus

The scanner regression corpus contains public DSH-related repositories selected
for ecosystem coverage. The downloaded source is used locally for regression
scans and is intentionally not committed or shipped in the npm package.

`public-corpus-manifest.json` records each repository's exact commit and validated
tree counts. Repositories are acquired as source-complete shallow Git clones; no
dependency install, lifecycle script, build, import, or plugin execution occurs.

```text
node scripts/fetch-corpus.mjs
node scripts/scan-corpus.mjs
node scripts/write-corpus-manifest.mjs
```

The manifest is metadata only. `write-corpus-manifest.mjs` refuses legacy partial
CDN snapshots and only accepts a validated `full-shallow-clone` corpus. A missing
or changed repository must be treated as corpus drift, not silently accepted as a
fresh benchmark result.
