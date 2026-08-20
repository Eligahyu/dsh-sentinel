# Public DSH corpus

The scanner regression corpus contains public DSH-related repositories selected
for ecosystem coverage. The downloaded source is used locally for regression
scans and is intentionally not committed or shipped in the npm package.

`public-corpus-manifest.json` records each repository, its pinned default branch
commit, and SHA-256 hashes for the files used by the local corpus snapshot. This
keeps benchmark claims auditable without redistributing third-party source.

```text
node scripts/fetch-corpus.mjs
node scripts/scan-corpus.mjs
node scripts/write-corpus-manifest.mjs
```

The manifest is metadata only. A missing or changed local file must be treated as
corpus drift, not silently accepted as a fresh benchmark result.
