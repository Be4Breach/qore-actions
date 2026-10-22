# QORE security scan

A GitHub Action that starts a QORE security scan of your repository (code issues, vulnerable dependencies and
leaked secrets), waits for the result, and fails the build when the scan finds something that matters. QORE
decides pass or fail; the Action only acts on that answer.

- **No GitHub token in your pipeline.** The scan runs through the GitHub connection your organisation already
  set up in QORE.
- **A key you control.** A dedicated API key that expires and can be deleted at any time.
- **No dependencies.** One Python script using only the standard library; it runs on any GitHub-hosted runner.

## Usage

1. In QORE, open **Settings, API Keys**, choose **Use for: CI/CD scans**, and generate a key.
2. In your repository, add it as a secret named `QORE_API_KEY`.
3. Add a workflow:

```yaml
name: Security scan
on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: qore-scan-${{ github.repository }}
  cancel-in-progress: false

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: Be4Breach/qore-actions/security-scan@v1
        with:
          api-key: ${{ secrets.QORE_API_KEY }}
```

> A scan always covers the repository's **default branch**, so run the Action on pushes to that branch (or by
> hand), not on `pull_request`.

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-key` | required | Your CI/CD key (`be4ci_...`), from a secret |
| `fail-on` | `critical,kev` | Comma list of `critical`, `high`, `medium`, `low`, `kev`. A matching finding fails the build. `kev` is a vulnerability CISA lists as exploited in the wild. |
| `mode` | `new` | `new`: fail only on findings first seen in this scan. `all`: fail on every open finding. |
| `repo` | the current repository | `owner/name` to scan |
| `timeout-minutes` | `20` | How long to wait. The scan keeps running if you stop waiting. |
| `api-url` | `https://api.be4breach.com` | Only for self-hosted QORE installations |

## Outputs

| Output | Description |
|---|---|
| `verdict` | `pass`, `fail` or `error` |
| `scan-id` | The QORE scan id |

The step's exit code is `0` for pass, `1` when findings fail the build, and `2` for an error (scan failed, timed
out, or the API refused the request). An error never counts as a pass. A summary table is added to the job
summary.

On the first scan of a repository, `mode: new` records existing findings as a baseline instead of failing, except
known-exploited (`kev`) findings, which always fail the build when `kev` is in `fail-on`.

## Documentation

Setup, how results are decided, limits and troubleshooting:
<https://docs.be4breach.com/docs/devsecops/ci-cd-integration>

## Versioning

Use the major tag (`@v1`) to receive compatible updates. To pin an exact version, reference a release tag
(`@v1.0.0`) or a full commit SHA.

## Security

- The key is read from the environment, sent only as a bearer header over HTTPS, and never printed.
