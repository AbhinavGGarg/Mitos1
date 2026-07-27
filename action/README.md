# Mitos as a GitHub Action

A library you install is written down, and every scanner works by reading that list. A file
you copied in is not written down at all, so when the original ships a security fix, your
copy never hears about it.

This action finds those copies in your repository, transplants the fix they missed, and
proves the patched file still compiles before it opens anything.

## Use it

```yaml
name: Vendored code
on:
  schedule: [{ cron: "0 6 * * 1" }]   # upstream fixes land on upstream's schedule, not yours
  workflow_dispatch:

permissions:
  contents: write
  pull-requests: write

jobs:
  backport:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - id: mitos
        uses: AbhinavGGarg/Mitos1/action@main

      - name: Open a pull request
        if: steps.mitos.outputs.patched == 'true'
        uses: peter-evans/create-pull-request@v6
        with:
          branch: mitos/backport
          title: "Backport upstream security fixes into vendored copies"
          body-path: ${{ steps.mitos.outputs.report }}
          commit-message: "Backport upstream fixes into vendored copies"
```

The first run reports and does not block. Set `fail-on-stale: true` once you want a stale
copy to break the build.

## Why it runs in your CI

Verifying a transplant means compiling the patched file, and the behavioural probe builds
and runs a binary from your own source. Your CI is already where your code compiles and
runs. Nothing here uploads your source anywhere, and nothing asks Mitos to execute code
from a repository it does not own. Set `probe: false` to compile without running anything.

## What a verdict means

| verdict | what was established |
| --- | --- |
| `VERIFIED_BEHAVIOURAL` | every transplanted line is live code in the expected function, the file compiles, and a crafted input the original accepts is now rejected |
| `VERIFIED_PLACEMENT` | every transplanted line is live code in the expected function, and the file compiles |
| `VERIFIED_PLACEMENT_NO_REGRESSION` | placement holds, and the copy does not build standalone because it needs your project's flags, so the answerable claim is that no new compiler error was introduced |
| `NOT_VERIFIED` | Mitos refused. The reason is printed under the copy. |

A hunk Mitos cannot place unambiguously is skipped and said so, never guessed. None of
these verdicts claim your shipped application was exploitable, or that your test suite ran.

## Inputs

| input | default | meaning |
| --- | --- | --- |
| `path` | `.` | directory to scan |
| `libraries` | all | restrict to one catalog library |
| `probe` | `true` | run the behavioural probe (builds and runs a binary from the scanned source) |
| `fail-on-stale` | `false` | fail the job when a copy is missing its fix |

## Outputs

`stale`, `verified`, and `patched` — the last is `true` when the working tree contains
verified patches, which is the condition to open a pull request on.
