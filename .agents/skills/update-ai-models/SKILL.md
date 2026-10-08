---
name: update-ai-models
description: Find new OpenRouter decision models, retest the listed ones, then update the README table and the live-tests workflow matrix.
disable-model-invocation: true
---

# update-ai-models

Keeps the AiSpamDetector model list honest: README table (`### AiSpamDetector`, "Models tested on OpenRouter") and the `matrix.model` list in `.github/workflows/live-tests.yml`. The recommended (✅) rows and the matrix hold the same models.

Run from the package root. Commit nothing; leave the diff for the human.

## 1. Collect models

Fetch the decision-model list with `curl` (WebFetch gets a 404 on OpenRouter):

```bash
curl -s 'https://openrouter.ai/api/v1/models?output_modalities=decisions' | jq -r '.data[].id'
```

A **candidate** is a listed id that has no row in the README table. Ids starting with `~` are floating aliases (`~typesafe/jev-latest`); the table pins the version instead (`typesafe/jev-1.13`), so skip them. A new pinned version (`typesafe/jev-1.14`) is a candidate. A `:free` variant of a listed model is a candidate.

The **roster** is every table row plus every candidate. A listed row missing from the API list stays in the roster and is reported to the human as possibly retired.

Done when the roster is written out with each id marked `new` or `listed`.

## 2. Price

For each roster id, take the lowest input price across its providers (the figure the model page shows), per million tokens, rounded to at most three decimals, trailing zeros trimmed, at least two decimals (`0.02`, `0.042`, `0.10`):

```bash
curl -s "https://openrouter.ai/api/v1/models/$ID/endpoints" | jq '[.data.endpoints[].pricing.prompt|tonumber]|min*1000000'
```

Check the completion price of every roster id the same way. A non-zero completion price goes into the model's note and changes the "output tokens are free" sentence above the table.

Done when every roster id has a price (`free` for 0).

## 3. Test

Needs `OPENROUTER_API_KEY` and `THREAT_BLOCKER_AI_SPAM_DETECTOR_PROVIDER=openrouter` in `.env`. Keep the key out of every output.

Run one model per command, **twice** (suite time varies run to run):

```bash
THREAT_BLOCKER_AI_SPAM_DETECTOR_MODEL="$ID" vendor/bin/pest --group=live --colors=never 2>&1
```

Record per run: tests passed out of 17, `Duration`, any `AiSpamDetector:` warning (`ProviderConnectionException` is a timeout, which the detector turns into an allowed request), and the `[category] name: ...` probability lines.

Per model derive:

- **score** of a submission = spam + phishing; the detector blocks at `threshold` (0.8).
- **legit max** = highest score among the six legitimate cases.
- **blocked min** = lowest score among the eleven spam and phishing cases.
- **suite time** = mean of the two `Duration` values.

Done when every roster id has two recorded runs and the four derived figures.

## 4. Decide

Thresholds below are defaults [da confermare].

A model is ✅ when all hold:

- both runs pass 17/17 with no provider warning;
- legit max ≤ 0.2 and blocked min ≥ 0.9, in both runs;
- suite time is under 2× the median suite time of the roster.

Every other model is ❌, with the reason in its note. Price orders the table and is named in the notes; a ✅ model keeps its ✅ however high its price.

Notes state measured facts only:

- `Passes the live tests.` as the base.
- Append `with the widest margins` to the ✅ model(s) with the highest (blocked min − legit max).
- Append `and is the fastest` / `but is the most expensive` for the extreme of the ✅ rows.
- ❌ notes: the failing cases, `scores close to the threshold`, `sometimes hits the timeout (request allowed)`, the `N-Mx slower` factor, or the provider error text.

A verdict that moved against the old README (✅→❌ or the reverse) is reported to the human with the two runs' numbers.

Done when every roster id has ✅ or ❌ and a note.

## 5. Update the README table

Rewrite the table in place: ✅ rows by price ascending (`free` first), then ❌ rows. Columns: Model, Recommended, Input price / 1M tokens (`$0.042`, `free`, `-` when unknown), Test results / limitations. Pad cells so the pipes line up. Set the line above the table to `Models tested on OpenRouter, ordered by lowest provider price as of <today's date, YYYY-MM-DD> (output tokens are free for all of them):`. Leave the paragraph under the table untouched.

Done when the table has exactly one row per roster id.

## 6. Update the workflow

Set `matrix.model` in `.github/workflows/live-tests.yml` to the ✅ ids in table order, quoted with single quotes, one line, same style as the file. Leave every other line of the workflow untouched.

Done when the matrix equals the ✅ rows.

## 7. Report

Print `git diff --stat`, then a table of id, verdict, price, suite time, legit max, blocked min, and a list of the verdicts that changed. Tell the human what is left to commit.
