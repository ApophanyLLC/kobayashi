# Kobayashi

A small, dependency-free CLI for exploring Codex's local
`~/.codex/logs_2.sqlite` database in read-only mode.

```bash
python3 -m kobayashi
python3 -m kobayashi heatmap --days 10
python3 -m kobayashi targets -n 15
python3 -m kobayashi threads
python3 -m kobayashi thread THREAD_ID --full
python3 -m kobayashi events
python3 -m kobayashi calls --name exec_command --full
python3 -m kobayashi payloads -n 10
python3 -m kobayashi raw ROW_ID --json
python3 -m kobayashi captured report --thread-id THREAD_ID -o captured-report.md
python3 -m kobayashi captured report --thread-id THREAD_ID --full -o captured-report-full.md
python3 -m kobayashi captured analyze --thread-id THREAD_ID -o captured-analysis.md
python3 -m kobayashi captured analyze --thread-id THREAD_ID --full --model MODEL_NAME -o captured-analysis-full.md
python3 -m kobayashi captured analyze-db -o database-analysis.md
python3 -m kobayashi captured analyze-db --full --output-dir database-analysis-work -o database-analysis-full.md
python3 -m kobayashi captured summary --thread-id THREAD_ID
python3 -m kobayashi captured patches --thread-id THREAD_ID --full
python3 -m kobayashi captured inputs --thread-id THREAD_ID --full
python3 -m kobayashi vibes
python3 -m kobayashi tail --level WARN --body
python3 -m kobayashi search "tool_call" -n 5
```

The high-level views avoid printing full log bodies. Commands such as `raw`,
`thread --full`, `payloads --full`, `calls --full`, and `search --full` are for
intentional transcript and payload spelunking.

Use `captured report` to generate a Markdown audit of what file/patch content
and prompt-like input content was captured for a thread. Use `captured summary`,
`captured patches`, and `captured inputs` for focused terminal drilldowns.

Use `captured analyze` to send the report to a local LLM. It defaults to a
llama.cpp/OpenAI-compatible server at `http://127.0.0.1:8080/v1` and will try to
discover the model from `/v1/models` when `--model` is omitted.

Use `captured analyze-db` to walk every thread in first-seen timestamp order,
ask the local LLM for a per-thread analysis, summarize batches, and synthesize a
database-wide Markdown report. This can make many local model calls; use
`--max-threads` for a smoke test and `--output-dir` to keep per-thread artifacts.
Large `--full` reports are automatically chunked before they are sent to the
local LLM; tune that with `--chunk-chars` if your server rejects large prompts.

## License

Kobayashi is released under the Apache License, Version 2.0. Redistributions and
derived products must preserve the attribution notice in `NOTICE` as required by
that license.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or
implied, including but not limited to warranties of correctness, reliability,
merchantability, fitness for a particular purpose, or non-infringement. The
authors and contributors make no guarantees about the accuracy, completeness, or
suitability of any output, report, analysis, classification, or recommendation
produced by this software.

You are solely responsible for how you install, configure, run, interpret, and
use this software and any data or reports it produces. To the maximum extent
permitted by applicable law, the authors and contributors will not be liable for
any claim, damages, loss, exposure, misuse, or other liability arising from or
related to the software or its use. By using this software, you assume all risks
and responsibilities associated with that use.
