# Kobayashi

A small, dependency-free CLI for exploring Codex's local
`~/.codex/logs_2.sqlite` database in read-only mode.

Kobayashi is not affiliated with, endorsed by, or sponsored by OpenAI.

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
python3 -m kobayashi captured adversarial-report --thread-id THREAD_ID
python3 -m kobayashi captured adversarial-analyze --thread-id THREAD_ID -o adversarial-analysis.md
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
When `--output-dir` is set, per-thread reports, per-thread analyses, chunk
analyses, and batch summaries are checkpointed and reused on rerun. Large
`--full` reports are automatically chunked before they are sent to the local
LLM; tune that with `--chunk-chars` if your server rejects large prompts.

Use `captured adversarial-report` for a deterministic report showing what an
adversarial reader could infer from the database. Use `captured
adversarial-analyze` to send that evidence report to a local LLM for a fuller
adversary-perspective analysis.

## Optional Local LLM Setup

The LLM-backed commands are optional. All deterministic commands work without a
local model. By default, Kobayashi refuses to send reports to non-loopback LLM
URLs because captured reports may contain private prompts, file paths, patches,
and tool arguments. Use a `127.0.0.1`, `::1`, or `localhost` URL unless you
intentionally want to send report content off-box.

### Ollama

Install Ollama, pull a chat/instruct model that fits your machine, and confirm
the local API can list models:

```bash
ollama pull MODEL_NAME
curl http://localhost:11434/api/tags
```

Then run an LLM-backed report with the Ollama provider:

```bash
python3 -m kobayashi captured analyze \
  --provider ollama \
  --model MODEL_NAME \
  --thread-id THREAD_ID \
  -o captured-analysis.md

python3 -m kobayashi captured adversarial-analyze \
  --provider ollama \
  --model MODEL_NAME \
  --thread-id THREAD_ID \
  -o adversarial-analysis.md
```

If `--model` is omitted, Kobayashi tries to discover the first locally available
model from Ollama.

### llama.cpp server

Build or install `llama-server`, download a compatible GGUF model, and start the
server on the default localhost port:

```bash
llama-server -m /path/to/model.gguf -c 8192
curl http://127.0.0.1:8080/v1/models
```

Kobayashi defaults to the llama.cpp/OpenAI-compatible URL
`http://127.0.0.1:8080/v1`, so this usually works without extra provider flags:

```bash
python3 -m kobayashi captured analyze --thread-id THREAD_ID -o captured-analysis.md
python3 -m kobayashi captured adversarial-analyze --thread-id THREAD_ID -o adversarial-analysis.md
```

For large `--full` reports, increase `--timeout`, reduce `--chunk-chars`, or
omit `--full` if the local server times out or rejects a prompt.

### Remote LLM endpoints

`--url` and `--base-url` are aliases. If you point either flag at a host that
does not resolve to loopback, Kobayashi exits before model discovery or analysis
requests are sent. To intentionally use a remote or LAN endpoint, pass
`--allow-remote`:

```bash
python3 -m kobayashi captured analyze \
  --base-url http://LLM_HOST:PORT/v1 \
  --allow-remote \
  --model MODEL_NAME \
  --thread-id THREAD_ID
```

Only use `--allow-remote` for endpoints you trust with the report contents.

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
