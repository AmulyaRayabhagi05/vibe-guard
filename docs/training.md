# Training the VibeCheck fix model

The goal is a small local model (`vibecheck-coder`, DeepSeek-Coder 7B + DPO LoRA, served by Ollama)
that rewrites a flagged REGION of code so the security or accessibility finding goes away without
introducing new ones. Everything is free: local Ollama models for data, Kaggle GPUs for training,
and the Hugging Face Hub for storage.

## Pipeline

```
dataset/prompts.py        stacks x feature requests ("vibe coder" phrasing), deterministic by seed
   │
dataset/generate_apps.py  local Ollama model writes multi-file apps   → out/apps/<id>/, out/specs/<id>.json
   │
dataset/label.py          engine scan on each app                     → out/labels.jsonl
   │
dataset/build_pairs.py    REGION/CONTEXT per finding → teacher fix (chosen, validated by re-scan)
   │                      + base-model fix that fails validation or a wrong mutation (rejected)
   │                                                                  → out/pairs_raw.jsonl
   │   + dataset/real_world.py  CVEfixes / CrossVul / HF pairs        → out/real_world_pairs.jsonl
   │
   └─ split 90/5/5 by app id                                          → out/pairs/{dpo,sft}_{train,val,test}.jsonl
training/train_dpo.py     Unsloth + TRL DPO, 4-bit QLoRA (Kaggle)     → LoRA adapter (HF Hub)
training/export_gguf.md   merge → GGUF Q4_K_M → ollama create vibecheck-coder -f training/Modelfile
training/evaluate.py      fix rate / regression rate / latency on the test split (MLflow optional)
```

The prompt format comes from one place: `engine/vibecheck_engine/fixer/prompt.py`. Dataset scripts
import `build_messages` from it, and `training/make_modelfile.py` copies its `SYSTEM` into the
Modelfile. If you change the prompt, rebuild the pairs and the Modelfile.

### Pair record (`out/pairs/dpo_*.jsonl`)

```json
{"prompt": [{"role": "system", "content": "<SYSTEM>"}, {"role": "user", "content": "<build_user_prompt(...)>"}],
 "chosen": "```python\n<validated fixed REGION>\n```",
 "rejected": "```python\n<failing or wrong REGION>\n```",
 "meta": {"key", "app_id", "app_dir", "source", "path", "language", "rule_id", "category", "severity",
          "cwe", "owasp", "wcag", "start_line", "end_line", "region_start", "region_end",
          "validatable", "rejected_source", "split", ...}}
```

`sft_*.jsonl` has `{"messages": prompt + [{"role": "assistant", "content": chosen}], "meta": ...}`.

## Setup

```bash
ollama pull qwen2.5-coder:14b              # app generator (any decent coder model works)
ollama pull qwen2.5-coder:32b              # teacher for chosen fixes (14b if RAM is tight)
ollama pull deepseek-coder:6.7b-instruct   # base model for rejected fixes and as the eval baseline
```

Before starting `ollama serve`, set `OLLAMA_NUM_PARALLEL=2` (two requests at once) and
`OLLAMA_MAX_LOADED_MODELS=2` (keeps the teacher and base models loaded together, so they don't swap).

The dataset scripts use only the standard library. They call the engine as
`python -m vibecheck_engine scan <dir> --json`, so run them with a Python that has the engine's
dependencies, or pass `--python path/to/venv/python`. Run the dataset scripts themselves with that
Python as well. With tree-sitter importable, `dataset/common.py` picks REGION, splices fixes and
checks parsing with the engine's own `context.py`, so training examples match what the extension
sends at inference. Without tree-sitter it falls back to "enclosing function or ±8 lines". All scripts can be resumed: re-run the same
command after a crash or a reboot.

## 2k pilot (prove the loop first)

```bash
python dataset/prompts.py --limit 2000 --stats
python dataset/generate_apps.py --limit 2000 --model qwen2.5-coder:14b --workers 2
python dataset/label.py --workers 4
python dataset/real_world.py --sources hf-cvefixes,cybernative --max-pairs 500
python dataset/build_pairs.py --teacher qwen2.5-coder:32b --base deepseek-coder:6.7b-instruct \
    --workers 2 --max-per-app 3 --extra dataset/out/real_world_pairs.jsonl
python training/train_dpo.py --data dataset/out/pairs --dry-run
```

Check before scaling up: `out/label.log` should show findings in every category (app, secret, ai,
a11y). `out/pairs/stats.json` should show a sensible chosen yield, and `pairs_raw.jsonl` statuses
should not be mostly `teacher_failed`. Hand-check about 50 test pairs. Then train on Kaggle
(`training/kaggle_notebook.md`), export (`training/export_gguf.md`) and run:

```bash
python training/evaluate.py --models deepseek-coder:6.7b-instruct,vibecheck-coder
```

## 20k full run

Specs are deterministic: the first 2,000 of the 20k run are the pilot apps, so nothing is redone.

```bash
python dataset/generate_apps.py --limit 20000 --models qwen2.5-coder:14b,deepseek-coder-v2:16b,llama3.1:8b --workers 2
python dataset/label.py --workers 4
python dataset/real_world.py --sources hf-cvefixes,cybernative --max-pairs 5000
#   optional, bigger and cleaner: --sources cvefixes-db --cvefixes-db CVEfixes.db --scan
python dataset/build_pairs.py --teacher qwen2.5-coder:32b --workers 2 --max-per-app 5 \
    --extra dataset/out/real_world_pairs.jsonl
```

Then train with `--sft-warmup --epochs 1` (add a second epoch only if the val reward margin is still
rising), export, and evaluate base vs SFT-only vs DPO.

## Time and disk (rough, consumer GPU / Apple Silicon)

| step | 2k pilot | 20k |
|---|---|---|
| generate (14B, ~1–2 min/app, 2 parallel) | ~1–2 days | ~10–15 days, run it overnight |
| label (engine scan, ~5–20 s/app) | ~2–4 h | ~1–2 days |
| build_pairs (teacher + base + 1–3 rescans per finding) | ~2–3 days | the slowest step; cap with `--max-per-app` |
| disk | ~200 MB | ~2 GB |

## Evaluation metrics

- **fix rate**: share of test findings where the patched app passes validation (target finding
  gone, no new findings, file still parses).
- **regression rate**: share of patches that add a finding or break parsing.
- **format fail**: replies without a fenced code block.
- **latency/tokens**: average and p95 seconds, and prompt/completion tokens per fix, from Ollama.

Results go to `dataset/out/eval/<model>/summary.json`. They are also logged to MLflow when
`MLFLOW_TRACKING_URI` is set. Real-world pairs that came from diffs only (no app on disk) are scored
by similarity to the upstream fix instead of re-scanning.
