# Training on Kaggle's free GPUs

Kaggle gives about 30 GPU hours a week, and a single session runs for up to 12 hours.
`train_dpo.py` saves a checkpoint every 200 steps and pushes it to the Hugging Face Hub, so a run
that needs more than one session continues where it stopped. All of this is free.

## One-time setup

1. **Hugging Face**: create a free account and a **write** token (Settings → Access Tokens).
   Create an empty model repo for checkpoints, e.g. `you/vibecheck-coder-lora`.
2. **Upload the pairs** as a Kaggle Dataset: zip `dataset/out/pairs/` (the `dpo_*.jsonl` and
   `sft_*.jsonl` files) and create a dataset called `vibecheck-pairs` at kaggle.com/datasets.
   A private dataset is fine.
3. **Kaggle phone verification** is required before Kaggle turns on GPUs and internet access.

## Notebook settings

- Accelerator: **GPU T4 x2**. Unsloth trains on one GPU, and the T4 (16 GB) fits 7B QLoRA DPO.
  Don't pick P100: it is compute capability 6.0, and Unsloth's Triton kernels need 7.0 or newer.
- Internet: **on**. Persistence: **Files only**, which keeps `/kaggle/working` between runs.
- Add-ons → Secrets: add `HF_TOKEN` (your write token) and attach it to the notebook.
- Add data: your `vibecheck-pairs` dataset. It appears under `/kaggle/input/vibecheck-pairs/`.

## Cells

```python
# 1. install (about 3 minutes)
!pip install -q unsloth "trl>=0.12" mlflow
```

```python
# 2. secrets + MLflow to a local sqlite file you download afterwards
import os
from kaggle_secrets import UserSecretsClient
os.environ["HF_TOKEN"] = UserSecretsClient().get_secret("HF_TOKEN")
os.environ["MLFLOW_TRACKING_URI"] = "sqlite:////kaggle/working/mlflow.db"
os.environ["MLFLOW_EXPERIMENT_NAME"] = "vibecheck-dpo"
```

```python
# 3. get the training script (it is self-contained; only needs the jsonl files)
!wget -q -O train_dpo.py https://raw.githubusercontent.com/<you>/vibecheck/main/training/train_dpo.py
# or upload training/train_dpo.py as part of the Kaggle dataset and copy it from /kaggle/input
!python train_dpo.py --data /kaggle/input/vibecheck-pairs --dry-run
```

```python
# 4. smoke test: 10 steps, checks memory and the chat template before burning hours
!python train_dpo.py --data /kaggle/input/vibecheck-pairs --output /kaggle/working/smoke --max-steps 10 --no-resume
```

```python
# 5. the real run. Resumes automatically from /kaggle/working or the Hub's last-checkpoint.
!python train_dpo.py --data /kaggle/input/vibecheck-pairs --output /kaggle/working/run \
    --sft-warmup --epochs 1 --push-to-hub you/vibecheck-coder-lora
```

For long runs, use **Save Version → Save & Run All (Commit)** rather than an interactive session.
A commit runs in the background for up to 12 hours even with the browser closed. In the next
session, run the same cells again: `find_resume` picks up the newest `checkpoint-*` in
`/kaggle/working/run`, or downloads `last-checkpoint/` from the Hub.

The SFT warm-up is not pushed to the Hub. It is short (one pass over the chosen fixes). If a
session dies during the warm-up, the next session repeats it. Once any DPO checkpoint exists, the
warm-up is skipped.

## After training

- The final adapter is in `/kaggle/working/run/final-adapter` and on the Hub (`you/vibecheck-coder-lora`).
- Download `/kaggle/working/mlflow.db` and `mlruns/`, then view them locally:
  `mlflow server --backend-store-uri sqlite:///mlflow.db --host 127.0.0.1`.
- Merge and export: see `training/export_gguf.md`. A Kaggle CPU session (30 GB RAM) can do the merge.

## Rough budget (not measured, check with the smoke test)

7B QLoRA DPO at 2048 tokens with batch 1 × grad-accum 8 on a T4 is on the order of 20–40 s per
optimizer step. The 2k-app pilot (~2–4k pairs) is about 1 session. The 20k run (~20–40k pairs, one
epoch) needs about 3–6 sessions, which is one or two weeks of free quota. To fit a single session,
lower `--max-len` to 1536 or cap the run with `--limit`.
