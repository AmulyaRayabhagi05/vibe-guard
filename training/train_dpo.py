"""DPO fine-tune of DeepSeek-Coder with Unsloth + TRL (4-bit QLoRA), built for free Kaggle/Colab GPUs.

    python training/train_dpo.py --data dataset/out/pairs --output runs/vibecheck-dpo
    python training/train_dpo.py --data /kaggle/input/vibecheck-pairs --output /kaggle/working/run \
        --sft-warmup --push-to-hub you/vibecheck-coder-lora     # resumes automatically next session
    python training/train_dpo.py --data dataset/out/pairs --dry-run   # check data, no GPU needed

Inputs: dpo_{train,val}.jsonl (+ sft_train.jsonl for --sft-warmup) from dataset/build_pairs.py.

Chat template: prompts are stored as message lists (system + user) built by
engine/vibecheck_engine/fixer/prompt.py. They are rendered here with the model tokenizer's own
chat template (apply_chat_template, add_generation_prompt=True), and the completion is whatever
the template puts after that prefix for the assistant turn. For deepseek-coder-*-instruct that is
"### Instruction:\n...\n### Response:\n<fix>\n<|EOT|>". TRL appends the EOS token (<|EOT|>) to
chosen/rejected itself, so it is stripped from the rendered completion to avoid doubling it.
Ollama must use the same template at inference (see training/Modelfile).

MLflow: set MLFLOW_TRACKING_URI (and optionally MLFLOW_EXPERIMENT_NAME) and the HF Trainer's
MLflow callback logs params, loss and DPO reward metrics.
"""
from __future__ import annotations

import argparse
import inspect
import json
import os
import sys
from pathlib import Path

DEFAULT_BASE = "deepseek-ai/deepseek-coder-7b-instruct-v1.5"
LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def check_records(recs: list[dict], kind: str) -> list[str]:
    """Return problems found in the data (dry run and pre-flight)."""
    problems = []
    for i, r in enumerate(recs):
        msgs = r["prompt"] if kind == "dpo" else r["messages"]
        roles = [m["role"] for m in msgs]
        want = ["system", "user"] if kind == "dpo" else ["system", "user", "assistant"]
        if roles != want:
            problems.append(f"{kind}[{i}] roles {roles}")
        if kind == "dpo":
            for k in ("chosen", "rejected"):
                if not r.get(k, "").lstrip().startswith("```"):
                    problems.append(f"dpo[{i}] {k} is not a fenced block")
            if r.get("chosen") == r.get("rejected"):
                problems.append(f"dpo[{i}] chosen == rejected")
        if len(problems) > 20:
            break
    return problems


# ---------------------------------------------------------------- formatting

def completion_after_prompt(tokenizer, prompt_msgs: list[dict], answer: str) -> tuple[str, str]:
    """(prompt_text, completion_text) rendered with the tokenizer's chat template."""
    prompt_text = tokenizer.apply_chat_template(prompt_msgs, tokenize=False, add_generation_prompt=True)
    full = tokenizer.apply_chat_template(prompt_msgs + [{"role": "assistant", "content": answer}],
                                         tokenize=False, add_generation_prompt=False)
    if full.startswith(prompt_text):
        completion = full[len(prompt_text):]
    else:  # templates that render the generation prompt differently
        completion = "\n" + answer
    eos = tokenizer.eos_token or ""
    completion = completion.rstrip()
    if eos and completion.endswith(eos):
        completion = completion[: -len(eos)]
    return prompt_text, completion


def to_dpo_rows(tokenizer, recs: list[dict]) -> list[dict]:
    rows = []
    for r in recs:
        p, chosen = completion_after_prompt(tokenizer, r["prompt"], r["chosen"])
        _, rejected = completion_after_prompt(tokenizer, r["prompt"], r["rejected"])
        rows.append({"prompt": p, "chosen": chosen, "rejected": rejected})
    return rows


def to_sft_rows(tokenizer, recs: list[dict]) -> list[dict]:
    return [{"text": tokenizer.apply_chat_template(r["messages"], tokenize=False)} for r in recs]


def _kw(cls, **kwargs):
    """Drop kwargs this TRL/transformers version doesn't accept (names moved between releases,
    e.g. max_seq_length -> max_length, tokenizer -> processing_class)."""
    params = inspect.signature(cls.__init__).parameters
    if any(p.kind == p.VAR_KEYWORD for p in params.values()):
        return kwargs
    dropped = sorted(set(kwargs) - set(params))
    if dropped:
        print(f"{cls.__name__}: ignoring unsupported args {dropped}")
    return {k: v for k, v in kwargs.items() if k in params}


def trainer_kwargs(cls, tokenizer, **kwargs):
    params = inspect.signature(cls.__init__).parameters
    key = "processing_class" if "processing_class" in params else "tokenizer"
    return {**{k: v for k, v in kwargs.items() if k in params}, key: tokenizer}


# ---------------------------------------------------------------- checkpoints

def find_resume(output_dir: Path, hub_model_id: str | None) -> str | None:
    from transformers.trainer_utils import get_last_checkpoint

    if output_dir.exists():
        last = get_last_checkpoint(str(output_dir))
        if last:
            return last
    if hub_model_id:
        # hub_strategy="checkpoint" keeps the newest checkpoint in <repo>/last-checkpoint
        try:
            from huggingface_hub import snapshot_download

            snapshot_download(hub_model_id, allow_patterns=["last-checkpoint/*"], local_dir=str(output_dir))
            ck = output_dir / "last-checkpoint"
            if (ck / "trainer_state.json").exists():
                return str(ck)
        except Exception as e:  # noqa: BLE001 - first session: nothing on the hub yet
            print(f"no hub checkpoint to resume from ({str(e)[:120]})")
    return None


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=Path("dataset/out/pairs"))
    ap.add_argument("--output", type=Path, default=Path("runs/vibecheck-dpo"))
    ap.add_argument("--base-model", default=DEFAULT_BASE)
    ap.add_argument("--max-len", type=int, default=2048)
    ap.add_argument("--max-prompt-len", type=int, default=1536)
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--lr", type=float, default=5e-6)
    ap.add_argument("--beta", type=float, default=0.1)
    ap.add_argument("--lora-r", type=int, default=16)
    ap.add_argument("--lora-alpha", type=int, default=32)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--grad-accum", type=int, default=8)
    ap.add_argument("--save-steps", type=int, default=200)
    ap.add_argument("--eval-steps", type=int, default=200)
    ap.add_argument("--max-steps", type=int, default=-1, help="smoke tests")
    ap.add_argument("--limit", type=int, default=0, help="use only N training pairs")
    ap.add_argument("--sft-warmup", action="store_true", help="1 short SFT pass on chosen fixes before DPO")
    ap.add_argument("--sft-epochs", type=float, default=1.0)
    ap.add_argument("--sft-lr", type=float, default=2e-4)
    ap.add_argument("--push-to-hub", dest="hub_model_id", default=None,
                    help="HF repo id; checkpoints are pushed as they are saved (needs HF_TOKEN)")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--seed", type=int, default=3407)
    ap.add_argument("--dry-run", action="store_true", help="validate data files and exit (no torch)")
    a = ap.parse_args()

    train = read_jsonl(a.data / "dpo_train.jsonl")
    val = read_jsonl(a.data / "dpo_val.jsonl")
    sft = read_jsonl(a.data / "sft_train.jsonl") if a.sft_warmup else []
    if a.limit:
        train, sft = train[: a.limit], sft[: a.limit]
    problems = check_records(train, "dpo") + check_records(val, "dpo") + check_records(sft, "sft")
    print(f"dpo train={len(train)} val={len(val)} sft={len(sft)} problems={len(problems)}")
    for p in problems[:20]:
        print("  ", p)
    if a.dry_run:
        if train:
            print("example user prompt:\n" + train[0]["prompt"][1]["content"][:600])
            print("example chosen:\n" + train[0]["chosen"][:300])
        sys.exit(1 if problems or not train else 0)
    if not train:
        sys.exit(f"no training data in {a.data}")

    # Unsloth must be imported before transformers/trl so its patches apply.
    from unsloth import FastLanguageModel, PatchDPOTrainer, is_bfloat16_supported

    PatchDPOTrainer()
    from datasets import Dataset
    from trl import DPOConfig, DPOTrainer

    use_mlflow = bool(os.environ.get("MLFLOW_TRACKING_URI"))
    report_to = ["mlflow"] if use_mlflow else "none"
    os.environ.setdefault("MLFLOW_EXPERIMENT_NAME", "vibecheck-dpo")
    bf16 = is_bfloat16_supported()  # T4/P100: False -> fp16

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=a.base_model, max_seq_length=a.max_len, dtype=None, load_in_4bit=True,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = FastLanguageModel.get_peft_model(
        model, r=a.lora_r, lora_alpha=a.lora_alpha, lora_dropout=0, bias="none",
        target_modules=LORA_TARGETS, use_gradient_checkpointing="unsloth", random_state=a.seed,
    )

    resume = None if a.no_resume else find_resume(a.output, a.hub_model_id)
    common = dict(
        per_device_train_batch_size=a.batch_size, gradient_accumulation_steps=a.grad_accum,
        warmup_ratio=0.1, lr_scheduler_type="linear", optim="adamw_8bit", weight_decay=0.0,
        fp16=not bf16, bf16=bf16, logging_steps=10, save_strategy="steps", save_steps=a.save_steps,
        save_total_limit=3, seed=a.seed, report_to=report_to, max_steps=a.max_steps,
        push_to_hub=bool(a.hub_model_id), hub_model_id=a.hub_model_id, hub_strategy="checkpoint",
        hub_private_repo=False,
    )

    # ---- optional SFT warm-up (skipped on resume once it has finished)
    sft_dir = a.output / "sft"
    sft_done = sft_dir / "DONE"
    # resume is only ever a DPO checkpoint (get_last_checkpoint does not look inside sft/)
    if a.sft_warmup and sft and not sft_done.exists() and resume is None:
        from trl import SFTConfig, SFTTrainer

        sft_resume = None
        if not a.no_resume and sft_dir.exists():
            from transformers.trainer_utils import get_last_checkpoint

            sft_resume = get_last_checkpoint(str(sft_dir))
        sft_ds = Dataset.from_list(to_sft_rows(tokenizer, sft))
        sft_args = SFTConfig(**_kw(SFTConfig, output_dir=str(sft_dir), num_train_epochs=a.sft_epochs,
                                   learning_rate=a.sft_lr, dataset_text_field="text",
                                   max_seq_length=a.max_len, max_length=a.max_len, packing=False,
                                   **{**common, "push_to_hub": False}))
        sft_trainer = SFTTrainer(**trainer_kwargs(SFTTrainer, tokenizer, model=model, args=sft_args,
                                                  train_dataset=sft_ds))
        sft_trainer.train(resume_from_checkpoint=sft_resume)
        sft_done.parent.mkdir(parents=True, exist_ok=True)
        sft_done.write_text("ok", encoding="utf-8")
        model.save_pretrained(str(sft_dir / "adapter"))
    elif a.sft_warmup and sft_done.exists() and resume is None:
        # SFT finished in an earlier session but DPO had not checkpointed yet: reload the SFT adapter
        from peft import set_peft_model_state_dict
        from safetensors.torch import load_file

        ad = sft_dir / "adapter" / "adapter_model.safetensors"
        if ad.exists():
            set_peft_model_state_dict(model, load_file(str(ad)))
            print("loaded SFT warm-up adapter")

    # ---- DPO
    train_ds = Dataset.from_list(to_dpo_rows(tokenizer, train))
    eval_ds = Dataset.from_list(to_dpo_rows(tokenizer, val)) if val else None
    args = DPOConfig(**_kw(
        DPOConfig, output_dir=str(a.output), num_train_epochs=a.epochs, learning_rate=a.lr, beta=a.beta,
        max_length=a.max_len, max_prompt_length=a.max_prompt_len,
        max_completion_length=a.max_len - a.max_prompt_len,
        eval_strategy="steps" if eval_ds is not None else "no",
        eval_steps=a.eval_steps if eval_ds is not None else None, per_device_eval_batch_size=1,
        **common,
    ))
    trainer = DPOTrainer(**trainer_kwargs(
        DPOTrainer, tokenizer, model=model, ref_model=None,  # PEFT: reference = adapter disabled
        args=args, train_dataset=train_ds, eval_dataset=eval_ds,
    ))
    if use_mlflow:
        try:
            import mlflow

            mlflow.log_params({"base_model": a.base_model, "lora_r": a.lora_r, "lora_alpha": a.lora_alpha,
                               "dpo_beta": a.beta, "n_train": len(train), "n_val": len(val),
                               "sft_warmup": a.sft_warmup})
        except Exception as e:  # noqa: BLE001 - logging must never stop training
            print(f"mlflow param logging skipped: {e}")
    print(f"resume_from_checkpoint={resume}")
    trainer.train(resume_from_checkpoint=resume)

    final = a.output / "final-adapter"
    model.save_pretrained(str(final))
    tokenizer.save_pretrained(str(final))
    if a.hub_model_id:
        model.push_to_hub(a.hub_model_id)
        tokenizer.push_to_hub(a.hub_model_id)
    print(f"saved adapter to {final}")


if __name__ == "__main__":
    main()
