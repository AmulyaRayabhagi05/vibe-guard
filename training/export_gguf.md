# Export the trained adapter to GGUF and serve it with Ollama

Input: the LoRA adapter from `train_dpo.py` (`runs/vibecheck-dpo/final-adapter`, or the HF repo you
pushed to). Output: `vibecheck-coder-Q4_K_M.gguf` (about 4.5 GB) and an Ollama model called
`vibecheck-coder`.

Merging needs about 16 GB of RAM (7B in fp16) and no GPU. A Kaggle CPU session works if your laptop
doesn't have enough memory.

## 1. Merge the adapter into the base model

Unsloth (same environment you trained in):

```python
from unsloth import FastLanguageModel

model, tok = FastLanguageModel.from_pretrained(
    "runs/vibecheck-dpo/final-adapter",   # or "you/vibecheck-coder-lora"
    max_seq_length=2048, load_in_4bit=False,
)
model.save_pretrained_merged("merged", tok, save_method="merged_16bit")
```

Plain PEFT, without Unsloth:

```python
import torch
from peft import AutoPeftModelForCausalLM
from transformers import AutoTokenizer

m = AutoPeftModelForCausalLM.from_pretrained("runs/vibecheck-dpo/final-adapter", torch_dtype=torch.float16)
m.merge_and_unload().save_pretrained("merged", safe_serialization=True)
AutoTokenizer.from_pretrained("runs/vibecheck-dpo/final-adapter").save_pretrained("merged")
```

Check that `merged/tokenizer_config.json` still contains the DeepSeek `chat_template`. The Modelfile
below copies it by hand, but llama.cpp also embeds it in the GGUF.

## 2. Convert to GGUF with llama.cpp and quantize to Q4_K_M

```bash
git clone --depth 1 https://github.com/ggml-org/llama.cpp
pip install -r llama.cpp/requirements/requirements-convert_hf_to_gguf.txt

python llama.cpp/convert_hf_to_gguf.py merged --outtype f16 --outfile vibecheck-coder-f16.gguf

cmake -S llama.cpp -B llama.cpp/build -DGGML_CUDA=OFF
cmake --build llama.cpp/build --config Release --target llama-quantize -j
llama.cpp/build/bin/llama-quantize vibecheck-coder-f16.gguf vibecheck-coder-Q4_K_M.gguf Q4_K_M
```

On Windows the binary is `llama.cpp\build\bin\Release\llama-quantize.exe`. You can also download a
prebuilt release zip from https://github.com/ggml-org/llama.cpp/releases and skip the cmake step.

Shortcut: Unsloth can do steps 1 and 2 in one call with
`model.save_pretrained_gguf("gguf", tok, quantization_method="q4_k_m")`, which builds llama.cpp for you.

## 3. Create the Ollama model

`training/Modelfile` is generated from the engine's prompt module, so the SYSTEM prompt matches
training exactly. Regenerate it pointing at your GGUF, then create the model:

```bash
python training/make_modelfile.py --gguf ./vibecheck-coder-Q4_K_M.gguf   # path is relative to the Modelfile
cp vibecheck-coder-Q4_K_M.gguf training/
ollama create vibecheck-coder -f training/Modelfile
```

What the Modelfile sets, and why:
- `TEMPLATE`: the deepseek-coder instruct format used at training time:
  `<bos>{system}### Instruction:\n{user}\n### Response:\n`. The template puts no newline between
  the system text and `### Instruction:`, which matches what `apply_chat_template` produced.
- `SYSTEM`: `SYSTEM` from `engine/vibecheck_engine/fixer/prompt.py`, inlined.
- `temperature 0.1`, `num_predict 1024`, `repeat_penalty 1.0` (a penalty hurts copying code verbatim).
- stop tokens `<|EOT|>` (DeepSeek's end of turn), `### Instruction:` and `<｜end▁of▁sentence｜>`.

## 4. Smoke test and evaluate

```bash
ollama run vibecheck-coder "Language: python ..."     # quick manual check
python training/evaluate.py --models deepseek-coder:6.7b-instruct,vibecheck-coder --limit 300
```

## 5. Publish (optional, free)

```bash
huggingface-cli upload you/vibecheck-coder-GGUF vibecheck-coder-Q4_K_M.gguf
```

Users can then point the Modelfile at the hub copy (`FROM hf.co/you/vibecheck-coder-GGUF:Q4_K_M`)
and run `ollama create vibecheck-coder -f Modelfile`. That keeps our TEMPLATE/SYSTEM/stop settings,
which a bare `ollama pull hf.co/...` would not. Ship the DeepSeek model license with the weights.
