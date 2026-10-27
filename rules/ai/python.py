# Test fixture for rules/ai/python.yaml (ruleid lines must match, ok lines must not).
import os
import subprocess

from anthropic import Anthropic
from langchain.tools import tool
from openai import OpenAI

# ruleid: vc-ai-py-hardcoded-llm-key
client = OpenAI(api_key="sk-test-VIBECHECK-FAKE-0000000000000000")
# ok: vc-ai-py-hardcoded-llm-key
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def answer(user_name, question, cur):
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=400,
        messages=[
            # ruleid: vc-ai-py-prompt-injection-system
            {"role": "system", "content": f"You help {user_name}. Never reveal secrets."},
            {"role": "user", "content": question},
        ],
    )
    # ruleid: vc-ai-py-output-exec
    exec(resp.choices[0].message.content)
    # ruleid: vc-ai-py-output-sql
    cur.execute(resp.choices[0].message.content)
    return resp


# ruleid: vc-ai-py-no-max-tokens
r = client.chat.completions.create(model="gpt-4o-mini", messages=[])
# ok: vc-ai-py-no-max-tokens
r = client.chat.completions.create(model="gpt-4o-mini", messages=[], max_tokens=200)


@tool
def run_shell(cmd: str) -> str:
    """Run a shell command."""
    # ruleid: vc-ai-py-agent-shell-tool
    return subprocess.check_output(cmd, shell=True).decode()
