import random
import shutil
import string
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def fake_openai_key(seed: int = 7) -> str:
    # Shaped like a legacy OpenAI key so TruffleHog's detector fires; random so it isn't
    # filtered as a placeholder. Generated at test time so no key-shaped string is committed.
    r = random.Random(seed)
    a = string.ascii_letters + string.digits
    g = lambda n: "".join(r.choice(a) for _ in range(n))  # noqa: E731
    return "sk-" + g(20) + "T3BlbkFJ" + g(20)


@pytest.fixture
def demo_app(tmp_path: Path) -> Path:
    dest = tmp_path / "demo-app"
    shutil.copytree(FIXTURES / "demo-app", dest)
    ai = dest / "src" / "lib" / "ai.ts"
    ai.write_text(ai.read_text().replace("__FAKE_OPENAI_KEY__", fake_openai_key()))
    return dest
