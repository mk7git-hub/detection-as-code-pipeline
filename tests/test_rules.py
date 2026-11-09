import json
import pathlib
import sys
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from sigma_eval import load, matches  # noqa: E402

RULES = sorted(pathlib.Path("rules").rglob("*.yml"))
REQUIRED = ["title", "id", "status", "description", "logsource", "detection", "level", "tags"]


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.stem)
def test_rule_metadata(path):
    rule = load(path)
    for key in REQUIRED:
        assert key in rule, f"{path.stem} missing {key}"
    uuid.UUID(rule["id"])
    assert any(t.startswith("attack.t") for t in rule["tags"]), "every rule maps to an ATT&CK technique"
    assert rule["level"] in {"informational", "low", "medium", "high", "critical"}


def test_ids_unique():
    ids = [load(p)["id"] for p in RULES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.stem)
def test_rule_against_samples(path):
    sample = pathlib.Path("tests/samples") / f"{path.stem}.json"
    assert sample.exists(), f"add true and false positive samples for {path.stem}"
    data = json.loads(sample.read_text())
    rule = load(path)
    for event in data["should_match"]:
        assert matches(rule, event), f"{path.stem} missed a true positive"
    for event in data["should_not_match"]:
        assert not matches(rule, event), f"{path.stem} fired on a benign event"
