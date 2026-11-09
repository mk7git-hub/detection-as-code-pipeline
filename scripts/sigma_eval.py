"""Tiny Sigma evaluator for unit tests: matches a rule against JSON events.

Supports what the rules in this repo use: dotted field paths, value lists (OR),
the |exists, |contains, |startswith, |endswith and |fieldref modifiers, and
conditions built from selection names with and / or / not and parentheses.
Production conversion to SPL or KQL is done by pySigma (see convert.py).
"""
import re
import yaml


def get(event, path):
    cur = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _match_value(actual, expected, mods, event):
    if "exists" in mods:
        return (actual is not None) == bool(expected)
    if actual is None:
        return False
    if "fieldref" in mods:
        return str(actual) == str(get(event, expected))
    a, e = str(actual), str(expected)
    if "contains" in mods:
        return e.lower() in a.lower()
    if "startswith" in mods:
        return a.lower().startswith(e.lower())
    if "endswith" in mods:
        return a.lower().endswith(e.lower())
    return a.lower() == e.lower()


def match_selection(selection, event):
    for key, expected in selection.items():
        field, *mods = key.split("|")
        actual = get(event, field)
        values = expected if isinstance(expected, list) else [expected]
        if not any(_match_value(actual, v, mods, event) for v in values):
            return False
    return True


def matches(rule, event):
    det = rule["detection"]
    names = {k: match_selection(v, event) for k, v in det.items() if k != "condition"}
    cond = det["condition"]
    expr = re.sub(r"\b([A-Za-z_][A-Za-z0-9_]*)\b",
                  lambda m: m.group(1) if m.group(1) in ("and", "or", "not") else str(names[m.group(1)]),
                  cond)
    return bool(eval(expr, {"__builtins__": {}}, {}))  # expression contains only True/False/and/or/not


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)
