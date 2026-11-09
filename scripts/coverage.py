"""Build a MITRE ATT&CK Navigator layer and a markdown coverage table from rule tags."""
import json
import pathlib
import re

import yaml

rules = [yaml.safe_load(p.read_text()) for p in sorted(pathlib.Path("rules").rglob("*.yml"))]
techniques = {}
for r in rules:
    for tag in r.get("tags", []):
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag)
        if m:
            techniques.setdefault(m.group(1).upper(), []).append(r["title"])

layer = {
    "name": "AWS detection coverage",
    "domain": "enterprise-attack",
    "versions": {"layer": "4.5", "navigator": "5.1.0"},
    "techniques": [
        {"techniqueID": t, "score": len(v), "comment": "; ".join(v)} for t, v in sorted(techniques.items())
    ],
    "gradient": {"colors": ["#d6e6ff", "#1f5fbf"], "minValue": 0, "maxValue": 2},
}
pathlib.Path("build").mkdir(exist_ok=True)
pathlib.Path("build/attack-layer.json").write_text(json.dumps(layer, indent=2))
lines = ["| Technique | Rules |", "| --- | --- |"] + [f"| {t} | {', '.join(v)} |" for t, v in sorted(techniques.items())]
pathlib.Path("build/coverage.md").write_text("\n".join(lines) + "\n")
print(f"{len(rules)} rules cover {len(techniques)} ATT&CK techniques")
