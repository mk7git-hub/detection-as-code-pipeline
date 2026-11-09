"""Convert every Sigma rule to Splunk SPL with pySigma. Fails CI on any rule that cannot convert."""
import pathlib
import sys

from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend

out = pathlib.Path("build/splunk")
out.mkdir(parents=True, exist_ok=True)
backend = SplunkBackend()
failed = 0
for path in sorted(pathlib.Path("rules").rglob("*.yml")):
    try:
        queries = backend.convert(SigmaCollection.from_yaml(path.read_text()))
        (out / f"{path.stem}.spl").write_text("\n".join(queries) + "\n")
        print(f"ok   {path.stem}: {queries[0][:90]}")
    except Exception as exc:  # report every failure, then exit non-zero
        failed += 1
        print(f"FAIL {path.stem}: {exc}")
sys.exit(1 if failed else 0)
