import pathlib
from collections import OrderedDict

groups = OrderedDict(
    [
        (
            "engine",
            [
                "src/mizan/engine.py",
                "src/mizan/core.py",
                "src/mizan/search.py",
                "src/mizan/parallel.py",
                "src/mizan/twin.py",
            ],
        ),
        (
            "detectors",
            [
                "src/mizan/taint.py",
                "src/mizan/races.py",
                "src/mizan/identity.py",
                "src/mizan/attribution.py",
                "src/mizan/postgres_audit.py",
            ],
        ),
        ("evidence", ["src/mizan/proof.py", "src/mizan/patching.py", "src/mizan/regression.py", "src/mizan/matrix.py"]),
        (
            "onboarding",
            [
                "src/mizan/proxy.py",
                "src/mizan/recorder.py",
                "src/mizan/learning.py",
                "src/mizan/traffic.py",
                "src/mizan/tokens.py",
            ],
        ),
        (
            "cli+integration",
            [
                "src/mizan/cli.py",
                "src/mizan/schemathesis_plugin.py",
                "src/mizan/schemathesis_hooks.py",
                "src/mizan/pytest_plugin.py",
            ],
        ),
        (
            "benchmark",
            [
                "src/mizan/benchmark/apps.py",
                "src/mizan/benchmark/evaluate.py",
                "src/mizan/benchmark/generator.py",
                "src/mizan/benchmark/__init__.py",
            ],
        ),
        (
            "demo",
            [
                "src/mizan/demo/app.py",
                "src/mizan/demo/server.py",
                "src/mizan/demo/__init__.py",
                "src/mizan/demo/openapi.json",
            ],
        ),
    ]
)
total = 0
for name, files in groups.items():
    n = 0
    for f in files:
        p = pathlib.Path(f)
        if p.exists():
            n += len(p.read_text(encoding="utf-8").splitlines())
    total += n
    print(f"{name:18s} {n:5d} lines  ({len(files)} files)")
tests = sum(len(p.read_text(encoding="utf-8").splitlines()) for p in pathlib.Path("tests").rglob("*.py"))
print(f"{'tests':18s} {tests:5d} lines")
print(f"{'TOTAL src':18s} {total:5d} lines")
