from pathlib import Path

p = Path("tests/test_parallel.py")
t = p.read_text(encoding="utf-8")
t = t.replace(
    """    from mizan.demo.app import DemoApp

    DemoApp(source)
""",
    """    from mizan.demo.app import DemoApp

    source = workspace / "seed.sqlite"
    DemoApp(source)
""",
)
p.write_text(t, encoding="utf-8")
print("patched test_parallel")
