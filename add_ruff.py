from pathlib import Path

p = Path("pyproject.toml")
t = p.read_text(encoding="utf-8")
t = t.replace('dev = ["pytest>=8.0"]', 'dev = ["pytest>=8.0", "ruff>=0.6"]')
t += """

[tool.ruff]
target-version = "py311"
line-length = 120

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "W"]
"""
p.write_text(t, encoding="utf-8")
print("pyproject updated")
