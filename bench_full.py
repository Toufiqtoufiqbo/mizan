from mizan.benchmark import build_suite, run_suite

report = run_suite(build_suite(50, controls=5))
report.write("authzbugs-report")
print(report.to_markdown()[:700])
