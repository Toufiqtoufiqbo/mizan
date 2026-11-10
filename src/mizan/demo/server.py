"""Run the demo application as a standalone process.

The twin launches it like it would launch a real project::

    python -m mizan.demo.server --db demo.sqlite --port 8000
"""

from __future__ import annotations

import argparse
from pathlib import Path

from mizan.demo.app import DemoApp, serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Mizan demo application")
    parser.add_argument("--db", default="demo.sqlite")
    parser.add_argument("--traffic", default=None, help="Traffic log to write")
    parser.add_argument("--ledger", default=None, help="Write ledger to write")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    arguments = parser.parse_args()

    app = DemoApp(
        Path(arguments.db),
        ledger_path=arguments.ledger,
        traffic_path=arguments.traffic,
    )
    server, port, _thread = serve(app, host=arguments.host, port=arguments.port)
    print(f"demo API listening on http://{arguments.host}:{port}", flush=True)
    try:
        while True:
            import time

            time.sleep(0.5)
    except KeyboardInterrupt:  # pragma: no cover
        server.shutdown()


if __name__ == "__main__":  # pragma: no cover
    main()
