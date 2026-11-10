"""The twin: a private, disposable copy of your application - without Docker.

The idea of running the target in a throwaway environment is not new, but the
usual answer is a container. That is heavy, it needs a daemon, and it does not
work on every machine. This module does the same job with what every machine
has: a process, a temporary directory and a copy of the data.

    with Twin(TwinSpec(command=["python", "-m", "mizan.demo.server"],
                       data_paths=[Path("demo.sqlite")])) as twin:
        base_url = twin.base_url
        twin.snapshot()      # take the pristine state
        ...                  # attack, mutate, explore
        twin.restore()       # back to the pristine state

What it gives the engine:

* every probe starts from the same state, so findings do not depend on the
  order in which the probes ran;
* probes can run in parallel;
* a fix can be applied and verified in the same environment.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def free_port(host: str = "127.0.0.1") -> int:
    """A port nobody is using right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


@dataclass
class TwinSpec:
    """How to start the application under test."""

    command: list[str]
    workdir: Path = field(default_factory=Path.cwd)
    env: dict[str, str] = field(default_factory=dict)
    host: str = "127.0.0.1"
    port: int = 0
    #: Files or directories that hold the state and must be snapshotted.
    data_paths: list[Path] = field(default_factory=list)
    #: The path that answers when the application is ready.
    health_path: str = "/"
    health_timeout: float = 30.0
    #: The environment variable that receives the chosen port.
    port_env: str = "PORT"
    #: Extra placeholders replaced in the command: ``{port}``, ``{workspace}``.
    replace_in_command: bool = True


class Twin:
    """A running copy of the application, with a restorable state."""

    def __init__(self, spec: TwinSpec, *, workspace: str | Path | None = None) -> None:
        self.spec = spec
        self.workspace = Path(workspace) if workspace else Path(spec.workdir) / ".mizan-twin"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.snapshot_dir = self.workspace / "snapshots"
        self.process: subprocess.Popen[bytes] | None = None
        self._port: int = spec.port
        self._snapshot_index = 0
        self._log = (self.workspace / "twin.log").open("ab")

    # -- lifecycle ---------------------------------------------------------- #

    @property
    def base_url(self) -> str:
        return f"http://{self.spec.host}:{self._port}"

    def start(self) -> str:
        """Start the application and wait until it answers."""
        self._port = self.spec.port or free_port(self.spec.host)
        env = dict(os.environ)
        env.update({key: str(value) for key, value in self.spec.env.items()})
        env[self.spec.port_env] = str(self._port)
        env["MIZAN_PORT"] = str(self._port)
        env["MIZAN_WORKSPACE"] = str(self.workspace)

        command = list(self.spec.command)
        if self.spec.replace_in_command:
            command = [
                part.replace("{port}", str(self._port)).replace("{workspace}", str(self.workspace))
                for part in command
            ]
        self.process = subprocess.Popen(
            command,
            cwd=str(self.spec.workdir),
            env=env,
            stdout=self._log,
            stderr=subprocess.STDOUT,
            **(_process_group_kwargs()),
        )
        self._wait_until_ready()
        return self.base_url

    def _wait_until_ready(self) -> None:
        import urllib.error
        import urllib.request

        deadline = time.time() + self.spec.health_timeout
        url = self.base_url + self.spec.health_path
        last_error: Exception | None = None
        while time.time() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise RuntimeError(
                    f"the application exited with code {self.process.returncode}; see {self._log.name}"
                )
            try:
                request = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(request, timeout=2) as response:
                    if response.status < 500:
                        return
            except urllib.error.HTTPError as exc:
                if exc.code < 500:
                    return
                last_error = exc
            except Exception as exc:  # connection refused while starting up
                last_error = exc
            time.sleep(0.15)
        raise TimeoutError(f"the application did not answer on {url} within {self.spec.health_timeout}s: {last_error}")

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                        check=False,
                        capture_output=True,
                    )
                else:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except Exception:
                self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except Exception:
                self.process.kill()
        self.process = None
        try:
            self._log.close()
        except Exception:
            pass

    def __enter__(self) -> Twin:
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()

    # -- state -------------------------------------------------------------- #

    def snapshot(self) -> Path:
        """Take a copy of the state."""
        self._snapshot_index += 1
        target = self.snapshot_dir / f"snapshot-{self._snapshot_index:03d}"
        target.mkdir(parents=True, exist_ok=True)
        for index, path in enumerate(self.spec.data_paths):
            source = Path(path)
            if not source.exists():
                continue
            destination = target / f"{index}-{source.name}"
            if source.is_dir():
                shutil.copytree(source, destination, dirs_exist_ok=True)
            else:
                shutil.copy2(source, destination)
        return target

    def restore(self) -> None:
        """Bring the state back to the last snapshot."""
        snapshots = sorted(self.snapshot_dir.glob("snapshot-*"))
        if not snapshots:
            return
        latest = snapshots[-1]
        for index, path in enumerate(self.spec.data_paths):
            source = Path(path)
            candidate = latest / f"{index}-{source.name}"
            if not candidate.exists():
                continue
            if source.is_dir():
                shutil.rmtree(source, ignore_errors=True)
                shutil.copytree(candidate, source)
            else:
                source.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidate, source)

    def reset(self) -> None:
        """Snapshot the current state and restore it - a clean slate."""
        self.snapshot()
        self.restore()


def _process_group_kwargs() -> dict[str, Any]:
    """Start the child in its own process group, so it can be killed entirely."""
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return {"creationflags": creationflags}
    return {"start_new_session": True}


def python_command(module: str, *arguments: str) -> list[str]:
    """A command that runs a module with the current interpreter."""
    return [sys.executable, "-m", module, *arguments]
