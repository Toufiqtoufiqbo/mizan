"""Parallel probing, with real isolation.

The twin restores the state before every probe, which makes the findings
independent of the order the probes run in. But restoring is still serial: one
probe at a time, each of them paying for a restart of the state.

With one copy of the application per worker, the probes can run at the same
time, and each of them owns its data. That is what this module builds:

    pool = TwinPool(spec, workers=4, workspace=Path("twin"))
    pool.start()
    for worker in pool.workers:
        print(worker.base_url, worker.data_paths)

Every worker gets its own directory, its own copy of the data files and its
own port. The command is started in the worker directory, so relative paths in
the command resolve to that worker's copy.

.. note::

    The data files are copied by their base name, so the command must refer to
    them by that name inside ``{data}``::

        python -m myapp --db {data}/app.db --port {port}

    A command that points at an absolute path outside ``{data}`` would make
    every worker share one database, and the isolation would be a lie.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mizan.twin import Twin, TwinSpec


@dataclass
class PortReservation:
    """A port held open until the application takes it."""

    port: int
    _socket: Any = None

    def release(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None


def _reserve_port(host: str = "127.0.0.1") -> PortReservation:
    """Reserve a port by binding it and keeping it open."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # On Windows a second socket may bind a port that is already taken unless
    # the first one is exclusive. Without this, two workers can end up on the
    # same port.
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        except OSError:  # pragma: no cover - platform dependent
            pass
    sock.bind((host, 0))
    sock.listen(1)
    return PortReservation(port=int(sock.getsockname()[1]), _socket=sock)


@dataclass
class Worker:
    """One isolated copy of the application."""

    index: int
    directory: Path
    twin: Twin
    base_url: str
    data_paths: list[Path] = field(default_factory=list)


class TwinPool:
    """Several copies of the same application, each with its own state."""

    def __init__(
        self,
        spec: TwinSpec,
        workers: int = 2,
        *,
        workspace: str | Path = ".mizan-pool",
        data_paths: list[Path] | None = None,
    ) -> None:
        self.spec = spec
        self.workers_count = max(1, workers)
        self.workspace = Path(workspace)
        self.source_data = [Path(path) for path in (data_paths or spec.data_paths)]
        self.workers: list[Worker] = []

    # -- lifecycle ---------------------------------------------------------- #

    def start(self) -> list[Worker]:
        """Start every worker."""
        self.workspace.mkdir(parents=True, exist_ok=True)
        # The ports are reserved before any application starts, so two workers
        # can never end up on the same port.
        reservations = [_reserve_port(self.spec.host) for _ in range(self.workers_count)]
        try:
            for index in range(self.workers_count):
                directory = self.workspace / f"worker-{index}"
                directory.mkdir(parents=True, exist_ok=True)
                data_paths = self._copy_data(directory)
                spec = TwinSpec(
                    command=[
                        part.replace("{data}", str(directory)).replace("{workspace}", str(directory))
                        for part in self.spec.command
                    ],
                    workdir=directory,
                    env=self.spec.env,
                    host=self.spec.host,
                    port=reservations[index].port,
                    data_paths=data_paths,
                    health_path=self.spec.health_path,
                    health_timeout=self.spec.health_timeout,
                    port_env=self.spec.port_env,
                    data_dir=directory,
                )
                twin = Twin(spec, workspace=directory / ".mizan-twin")
                # The port is handed over to the application now.
                reservations[index].release()
                base_url = twin.start()
                self.workers.append(
                    Worker(index=index, directory=directory, twin=twin, base_url=base_url, data_paths=data_paths)
                )
        finally:
            for reservation in reservations:
                reservation.release()
        return self.workers

    def stop(self) -> None:
        for worker in self.workers:
            worker.twin.stop()
        self.workers = []

    def __enter__(self) -> TwinPool:
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()

    # -- data --------------------------------------------------------------- #

    def _copy_data(self, directory: Path) -> list[Path]:
        """Give this worker its own copy of the data files."""
        copied: list[Path] = []
        for path in self.source_data:
            if not path.exists():
                continue
            destination = directory / path.name
            if path.is_dir():
                shutil.copytree(path, destination, dirs_exist_ok=True)
            else:
                shutil.copy2(path, destination)
            copied.append(destination)
        return copied


def run_parallel(
    spec: TwinSpec,
    *,
    workers: int = 2,
    workspace: str | Path = ".mizan-pool",
    data_paths: list[Path] | None = None,
    build_engine: Callable[[str, list[Path], Any], Any],
    groups: list[str] | None = None,
) -> tuple[list[Any], list[str]]:
    """Run the probes of several engines at the same time.

    ``build_engine`` receives the base URL, the data paths and the twin of a
    worker, and returns an engine bound to it. Returns the findings and the
    groups that were executed.
    """
    pool = TwinPool(spec, workers, workspace=workspace, data_paths=data_paths)
    pool.start()
    findings: list[Any] = []
    executed: list[str] = []
    try:
        with ThreadPoolExecutor(max_workers=max(1, len(pool.workers))) as executor:
            futures = []
            for index, worker in enumerate(pool.workers):
                engine = build_engine(worker.base_url, worker.data_paths, worker.twin)
                # Every worker learns the laws for itself: the traffic is the
                # same, but the worker sees its own application.
                engine.learn()
                names = groups if groups is not None else engine.probe_names()
                assigned = [name for position, name in enumerate(names) if position % len(pool.workers) == index]
                executed.extend(assigned)
                futures.append(executor.submit(engine.attack_groups, assigned))
            for future in futures:
                findings.extend(future.result())
    finally:
        pool.stop()
    # The same breach can be reported by two workers - the probe and the data
    # view see it. Keep one.
    unique: dict[tuple[Any, ...], Any] = {}
    for finding in findings:
        key = (
            getattr(finding, "law", None),
            getattr(finding, "principal", None),
            getattr(finding, "resource", None),
        )
        unique.setdefault(key, finding)
    return list(unique.values()), executed
