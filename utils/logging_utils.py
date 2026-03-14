"""
Structured JSON logging for the AppSec multi-agent framework.

All pipeline events are written as JSON lines to a configurable log file
AND to the standard Python logging system so existing log handlers still
receive events.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = ["StructuredLogger"]


class StructuredLogger:
    """
    Emit structured JSON log entries alongside human-readable console output.

    Parameters
    ----------
    name:
        Logger name (appears in the ``logger`` JSON field).
    log_file:
        Optional path to a JSON-lines log file.  Parent directory is created
        automatically if it does not exist.
    level:
        Logging level string (``"DEBUG"``, ``"INFO"``, etc.).
    """

    def __init__(
        self,
        name: str = "appsec",
        log_file: Optional[str] = None,
        level: str = "INFO",
    ) -> None:
        self._name = name
        self._log_file = log_file
        self._level = getattr(logging, level.upper(), logging.INFO)

        # Underlying stdlib logger
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
            )
            self._logger.addHandler(handler)
        self._logger.setLevel(self._level)

        # JSON file handle
        self._fh: Optional[Any] = None
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(log_file, "a", encoding="utf-8")  # noqa: WPS515

    # ------------------------------------------------------------------
    # Levelled helpers
    # ------------------------------------------------------------------

    def debug(self, msg: str, **extra: Any) -> None:
        self._emit("DEBUG", msg, extra)

    def info(self, msg: str, **extra: Any) -> None:
        self._emit("INFO", msg, extra)

    def warning(self, msg: str, **extra: Any) -> None:
        self._emit("WARNING", msg, extra)

    def error(self, msg: str, **extra: Any) -> None:
        self._emit("ERROR", msg, extra)

    def phase_start(self, phase: str, target: str, **extra: Any) -> None:
        self._emit("INFO", f"Phase started: {phase}", {"phase": phase, "target": target, **extra})

    def phase_done(self, phase: str, target: str, **extra: Any) -> None:
        self._emit("INFO", f"Phase done: {phase}", {"phase": phase, "target": target, **extra})

    def phase_failed(self, phase: str, target: str, error: str, **extra: Any) -> None:
        self._emit(
            "ERROR",
            f"Phase failed: {phase}",
            {"phase": phase, "target": target, "error": error, **extra},
        )

    def finding(self, finding: dict[str, Any]) -> None:
        self._emit("INFO", f"Finding: {finding.get('name', '?')} [{finding.get('severity', '?')}]", {"finding": finding})

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit(self, level: str, msg: str, extra: dict[str, Any]) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "logger": self._name,
            "msg": msg,
            **extra,
        }

        # stdlib log
        log_level = getattr(logging, level, logging.INFO)
        self._logger.log(log_level, msg, stacklevel=3)

        # JSON file
        if self._fh:
            try:
                self._fh.write(json.dumps(record, default=str) + "\n")
                self._fh.flush()
            except OSError:
                pass

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def __del__(self) -> None:
        self.close()
