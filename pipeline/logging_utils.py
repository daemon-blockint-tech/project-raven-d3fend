"""
Structured Logging Utilities — Common Log Ingestion Best Practices

Implements CySA+ aligned logging with:
- Standard severity levels (FATAL, ERROR, WARN, INFO, DEBUG, TRACE)
- Structured JSON output for SIEM ingestion
- UTC timestamps with timezone for legal admissibility
- Pipeline context (stage, finding ID, run ID) for event correlation
- Time synchronization awareness

Usage:
    from pipeline.logging_utils import PipelineLogger, LogLevel
    logger = PipelineLogger.get_logger("scan")
    logger.info("Found candidate finding", finding_id="F-001", location="src/main.c")
"""
import logging
import json
import sys
import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from enum import Enum


class LogLevel(Enum):
    """Standard logging levels aligned with Common Log Ingestion Concepts."""
    FATAL = 50   # Crash! System cannot continue
    ERROR = 40   # Something unexpected happened, prevented function/action
    WARN = 30    # Something unexpected, but system continued
    INFO = 20    # Standard log data: who/what/when/success
    DEBUG = 10   # Fine-grained data for troubleshooting
    TRACE = 5    # Most finely granulated data for difficult errors


class StructuredFormatter(logging.Formatter):
    """
    JSON formatter for SIEM ingestion.

    Produces structured logs with:
    - timestamp (UTC with timezone offset for legal admissibility)
    - level (standard severity)
    - logger (component name)
    - message
    - context (pipeline stage, finding ID, run ID)
    - source (file:line for traceability)
    """

    def __init__(self, include_context: bool = True):
        super().__init__()
        self.include_context = include_context
        self.hostname = os.uname().nodename if hasattr(os, "uname") else "unknown"

    def format(self, record: logging.LogRecord) -> str:
        # UTC timestamp with timezone — legally admissible
        timestamp = datetime.fromtimestamp(record.created, tz=timezone.utc)
        ts_iso = timestamp.isoformat()  # e.g., 2024-01-15T14:30:00+00:00

        log_entry = {
            "timestamp": ts_iso,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "source": f"{record.filename}:{record.lineno}",
            "function": record.funcName,
            "host": self.hostname,
        }

        # Add structured context if available
        if hasattr(record, "pipeline_stage"):
            log_entry["pipeline_stage"] = record.pipeline_stage
        if hasattr(record, "finding_id"):
            log_entry["finding_id"] = record.finding_id
        if hasattr(record, "run_id"):
            log_entry["run_id"] = record.run_id
        if hasattr(record, "bug_class"):
            log_entry["bug_class"] = record.bug_class

        # Add extra fields from record
        for key in ["elapsed_ms", "stage", "budget_remaining", "model", "cost"]:
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable console formatter with colors."""

    COLORS = {
        "FATAL": "\033[91m",    # Bright red
        "ERROR": "\033[31m",    # Red
        "WARN": "\033[33m",     # Yellow
        "INFO": "\033[32m",     # Green
        "DEBUG": "\033[36m",    # Cyan
        "TRACE": "\033[35m",    # Magenta
        "RESET": "\033[0m",
    }

    def __init__(self, use_colors: bool = True):
        super().__init__(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        if self.use_colors:
            color = self.COLORS.get(record.levelname, "")
            reset = self.COLORS["RESET"] if color else ""
            return f"{color}{formatted}{reset}"
        return formatted


class PipelineLogger:
    """
    Centralized logger for Raven pipeline components.

    Provides structured logging with pipeline context for:
    - Event correlation across stages
    - SIEM ingestion
    - Audit trails (CDP contract compliance)
    - Performance monitoring
    """

    _initialized = False
    _root_level = logging.INFO

    @classmethod
    def initialize(
        cls,
        log_level: str = "INFO",
        json_output: bool = False,
        log_file: Optional[str] = None,
    ):
        """
        Initialize pipeline logging.

        Args:
            log_level: Minimum log level (FATAL, ERROR, WARN, INFO, DEBUG, TRACE)
            json_output: Output structured JSON for SIEM ingestion
            log_file: Optional file path for persistent logging
        """
        # Map string to numeric level
        level_map = {
            "FATAL": LogLevel.FATAL.value,
            "ERROR": LogLevel.ERROR.value,
            "WARN": LogLevel.WARN.value,
            "INFO": LogLevel.INFO.value,
            "DEBUG": LogLevel.DEBUG.value,
            "TRACE": LogLevel.TRACE.value,
        }
        numeric_level = level_map.get(log_level.upper(), logging.INFO)
        cls._root_level = numeric_level

        # Add TRACE level to logging
        logging.addLevelName(LogLevel.TRACE.value, "TRACE")

        root = logging.getLogger()
        root.setLevel(numeric_level)

        # Clear existing handlers
        for handler in root.handlers[:]:
            root.removeHandler(handler)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)

        if json_output:
            console_handler.setFormatter(StructuredFormatter())
        else:
            console_handler.setFormatter(ConsoleFormatter())

        root.addHandler(console_handler)

        # File handler (if requested)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(StructuredFormatter())
            root.addHandler(file_handler)

        cls._initialized = True
        logging.getLogger(__name__).info(
            f"PipelineLogger initialized: level={log_level}, json={json_output}"
        )

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """Get a logger with pipeline context support."""
        if not cls._initialized:
            cls.initialize()
        return logging.getLogger(name)

    @staticmethod
    def log_stage_start(stage: str, item_count: int, run_id: Optional[str] = None):
        """Log pipeline stage start with context."""
        logger = logging.getLogger("pipeline")
        extra = {
            "pipeline_stage": stage,
            "run_id": run_id or "unknown",
            "item_count": item_count,
        }
        logger.info(f"=== Stage: {stage} ({item_count} items) ===", extra=extra)

    @staticmethod
    def log_stage_end(stage: str, result_count: int, elapsed_ms: float, run_id: Optional[str] = None):
        """Log pipeline stage completion with timing."""
        logger = logging.getLogger("pipeline")
        extra = {
            "pipeline_stage": stage,
            "run_id": run_id or "unknown",
            "result_count": result_count,
            "elapsed_ms": round(elapsed_ms, 2),
        }
        logger.info(
            f"=== Stage {stage} complete: {result_count} results in {elapsed_ms:.1f}ms ===",
            extra=extra,
        )

    @staticmethod
    def log_finding(
        finding_id: str,
        bug_class: str,
        severity: str,
        location: str,
        stage: str = "scan",
        run_id: Optional[str] = None,
    ):
        """Log a security finding with full context for event correlation."""
        logger = logging.getLogger("pipeline.findings")
        extra = {
            "pipeline_stage": stage,
            "finding_id": finding_id,
            "run_id": run_id or "unknown",
            "bug_class": bug_class,
            "severity": severity,
        }
        level = LogLevel.ERROR.value if severity in ("critical", "high") else LogLevel.WARN.value
        logger.log(level, f"Finding {finding_id}: {bug_class} at {location}", extra=extra)

    @staticmethod
    def log_budget_warning(stage: str, budget_used: float, budget_total: float):
        """Log budget threshold warning."""
        logger = logging.getLogger("pipeline.budget")
        pct = (budget_used / budget_total * 100) if budget_total > 0 else 0
        extra = {
            "pipeline_stage": stage,
            "budget_used": budget_used,
            "budget_total": budget_total,
            "budget_pct": round(pct, 1),
        }
        logger.warning(
            f"Budget alert: {pct:.1f}% used (${budget_used:.2f}/${budget_total:.2f})",
            extra=extra,
        )

    @staticmethod
    def log_cdp_violation(
        finding_id: str,
        reason: str,
        stage: str = "validate",
        run_id: Optional[str] = None,
    ):
        """Log a CDP contract violation — highest severity."""
        logger = logging.getLogger("pipeline.cdp")
        extra = {
            "pipeline_stage": stage,
            "finding_id": finding_id,
            "run_id": run_id or "unknown",
            "cdp_status": "violation",
        }
        logger.critical(
            f"CDP VIOLATION for {finding_id}: {reason}",
            extra=extra,
        )

    @staticmethod
    def log_debate_vote(
        finding_id: str,
        debater: str,
        vote: str,
        confidence: float,
        run_id: Optional[str] = None,
    ):
        """Log a debate vote for audit trail."""
        logger = logging.getLogger("pipeline.debate")
        extra = {
            "pipeline_stage": "validate",
            "finding_id": finding_id,
            "run_id": run_id or "unknown",
            "debater": debater,
            "vote": vote,
            "confidence": round(confidence, 3),
        }
        logger.info(
            f"Debate vote: {debater} -> {vote} (conf={confidence:.3f})",
            extra=extra,
        )


def get_logger(name: str) -> logging.Logger:
    """Convenience function to get a pipeline logger."""
    return PipelineLogger.get_logger(name)
