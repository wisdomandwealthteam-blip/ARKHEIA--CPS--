"""
cps_backend.utils.logging_setup
=================================
Structured, deterministic logging configuration. No log line ever affects
control flow — logging is purely observational.
"""
from __future__ import annotations

import logging
import sys

from cps_backend.config import settings


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("cps_backend")
    if logger.handlers:
        return logger  # already configured (avoids duplicate handlers on reload)

    logger.setLevel(settings.log_level)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = configure_logging()
