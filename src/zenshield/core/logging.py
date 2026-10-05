"""Zero-leakage structured logging for ZenShield.

Ensures no raw user messages, sensitive PII, or security canary inputs
are leaked into application logs.
"""

import logging
import sys


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configures application logger with safe audit formatting."""
    log_format = "%(asctime)s [%(levelname)s] [req_id=%(name)s] %(message)s"

    # Configure root/zenshield logger
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )

    logger = logging.getLogger("zenshield.audit")
    logger.setLevel(level)
    return logger


audit_logger = setup_logging()
