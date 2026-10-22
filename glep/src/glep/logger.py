"""Logging a archivo. GLEP no imprime nada tipo "chat" a stdout — es un
agente silencioso. Todo lo observable queda en el log file; con
`--verbose` además se copia a stderr para debug en vivo."""

import logging
import sys
from pathlib import Path


def get_logger(
    name: str,
    log_file: str | None,
    level: str = "INFO",
    console: bool = False,
) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    # Evita handlers duplicados si main() se llama más de una vez.
    if getattr(logger, "_glep_configured", False):
        return logger

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    if console or not log_file:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    logger._glep_configured = True
    return logger
