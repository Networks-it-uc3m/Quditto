import logging
from rich.logging import RichHandler

def setup_logging(verbosity: int = 0):
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        handlers=[RichHandler(rich_tracebacks=True)],
        format="%(message)s",
    )
