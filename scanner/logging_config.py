import logging

def configure_logging(verbosity: int = 0) -> None:
    """
    Configure root logger.
    verbosity:
      0 = WARNING and above
      1 = INFO and above
      2 = DEBUG and above
    """
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
