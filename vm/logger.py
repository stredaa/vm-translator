"""Generic logging provider
"""

from logging import getLogger, INFO, Formatter, FileHandler


def get_asm_logger(filename):
    """Get file LOG. The log is saved to ./data/necurs.log

    Args:
        tag (str): log entry tag
    """
    logger = getLogger("disassembly")
    logger.setLevel(INFO)
    log_handler = FileHandler("filename")
    log_handler.setFormatter(Formatter('%(message)s'))
    logger.addHandler(log_handler)
    return logger
