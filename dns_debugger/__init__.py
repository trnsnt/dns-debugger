"""dns_tools module"""
import logging

logging.basicConfig(level=logging.DEBUG)
LOGGER_FORMATTER = logging.Formatter('[%(levelname)-8s] %(message)s')
LOGGER_HANDLER = logging.FileHandler(filename='logs.txt', mode='w')
LOGGER_HANDLER.setFormatter(LOGGER_FORMATTER)

LOGGER = logging.getLogger()
LOGGER.handlers = []
LOGGER.addHandler(LOGGER_HANDLER)
