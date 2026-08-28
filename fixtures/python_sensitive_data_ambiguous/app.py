import logging
logger = logging.getLogger(__name__)

def record(user):
    logger.info("password supplied")
    logger.info("token=%s", get_token())
