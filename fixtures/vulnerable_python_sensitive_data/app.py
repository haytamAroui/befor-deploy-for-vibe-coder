import logging
logger = logging.getLogger(__name__)

def record(user):
    logger.info("user=%s", user.password)
    logging.warning(user.access_token)
