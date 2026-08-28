import logging
logger = logging.getLogger(__name__)

def record(user):
    logger.info("user login completed")
    logger.debug("user id=%s", user.id)
