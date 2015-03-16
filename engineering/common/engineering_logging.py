import logging
from common import config

logging.basicConfig(filename=config.CONF.log_file, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', )


def log_for_func_of_class(logger_name):
    def _log_wrapper(func):
        def __log_wrapper(class_self):
            logger = logging.getLogger(logger_name)
            logger.info('Start to execute %s', getattr(func, '__name__'))
            result = func(class_self)
            logger.info('End to execute %s, result is: %s', getattr(func, '__name__'), result)

        return __log_wrapper
    return _log_wrapper
