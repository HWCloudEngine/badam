import sys
import logging

from common import config,engineering_logging
from engineering_factory import EnginneringFactory, HostnameConfigurator, AllInOneConfigurator

logger = logging.getLogger(__name__)

def main():
    logger.info('Start to config All-in-one ')
    operation = config.CONF.sysconfig.operation
    print 'Current operation is: %s' % operation
    if operation == 'cfg-hostname':
        EnginneringFactory(operation, configurator=HostnameConfigurator()).execute()
    elif operation == 'cfg-all-in-one':
        EnginneringFactory(operation, configurator=AllInOneConfigurator()).execute()
    else:
        err_info = 'Invalid operation-<%s>, please check your config file.' % operation
        print (err_info)
        logger.error(err_info)


    logger.info('End to config All-in-one')

if __name__ == '__main__':
    main()
