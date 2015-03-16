import sys
import logging

from common import config,engineering_logging
from engineering_factory import EnginneringFactory
from engineering_factory import HostnameConfigurator

logger = logging.getLogger(__name__)

def main():
    logger.info('Start to config All-in-one ')
    operation = config.CONF.sysconfig.operation
    print 'Current operation is: %s' % operation
    if operation == 'cfg-hostname':
        EnginneringFactory(operation, configurator=HostnameConfigurator()).execute()
    elif operation == 'cfg-all-in-one':
        pass


    logger.info('End to config All-in-one')

if __name__ == '__main__':
    main()
