import sys
import logging

from common import config,engineering_logging
from engineering_factory import EnginneringFactory, HostnameConfigurator, AllInOneConfigurator
from installation import CascadingDeploy

logger = logging.getLogger(__name__)

def main():
    """
    How to use:
    Step1. Copy hybrid_cloud_badam and tricircle-master to <Your-Dir>
    Step2. Config <Your-Dir>/hybrid_cloud_badam/engineering/config/configuration.conf
    Step3. Install by execute following commands.
        # cd <Your-Dir>/hybrid_cloud_badam/engineering
        #python install_exe.py --config-file config/configuration.conf
    :return:
    """
    logger.info('Start to config All-in-one ')
    operation = config.CONF.sysconfig.operation
    print 'Current operation is: %s' % operation
    if operation == 'cfg-hostname':
        EnginneringFactory(operation, configurator=HostnameConfigurator()).execute()
    elif operation == 'cfg-all-in-one':
        EnginneringFactory(operation, configurator=AllInOneConfigurator()).execute()
    elif operation == 'deploy-cascade-openstack':
        CascadingDeploy().deploy_cascading_modules()
    else:
        err_info = 'Invalid operation-<%s>, please check your config file.' % operation
        print (err_info)
        logger.error(err_info)


    logger.info('End to config All-in-one')

if __name__ == '__main__':
    main()
