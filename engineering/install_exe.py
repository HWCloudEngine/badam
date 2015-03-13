import sys

from common import config
from engineering_factory import EnginneringFactory
from engineering_factory import HostnameConfigurator

def main():
    operation = config.CONF.sysconfig.operation
    print operation
    if operation == 'cfg-hostname':
        EnginneringFactory(configurator=HostnameConfigurator()).execute()

if __name__ == '__main__':
    main()