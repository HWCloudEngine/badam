__author__ = 'nash.xiejun'

from oslo.config import cfg
from common import config


class AllInOneConfig(object):

    def __init__(self):
        pass

    def change_host_name(self):
        pass

class InitConfiguration(object):

    def __init__(self):
        print (config.CONF.sysconfig.hostname)
        print(config.CONF.file_hosts)

initConfig = InitConfiguration()


