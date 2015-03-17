__author__ = 'nash.xiejun'

import logging
import sys

from common import config, engineering_logging
from common.engineering_logging import log_for_func_of_class
from utils import AllInOneUsedCMD
from common.config import ConfigCommon
from oslo.config import cfg

logger_name = __name__
logger = logging.getLogger(__name__)

CONF = cfg.CONF



class ValidateBase(object):
    @log_for_func_of_class(logger_name)
    def validate(self):
        return True

class ConfiguratorBase(object):
    @log_for_func_of_class(logger_name)
    def config(self):
        return True

class InstallerBase(object):
    @log_for_func_of_class(logger_name)
    def install(self):
        return True

class CheckBase(object):
    @log_for_func_of_class(logger_name)
    def check(self):
        return True

class EnginneringFactory(object):

    def __init__(self, factory_name, validator=ValidateBase(), installer=InstallerBase(), configurator=ConfiguratorBase(), checker=CheckBase()):
        self.factory_name = factory_name
        self.validator = validator
        self.installer = installer
        self.configurator = configurator
        self.checker = checker

    def instance(self):
        return self

    def execute(self):
        logger.info('Start to execute for %s' % self.factory_name)

        execute_result = True

        validate_result = self.validator.validate()

        install_result = self.installer.install()

        config_result = self.configurator.config()

        check_result = self.checker.check()

        logger.info('End to execute for %s, result is %s' , self.factory_name, execute_result)


class HostnameConfigurator(ConfiguratorBase):

    def config(self):
        try:
            self._config_etc_hostname()
            self._config_etc_hosts()
            AllInOneUsedCMD.reboot()
        except:
            logger.error('Exception occur when config hostname. EXCEPTION: %s' % sys.exc_traceback)

    def _config_etc_hostname(self):
        logger.info('Start to config hostname file')
        with open(config.CONF.file_hostname, 'w') as hostname_file:
            hostname_file.truncate()
            hostname_file.write(config.CONF.sysconfig.hostname)
        logger.info('Success to config hostname file, /etc/hostname')

    def _config_etc_hosts(self):
        logger.info('Start to config hosts file')
        modified_contents = ''
        with open(config.CONF.file_hosts, 'r') as hosts_file:
            for line in hosts_file:
                if modified_contents == '':
                    modified_contents = line.replace('openstack', config.CONF.sysconfig.hostname)
                else:
                    modified_contents = ''.join([modified_contents, line.replace('openstack', config.CONF.sysconfig.hostname)])

        with open(config.CONF.file_hosts, 'w') as hosts_file:
            hosts_file.truncate()
            hosts_file.write(modified_contents)

        logger.info('Config hosts file success, /etc/hosts')

class AllInOneConfigurator(ConfiguratorBase):

    @log_for_func_of_class(logger_name)
    def config(self):
        try:
            AllInOneUsedCMD.rabbitmq_changed_pwd()
            self._config_rc_local()
            self._config_nova_conf()
        except:
            logger.error('Exception occur when change rabbitmq pwd, EXCEPTION: %s' % sys.exc_traceback)

    @log_for_func_of_class(logger_name)
    def _config_rc_local(self):
        try:
            contents = ['service nova-cert restart',
                        'service nova-scheduler restart',
                        'ifconfig br-ex:0 %s netmask 255.255.255.0' % config.CONF.sysconfig.local_host_ip,
                        'exit 0']

            with open(config.CONF.rc_local_file) as rc_local_file:
                rc_local_file.truncate()
                rc_local_file.writelines(contents)
        except:
            logger.error('Exception occur when config rc.local. EXCEPTION: %s' % sys.exc_traceback)

    def _config_nova_conf(self):
        vncserver_listen = '0.0.0.0'
        path_nova_conf_file = config.CONF.sysconfig.path_nova_conf

        config_common = ConfigCommon(path_nova_conf_file)
        config_common.set_option(config.CONF.section_default, 'vncserver_listen', '0.0.0.0')
        config_common.set_option(config.CONF.section_default, 'service_metadata_proxy', 'False')
        config_common.set_option(config.CONF.section_default, metadata_proxy_shared_secret , 'openstack')
        config_common.write_commit()

