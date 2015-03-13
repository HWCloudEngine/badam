__author__ = 'nash.xiejun'

from common import config

class EnginneringFactory(object):

    def __init__(self, validator=None, installer=None, configurator=None, checker=None):
        self.validator = validator
        self.installer = installer
        self.configurator = configurator
        self.checker = checker

    def instance(self):
        return self

    def execute(self):

        if self.validator is not None:
            validate_result = self.validator.validate()

        if self.installer is not None:
            install_result = self.installer.install()

        if self.configurator is not None:
            config_result = self.configurator.config()

        if self.checker is not None:
            check_result = self.checker.check()

class ConfiguratorBase(object):
    def config(self):
        pass

class InstallerBase(object):
    def install(self):
        pass

class HostnameConfigurator(ConfiguratorBase):

    def config(self):
        self._config_etc_hostname()
        self._config_etc_hosts()

    def _config_etc_hostname(self):
        with open(config.CONF.file_hostname, 'w') as hostname_file:
            hostname_file.truncate()
            hostname_file.write(config.CONF.sysconfig.hostname)

    def _config_etc_hosts(self):
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

class HostnameInstaller(InstallerBase):
    def install(self):
        pass




