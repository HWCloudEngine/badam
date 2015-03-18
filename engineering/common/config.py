__author__ = 'nash.xiejun'

import os
import sys
import ConfigParser

from oslo.config import cfg


CONF = cfg.CONF

#########################
# block used to init global opts
#########################
global_opts = [
    cfg.StrOpt('file_hosts',
               default='/etc/hosts'),
    cfg.StrOpt('file_hostname',
               default='/etc/hostname'),
    cfg.StrOpt('self_config_file', default=os.path.split(os.path.realpath(__file__))[0] + '/../config/configuration.conf'),
    cfg.StrOpt('log_file', default='/var/log/engineering.log'),
    cfg.StrOpt('rc_local_file', default='/etc/rc.local'),
    cfg.StrOpt('path_nova_conf', default='/etc/nova/nova.conf'),
    cfg.StrOpt('path_neutron_conf', default='/etc/neutron/neutron.conf'),
    cfg.StrOpt('path_cinder_conf', default='/etc/cinder/cinder.conf'),
    cfg.StrOpt('path_ml2_ini', default='/etc/neutron/plugins/ml2/ml2_conf.ini'),
    cfg.StrOpt('path_sysctl', default='/etc/sysctl.conf'),
    cfg.StrOpt('path_l3_agent', default='/etc/neutron/l3_agent.ini'),
    cfg.StrOpt('path_dhcp_agent_ini', default='/etc/neutron/dhcp_agent.ini'),
    cfg.StrOpt('path_metadata_agent_ini', default='/etc/neutron/metadata_agent.ini'),
    cfg.StrOpt('section_default', default='DEFAULT')
]
CONF.register_opts(global_opts)

#########################
# block used to init sysconfig section of config "config/configuration.conf"
#########################
sysconfig_group = cfg.OptGroup(name='sysconfig',
                               title='sys config for all in one')
sysconfig_opts = [
    cfg.StrOpt('hostname',
               default='hostname_default'),
    cfg.StrOpt('operation',
               default='operation_default'),
    cfg.StrOpt('local_host_ip',
               default='127.0.0.1'),
    cfg.StrOpt('ml2_local_ip', default='10.0.0.99')
]

CONF.register_group(sysconfig_group)
CONF.register_opts(sysconfig_opts, sysconfig_group)
CONF(sys.argv[1:])

class ConfigCommon(object):

    def __init__(self, config_file):
        """
        initial config operation instance.
        :param config_file: string, full path name of config file.
        :return:
        """
        self.config_file = config_file
        self.config = ConfigParser.SafeConfigParser()
        self.config.read(self.config_file)

    def write_commit(self):
        with open(self.config_file, 'w') as config_file_obj:
            self.config.write(config_file_obj)

    def set_option(self, section, option, value):
        self.config.set(section, option, value)

    def get_value(self, section, option):
        return self.config.get(section, option)

    def set_options(self, section, dict_options):
        """

        :param section: type string, name of section
        :param dict_options: type dict
        :return:
        """
        for option, value in dict_options.items():
            self.set_option(section, option, value)