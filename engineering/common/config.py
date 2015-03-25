__author__ = 'nash.xiejun'

import os
import sys
import ConfigParser
from engineering.common.econstants import PathTriCircle

from oslo.config import cfg
from engineering import utils

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
    cfg.StrOpt('section_default', default='DEFAULT'),
    cfg.StrOpt('openstack_installed_path', default=utils.get_openstack_installed_path()),
    cfg.StrOpt('openstack_bak_path', default='/root/'),
    cfg.StrOpt('path_nova_patches_conf', default=os.path.split(os.path.realpath(__file__))[0] + '/../config/nova.conf')
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

node_cfg_group = cfg.OptGroup(name='node_cfg',
                               title='for define node type, 3 option: cascading_node, cascaded_node, proxy_node')
node_cfg_opts = [
    cfg.BoolOpt('cascading_node',
                default=False),
    cfg.BoolOpt('cascaded_node',
                default=False),
    cfg.BoolOpt('proxy_node',
                default=False),
    cfg.StrOpt('region_name', default=''),
    cfg.StrOpt('cascading_node_ip', default='127.0.0.1'),
    cfg.StrOpt('proxy_node_ip', default='127.0.0.1'),
    cfg.StrOpt('cascaded_node_ip', default='127.0.0.1'),
    cfg.StrOpt('availability_zone', default='RegionOne'),
    cfg.StrOpt('cascading_os_region_name', default='RegionOne')
]

cascading_node_plugins_group = cfg.OptGroup('cascading_node_plugins',
                                      title='For define cascading plugin')

cascading_node_plugins_opts = [
    cfg.BoolOpt(PathTriCircle.PATCH_NOVA_SCHEDULING,
                default=True),
    cfg.BoolOpt('neutron_cascading_big2layer_patch',
                default=True),
    cfg.BoolOpt('neutron_cascading_l3_patch',
                default=False),
    cfg.DictOpt('endpoints_info', default=None)
]

cascaded_node_plugins_group = cfg.OptGroup(name='cascaded_node_plugins',
                                     title='For define cascaded plugin')

cascaded_node_plugins_opts = [
    cfg.BoolOpt('neutron_cascaded_big2layer_patch',
                default=True),
    cfg.BoolOpt('neutron_cascaded_l3_patch',
                default=False),
    cfg.BoolOpt('neutron_timestamp_cascaded_patch',
                default=True),
    cfg.BoolOpt('cinder_timestamp_query_patch', default=True)
]

proxy_node_plugins_group = cfg.OptGroup(name='proxy_node_plugins',
                                        title='for define which proxy plugins be installed in proxy node')

proxy_node_plugins_opts = [
    cfg.BoolOpt('nova_proxy',
                default=False),
    cfg.BoolOpt('cinder_proxy',
                default=False),
    cfg.BoolOpt('neutron_l2_proxy',
                default=False),
    cfg.BoolOpt('neutron_l3_proxy',
                default=False),
]


CONF.register_group(sysconfig_group)
CONF.register_opts(sysconfig_opts, sysconfig_group)

CONF.register_group(cascading_node_plugins_group)
CONF.register_opts(cascading_node_plugins_opts, cascading_node_plugins_group)

CONF.register_group(cascaded_node_plugins_group)
CONF.register_opts(cascaded_node_plugins_opts, cascaded_node_plugins_group)

CONF.register_group(proxy_node_plugins_group)
CONF.register_opts(proxy_node_plugins_opts, proxy_node_plugins_group)

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

    def get_sections(self):
        return self.config.sections()

    def get_options(self, section):
        return self.config.options(section)