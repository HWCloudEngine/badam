__author__ = 'nash.xiejun'

from oslo.config import cfg
import os
import sys

CONF = cfg.CONF

global_opts = [
    cfg.StrOpt('file_hosts',
               default='/etc/hosts'),
    cfg.StrOpt('file_hostname',
               default='/etc/hostname'),
    cfg.StrOpt('self_config_file', default=os.path.split(os.path.realpath(__file__))[0] + '/../config/configuration.conf'),
    cfg.StrOpt('log_file', default='/var/log/engineering.log')
]
CONF.register_opts(global_opts)

sysconfig_group = cfg.OptGroup(name='sysconfig',
                               title='sys config for all in one')
sysconfig_opts = [
    cfg.StrOpt('hostname',
               default='hostname_default'),
    cfg.StrOpt('operation',
               default='operation_default')
]

CONF.register_group(sysconfig_group)
CONF.register_opts(sysconfig_opts, sysconfig_group)
CONF(sys.argv[1:])