__author__ = 'nash.xiejun'

from oslo.config import cfg

CONF = cfg.CONF

global_opts = [
    cfg.StrOpt('file_hosts',
               default='/etc/hosts'),
    cfg.StrOpt('file_hostname',
               default='/etc/hostname')
]
CONF.register_opts(global_opts)



