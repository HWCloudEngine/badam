#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join

SYSTEM_INI_PATH = join(os.path.dirname(os.path.abspath(__file__)), 'default_sys.ini')
NTP_TIMEZONE_CONF = join(os.path.dirname(os.path.abspath(__file__)), 'zonelist.conf')

SECTION_SYS_CONFIG = "domain"
SECTION_SYS_CONFIG_DOMAIN_CHANGE = "sys_domain_change"
SECTION_SYS_CONFIG_KEYSTONE_DOMAIN = "keystone_domain"
SECTION_SYS_CONFIG_GLANCE_DOMAIN = "glance_domain"
SECTION_SYS_CONFIG_CINDER_DEFAULT_STORE = "cinder_default_store"
SECTION_DNS_CONFIG = "dns"
SECTION_SYS_CONFIG_DNS_SERVER = "dns_server"
SECTION_SYS_CONFIG_DNS_ADDRESS = "dns_address"
SECTION_SYS_CONFIG_DNS_NETWORK = "dns_network"
SECTION_AUTH_MODE_CONFIG = "auth_mode_cfg"
SECTION_SYS_OPEN_TOKEN = "auth_mode"
SECTION_NTP_CONFIG = "ntp"
SECTION_SYS_CONFIG_NTP_NETWORK_TYPE = "ntp_network_type"
SECIONT_SYS_CONFIG_NTP_GATEWAY_TYPE = "ntp_gateway"
SECTION_SYS_CONFIG_NTP_SERVER = "ntp_server"
SECTION_SYS_CONFIG_NTP_ACTIVE_IP = "ntp_active_ip"
SECTION_SYS_CONFIG_NTP_STANDBY_IP = "ntp_standby_ip"
SECTION_UDS_CONFIG = "uds"
SECTION_SYS_CONFIG_IS_UDS = "is_uds"
SECTION_SYS_CONFIG_UDS_DOMAIN_URL = "uds_domain_url"
SECTION_SYS_CONFIG_UDS_EXTERNAL_IP = "uds_external_ip"
SECTION_SYS_CONFIG_UDS_PORT = "uds_port"
SECTION_SYS_CONFIG_GLOBAL_UDS_DOMAIN_URL = "global_uds_domain_url"
SECTION_SYS_CONFIG_GLOBAL_UDS_EXTERNAL_IP = "global_uds_external_ip"
SECTION_SYS_CONFIG_GLOBAL_UDS_PORT = "global_uds_port"
SECTION_SYS_NETWORK = "network"
SECTION_SYS_NETWORK_CUR_PROVIDER_LIST = "cur_provider_list"
SECTION_SYS_NETWORK_CUR_SYSINTFNW_LIST = "cur_sysintfnw_list"

SECTION_TIMEZONE_CONFIG = "timezone"
SECTION_IMETZONE_KEY = "timezone"

SECTION_ROLE_DEPLOY = "host_deploy"
SECTION_ROLE_DEPLOY_CTRL_HOST = "ctrl_hosts"
SECTION_ROLE_DEPLOY_HOST_MODE = "host_mode"
SECTION_ROLE_DEPLOY_LB_LIST = "lb_hosts"
SECTION_ROLE_DEPLOY_ROUTER_LIST = "router_hosts"
SECTION_ROLE_DEPLOY_CINDER_DEFAULT_STORE = "cinder_default_store"
SECTION_ROLE_DEPLOY_BLOCKSTORAGE_DRIVER_HOSTS = "blockstorage_driver_hosts"

SECTION_DYNAMIC_ROLE = "dynamic_role"
SECTION_DYNAMIC_ROLE_LIST = "role_list"

CINDER_TYPE_FUSION_STORAGE = "fusionstorage"
CINDER_TYPE_FILE = "file"
CINDER_TYPE_IPSAN = "ipsan"

PREINSTALL_WAIT_TIME_ENV = "PREINSTALL_WAIT_TIME"


