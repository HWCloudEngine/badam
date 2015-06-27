#!/usr/bin/python
#coding:utf-8

class DefaultConst(object):
    """
    default.ini中涉及的section、option和键-值常量
    """
    SEC_DOMAIN = "domain"
    OPT_LOCAL_DC = "local_dc"
    OPT_LOCAL_AZ = "local_az"
    OPT_DOMAINPOSTFIX = "domainpostfix"

    SEC_DEPLOY_POLICY = "deploy_policy"
    OPT_DEPLOY_BAREMETAL = 'deploy_baremetal_role'

    SEC_RVS_PROXY = "reverse_proxy"
    OPT_EXT_API_IP = "external_api_ip"
    KEY_BKEND_SRVC = "backendservice"
    KEY_FRONTPORT = "frontendport"
    VAL_NOVNCPROXY = "nova-novncproxy"

    SEC_HTTP_MODE = "http_mode"
    OPT_HTTP_TYPE = "url_http_type"

class ParamsConst(object):
    """
    各组件参数中的键常量
    """
    AUTH_HOST_KEY = "auth_host"
    AUTH_PORT_KEY = "auth_port"
    AUTH_PROTOCOL_KEY = "auth_protocol"
    OS_AUTH_URL = "os_auth_url"
    GLANCE_PORT = "glance_port"
    GLANCE_HOST = "glance_host"
    GLANCE_PROTOCOL = "glance_protocol"
    ADMIN_URL = "admin_url"
    NEUTRON_AUTH_URL = "neutron_admin_auth_url"
    NOVNCPROXY_URL = "novncproxy_base_url"
