#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import fs_glance_server
import fsutils as utils
import fs_system_server
import fs_keystone_constant
import fs_keystone_util
#mode对应的字段全集
NOVA = "nova"
NEUTRON = "neutron"
SWIFT = "swift"
CINDER = "cinder"
CINDERV2 = "cinderv2"
HEAT = "heat"
CEILOMETER = "ceilometer"
KEYSTONE = "keystone"
GLANCE = "glance"
COLLECT = "collect"
S3 = "s3"
GLOBAL_S3 = "global_s3"
CPS = "cps"
UPGRADE = "upgrade"
LOG = "log"
BACKUP = "backup"
FUSIONNETWORK = "fusionnetwork"
IRONIC = "ironic"
ENDPOINT_HTTPS = {LOG: "https", BACKUP: "https", NOVA: "https", NEUTRON: "https", SWIFT: "https", CINDER: "https", CINDERV2: "https", HEAT: "https",
                  CEILOMETER: "https", KEYSTONE: "https", GLANCE: "https", COLLECT: "https", CPS: "https",FUSIONNETWORK: "https",
                  UPGRADE: "https"}

def get_endpoint_postfix(keystone_port,glance_port,local_haproxy_port):
    ceilometer_public_url = ':%s' % local_haproxy_port
    cinder_public_url = ':%s/v2/$(tenant_id)s' % local_haproxy_port
    heat_public_url = ':%s/v1/$(tenant_id)s' % local_haproxy_port        
    neutron_public_url = ':%s' % local_haproxy_port
    nova_public_url = ':%s/v2/$(tenant_id)s' % local_haproxy_port
    swift_public_url = ':%s/v1/AUTH_$(tenant_id)s' % local_haproxy_port
    collect_public_url = ':%s' % local_haproxy_port
    cps_public_url = ':%s' % local_haproxy_port
    upgrade_public_url = ':%s' % local_haproxy_port       
    log_public_url = ':%s' % local_haproxy_port
    fusionnetwork_public_url = ':%s' % local_haproxy_port
    backup_public_url = ':%s' % local_haproxy_port
    ironic_public_url_postfix = ':%s' % local_haproxy_port

    keystone_public_url = ':%s/identity/v2.0' % keystone_port        
    keystone_admin_url = ':%s/identity-admin/v2.0' % keystone_port        

    glance_admin_url = ':%s' % glance_port
    glance_public_url = ':%s' % glance_port        
    
    return {
    'ceilometer_admin_url': ceilometer_public_url, 'ceilometer_internal_url': ':8777', 'ceilometer_public_url': ceilometer_public_url,
    'cinder_admin_url': cinder_public_url, 'cinder_internal_url': ':8776/v2/$(tenant_id)s',
    'cinder_public_url': cinder_public_url,
    'glance_admin_url': glance_admin_url, 'glance_internal_url': ':8500', 'glance_public_url': glance_public_url,
    'heat_admin_url': heat_public_url, 'heat_internal_url': ':8700/v1/$(tenant_id)s',
    'heat_public_url': heat_public_url,
    'keystone_admin_url': keystone_admin_url, 'keystone_internal_url': ':8023/identity-admin/v2.0',
    'keystone_public_url': keystone_public_url,
    'neutron_admin_url': neutron_public_url, 'neutron_internal_url': ':8020', 'neutron_public_url': neutron_public_url,
    "nova_admin_url": nova_public_url, "nova_internal_url": ':8001/v2/$(tenant_id)s',
    "nova_public_url": nova_public_url,
    'swift_admin_url': swift_public_url, 'swift_internal_url': ':8006/v1/AUTH_$(tenant_id)s',
    'swift_public_url': swift_public_url,
    'collect_admin_url': collect_public_url, 'collect_internal_url': ':8235', 'collect_public_url': collect_public_url,
    'cps_admin_url': cps_public_url, 'cps_internal_url': ':8008', 'cps_public_url': cps_public_url,
    'upgrade_admin_url': upgrade_public_url, 'upgrade_internal_url': ':8100', 'upgrade_public_url': upgrade_public_url,
    'log_admin_url': log_public_url, 'log_internal_url': ':8232', 'log_public_url': log_public_url,
	'fusionnetwork_admin_url': fusionnetwork_public_url, 'fusionnetwork_internal_url': ':8200', 'fusionnetwork_public_url': fusionnetwork_public_url,
    'backup_admin_url': backup_public_url, 'backup_internal_url': ':8888', 'backup_public_url': backup_public_url,
    'ironic_admin_url': ironic_public_url_postfix, 'ironic_internal_url': ':8885','ironic_public_url': ironic_public_url_postfix
    } 


def get_check_list():
    check_list = ["log", "backup","ceilometer","cinder","cinderv2","collect","cps","glance","global_s3","heat","keystone","neutron","nova","s3","swift","upgrade","fusionnetwork", "ironic"]
    return check_list


def calc_endpoint(cf, mode,is_current_endpoint=True):
    """
    计算各url。
    @param cf：default.ini中的值
    @param mode:"ALL":所有都获取；"组件名"：获取相应的组件url。
    @return:{"组件名"：{"public_url":"","admin_url","internal_url":""}}
    """
    service_endpoints = {}
    http_type_endpoint = None
    if fs_system_server.system_is_keystone_https():
        http_type_endpoint = "https"
    else:
        http_type_endpoint = "http"
    if not is_current_endpoint:
        http_type_endpoint = fs_keystone_util.KeystoneUtil().get_http_type_ex()
    if mode == KEYSTONE:
        urls = _gen_url(KEYSTONE, "identity", fs_system_server.system_get_keystone_az(),\
               fs_system_server.system_get_keystone_dc(), fs_system_server.system_get_keystone_domain_postfix(),\
               http_type_endpoint,"")
        service_endpoints.setdefault(KEYSTONE, urls)
        return service_endpoints
    if cf is None:
        cf = ConfigParser.ConfigParser()
        cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)
    local_haproxy_port = fs_keystone_util.KeystoneUtil().get_haproxy_cfg()
    local_az = fs_system_server.system_get_local_az()
    local_dc = fs_system_server.system_get_local_dc()
    domain_postfix = fs_system_server.system_get_domain_postfix()
    keystone_az = fs_system_server.system_get_keystone_az()
    keystone_dc = fs_system_server.system_get_keystone_dc()
    glance_dc = fs_system_server.system_get_glance_dc()
    glance_az = fs_system_server.system_get_glance_az()
    if mode == "ALL" or mode == NOVA:
        urls = _gen_url(NOVA, "compute", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(NOVA, urls)
    if mode == "ALL" or mode == NEUTRON:
        urls = _gen_url(NEUTRON, "network", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(NEUTRON, urls)
    if mode == "ALL" or mode == SWIFT:
        urls = _gen_url(SWIFT, "object-store", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(SWIFT, urls)
    if mode == "ALL" or mode == CINDER:
        urls = _gen_url(CINDER, "volume", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(CINDER, urls)
    if mode == "ALL" or mode == CINDERV2:
        urls = _gen_url(CINDER, "volume", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(CINDERV2, urls)
    if mode == "ALL" or mode == HEAT:
        urls = _gen_url(HEAT, "orchestration", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(HEAT, urls)
    if mode == "ALL" or mode == CEILOMETER:
        urls = _gen_url(CEILOMETER, "metering", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(CEILOMETER, urls)
    if mode == "ALL" or mode == KEYSTONE:
        urls = _gen_url(KEYSTONE, "identity", keystone_az, keystone_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(KEYSTONE, urls)
    if mode == "ALL" or mode == GLANCE:
        urls = _gen_url(GLANCE, "image", glance_az, glance_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(GLANCE, urls)
    if mode == "ALL" or mode == COLLECT:
        urls = _gen_url(COLLECT, "info-collect", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(COLLECT, urls)
    if mode == "ALL" or mode == S3:
        s3_public_url = fs_glance_server.glance_get_s3_public_url()
        s3_admin_url = fs_glance_server.glance_get_s3_admin_url()
        s3_internal_url = fs_glance_server.glance_get_s3_internal_url()
        service_endpoints.setdefault(S3, {"public_url": s3_public_url, "admin_url": s3_admin_url,
                                          "internal_url": s3_internal_url})
    if mode == "ALL" or mode == GLOBAL_S3:
        if fs_system_server.system_is_keystone_at_local():
            global_s3_public_url = fs_glance_server.glance_get_global_s3_public_url()
            global_s3_admin_url = fs_glance_server.glance_get_global_s3_admin_url()
            global_s3_internal_url = fs_glance_server.glance_get_global_s3_internal_url()
            service_endpoints.setdefault(GLOBAL_S3,
                                         {"public_url": global_s3_public_url, "admin_url": global_s3_admin_url,
                                          "internal_url": global_s3_internal_url})

    if mode == "ALL" or mode == CPS:
        urls = _gen_url(CPS, "cps", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(CPS, urls)

    if mode == "ALL" or mode == UPGRADE:
        urls = _gen_url(UPGRADE, "upgrade", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(UPGRADE, urls)

    if mode == "ALL" or mode == LOG:
        urls = _gen_url(LOG, "log", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(LOG, urls)

    if mode == "ALL" or mode == BACKUP:
        urls = _gen_url(BACKUP, "backup", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(BACKUP, urls)

    if mode == "ALL" or mode == FUSIONNETWORK:
        urls = _gen_url(FUSIONNETWORK, "oam", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(FUSIONNETWORK, urls)

    if mode == "ALL" or mode == IRONIC:
        urls = _gen_url(IRONIC, "baremetal", local_az, local_dc, domain_postfix, http_type_endpoint,local_haproxy_port)
        service_endpoints.setdefault(IRONIC, urls)

    return service_endpoints


def _gen_url(name, info, az_name, dz_name, domain_name, https_or_http,local_haproxy_port):
    """
    获取url.
    """
    keystone_public_url = '/identity/v2.0'
    keystone_admin_url = '/identity-admin/v2.0'
    keystone_internal_url = ':8023/identity-admin/v2.0'

    prv_endpoint_postfix = None
    glance_port = fs_system_server.system_get_glance_port()
    keystone_port = fs_system_server.system_get_keystone_port()
    keystone_public_url = ':%s/identity/v2.0' % keystone_port
    keystone_admin_url = ':%s/identity-admin/v2.0' % keystone_port
    if info == "identity":
        prv_endpoint_postfix = { 'keystone_admin_url': keystone_admin_url,\
                             'keystone_internal_url': keystone_internal_url,\
                             'keystone_public_url': keystone_public_url}
    else:
        prv_endpoint_postfix = get_endpoint_postfix(keystone_port, glance_port,local_haproxy_port)

    key_public = name + "_public_url"
    key_admin = name + "_admin_url"
    key_internal = name + "_internal_url"

    public_url = "%s://%s.%s.%s.%s%s" % (
        https_or_http, info, az_name, dz_name, domain_name, prv_endpoint_postfix[key_public])
    admin_url = "%s://%s.%s.%s.%s%s" % (
        https_or_http, info, az_name, dz_name, domain_name, prv_endpoint_postfix[key_admin])
    internal_url = "%s://%s.%s%s" % (
        https_or_http, info, utils.DOMAIN_INTERNAL, prv_endpoint_postfix[key_internal])
    return {"public_url": public_url, "admin_url": admin_url, "internal_url": internal_url}

