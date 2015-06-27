#!/usr/bin/python
#coding:utf-8

import copy
import types
import traceback

from install_tool import log
import cps_server
import fs_system_server


def set_match_config_value(config):
    """
    将组件中所有keystone和glance相关参数的键都赋予对应的值
    """
    update_params = {}

    #获取最新的glance路径参数
    glance_az = fs_system_server.system_get_glance_az()
    glance_dc = fs_system_server.system_get_glance_dc()
    glance_server = fs_system_server.system_get_glance_server()
    glance_post_fix = fs_system_server.system_get_glance_domain_postfix()
    glance_port = fs_system_server.system_get_glance_port()
    if fs_system_server.system_is_glance_https():
        glance_protocol = "https"
    else:
        glance_protocol = "http"

    #获取最新的keystone路径参数
    keystone_az = fs_system_server.system_get_keystone_az()
    keystone_dc = fs_system_server.system_get_keystone_dc()
    keystone_server = fs_system_server.system_get_keystone_server()
    keystone_post_fix = fs_system_server.system_get_keystone_domain_postfix()
    keystone_port = fs_system_server.system_get_keystone_port()
    if fs_system_server.system_is_keystone_https():
        keystone_protocol = "https"
    else:
        keystone_protocol = "http"

    #获取本az的az、dc、域名参数
    local_dc, local_az, _ = fs_system_server.system_get_local_domain()

    update_params["auth_port"] = keystone_port
    update_params["api_auth_port"] = keystone_port
    update_params["registry_auth_port"] = keystone_port
    update_params["glance_port"] = glance_port

    auth_host = "%s.%s.%s.%s" % (keystone_server, keystone_az,
                                 keystone_dc, keystone_post_fix)
    update_params["auth_host"] = auth_host
    update_params["api_auth_host"] = auth_host
    update_params["registry_auth_host"] = auth_host

    os_auth_url = "%s://%s.%s.%s.%s:%s/identity-admin/v2.0" \
                  % (keystone_protocol, keystone_server, keystone_az,
                     keystone_dc, keystone_post_fix, keystone_port)
    update_params["os_auth_url"] = os_auth_url
    update_params["swift_store_auth_address"] = os_auth_url
    update_params["auth_uri"] = os_auth_url
    update_params["auth_url"] = os_auth_url
    update_params["nova_admin_auth_url"] = os_auth_url
    update_params["neutron_admin_auth_url"] = os_auth_url
    update_params["admin_url"] = os_auth_url

    os_region_name = local_az + '.' + local_dc
    update_params["os_region_name"] = os_region_name
    update_params["default_availability_zone"] = os_region_name
    update_params["storage_availability_zone"] = os_region_name

    glance_host = '%s://%s.%s.%s.%s' % (glance_protocol, glance_server,
                                        glance_az, glance_dc, glance_post_fix)
    update_params["glance_host"] = glance_host

    keystone_ec2_url = '%s://%s.%s.%s.%s:%s/%s/v2.0/ec2tokens' \
                % (keystone_protocol, keystone_server, keystone_az, keystone_dc,
                   keystone_post_fix, keystone_port, keystone_server)
    update_params["keystone_ec2_url"] = keystone_ec2_url

    update_params["glance_domain"] = "%s:%s" % (glance_host, glance_port)
    update_params["keystone_domain"] = "%s://%s:%s" % (keystone_protocol,
                                                       auth_host, keystone_port)
    return update_params


def update_component_cfg(config):
    """
    更新所有组件涉及keystone和glance相关的参数
    """
    try:
        templates = cps_server.get_template_list()
        if not templates:
            log.error("get_template_list failed")
            return False

        template_list = templates.get("templates", [])
        if not template_list:
            log.error("get_template_list failed")
            return False

        #准备更新参数
        config_dict = set_match_config_value(config)
        for item in template_list:
            service = item.get("service")
            template = item.get("name")
            if not update_template_params_rm_not_exist_value(service, template,
                                                             config_dict):
                log.error("updateTemplateParams failed. service = %s, "
                          "template= %s" % (service, template))
                return False

        return True
    except:
        log.error("update_component_cfg occur unknow error:%s"
                  % str(traceback.format_exc()))
        return False

def update_template_params_rm_not_exist_value(service, template, cfg_dct):
    """
    功能：更新指定组件的部分参数项，这些参数项在入参的集合中
    入参：service:服务名， template：组件名， cfg_dct：指定的参数项字典
    返回值：True:更新成功, False:更新失败
    """
    params = copy.deepcopy(cfg_dct)
    ret_value = check_template_params(service, template, params)
    if ret_value is None:
        return False

    if not ret_value:
        return True
    body = {'cfg': params}
    log.info("DOMAIN_UPDATE info:%s,%s,%s" % (service, template, params.keys()))
    url = "/cps/v1/services/%s/componenttemplates/%s/params" \
          % (service, template)
    ret = cps_server.post_cps_http(url, body)
    return ret

def check_template_params(service_name, template_name, params):
    """
    功能：获取入参的选项字典集合中与该组件中的参数选项共同的参数选项
    入参：params：指定的参数选项字典,返回后该字典中是和组件共同的参数选项键值
    返回值：True-正常返回， False-异常返回
    """
    ret_value = False
    tmp_list = params.keys()
    dic_msg = cps_server.get_template_params(service_name, template_name)
    if dic_msg is None:
        return None

    if dic_msg.has_key("cfg"):
        body = dic_msg.get("cfg")
        if type(body) != types.DictType:
            log.error("DOMAIN_UPDATE Warnings: template %s/%s,ignore this "
                      "item(%s), dict_msg=%s." % (service_name, template_name,
                                                 body, dic_msg))
            return False

        key_info = dic_msg["cfg"].keys()
        ignore_item = []
        for item in tmp_list:
            if item not in key_info:
                ignore_item.append(item)
                params.pop(item)
        log.info("DOMAIN_UPDATE Warnings:No property found in template %s/%s,"
                 "ignore this item(%s)" % (service_name, template_name,
                                           ignore_item))
        if params is not None and len(params) != 0:
            ret_value = True
    return ret_value

