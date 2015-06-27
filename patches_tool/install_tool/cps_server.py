#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import json
import os
import traceback
import requests
import sys
import time
import change_auth_mode
import fs_keystone_server
import fs_log_util
import fsutils
from os.path import join

TOKEN_FLAG = False
TIME = 20

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)

cps_url = None

HTTP_POST = 'POST'
HTTP_DELETE = 'DELETE'
HTTP_GET = 'GET'
HTTP_PUT = 'PUT'

class Cps_work_bean():
    def __int__(self):
        pass
    def is_cps_work(self):
        kwargs = {'headers': {"Content-type": "application/json"}, 'verify': False}
        flag, res = base_cps_http(HTTP_GET,  '/cps/v1/haproxylocalurl', **kwargs)
        logger.info("is_cps_work flag=%s ,res=%s."%(flag, res))
        return flag

    def is_host_is_ok(self):
        hosts, ips = get_all_hosts()
        for host in hosts:
            host_info = get_host_detail_info(host)
            if host_info is None:
                print "Host discovery failed,host = %s." %host
                return False
        return True



def is_cps_work_ex():
    sys.path.append("/usr/bin/install_tool")
    module = __import__("cps_server")
    instance = getattr(module, "Cps_work_bean")()
    return instance.is_cps_work()

def is_host_is_ok_ex():
    sys.path.append("/usr/bin/install_tool")
    module = __import__("cps_server")
    instance = getattr(module, "Cps_work_bean")()
    return instance.is_host_is_ok()


def get_local_domain():
    url = '/cps/v1/haproxylocalurl'
    return json.loads(get_cps_http(url))["localurl"]


def set_local_domain(local_dc, local_az, domain_postfix):
    logger.info("enter in set_local_domain. local_dc:%s, local_az:%s, domain_postfix:%s" % (local_dc, local_az, domain_postfix))
    local_url = "%s.%s.%s" % (local_az, local_dc, domain_postfix)
    body = {'localdc': local_dc, 'localaz': local_az, 'localurl': local_url, 'domainpostfix': domain_postfix}
    url = "/cps/v1/haproxylocalurl"
    return post_cps_http(url, body)


def net_host_cfg_add(name):
    logger.info("enter in net_host_cfg_add. name:%s" % name)
    url = "/cps/v1/hostcfg/network/types/%s" % name
    return put_cps_http(url)


def get_host_cfg(name, host_cfg_type, commit_state):
    logger.info("enter in get_host_cfg. name:%s, commitstate:%s, type:%s" % (name, commit_state, host_cfg_type))
    url = "/cps/v1/hostcfg/%s?commit_state=%s" % (host_cfg_type, commit_state)
    res_text = get_cps_http(url)
    if not res_text is None:
        body = json.loads(res_text)
        lst_host_cfg = body["hostcfg"]
        for dct_host_cfg in lst_host_cfg:
            if dct_host_cfg["name"] == name:
                return dct_host_cfg

    return None


def hostcfgGet(name, type_name, commitstate, cpsUrl):
    logger.info("enter in netHostcfgGet. name:%s, type:%s" % (name, type_name))
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network?commit_state=%s" % (cpsUrl, commitstate)
    try:
        res = rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        body = json.loads(res.text)
        lst_hostcfg = body["hostcfg"]
        for dct_hostcfg in lst_hostcfg:
            if dct_hostcfg["name"] == name:
                return dct_hostcfg

        return None
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None


def netHostcfgAdd(name):
    cpsServerUrl = get_cpsserver_url()
    logger.info("start to netHostcfgAdd, name:%s" % name)
    bRet = hostcfgGet(name, "network", "uncommit", cpsServerUrl)
    if bRet:
        logger.info("hostcfg %s is already exist" % name)
        return True

    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network/types/%s" % (cpsServerUrl, name)
    try:
        res = rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        logger.info("create network hostcfg, hostcfgname=%s" % name)
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False


def update_sys_interfaces(content):
    logger.info("enter in update_sysintfnw. content:%s" % content)
    url = "/cps/v1/sysinterfaces"
    return put_cps_http(url, content)


def create_sys_interfaces(sysintfnw_info):
    logger.info("enter in create_sys_interfaces. sysintfnw_info:%s" % sysintfnw_info)
    url = "/cps/v1/sysinterfaces"
    return post_cps_http(url, sysintfnw_info)


def delete_sys_interfaces(str_name):
    logger.info("enter in delete_sys_interfaces. str_name:%s" % str_name)
    body = {"name": str_name}
    url = "/cps/v1/sysinterfaces"
    return delete_cps_http(url, body)


def create_provider(provider_info):
    logger.info("enter in role_host_add. provider_info:%s" % provider_info)
    url = "/cps/v1/providers"
    return post_cps_http(url, provider_info)


def delete_provider(provider_name):
    logger.info("enter in delete_provider. provider_name:%s" % provider_name)
    body = {"name": provider_name}
    url = "/cps/v1/providers"
    return delete_cps_http(url, body)


def get_network_group_detail(group_name):
    url = "/cps/v1/hostcfg/network/types/%s?commit_state=commited" % group_name
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)
    return None


def get_network_group_list():
    url = "/cps/v1/hostcfg/network?commit_state=commited"
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)["hostcfg"]
    return None


def get_sys_interfaces_list():
    url = "/cps/v1/sysinterfaces?commit_state=commited"
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)["sysintfnw"]
    return None


def get_provider_list():
    url = "/cps/v1/providers?commit_state=commited"
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)["provider"]
    return None


def get_all_role_hosts(role):
    url = "/cps/v1/roles/%s/hosts?commit_state=commited" % role
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)["hosts"]
    return None


def cps_host_list():
    url = "/cps/v1/hosts"
    res = get_cps_http(url)
    if res is None:
        return None
    return json.loads(res)


def get_all_hosts():
    result = cps_host_list()
    if result is None:
        return None, None
    all_hosts = []
    all_hosts_ip = []
    for item in result['hosts']:
        all_hosts.append(item['id'])
        all_hosts_ip.append(item['manageip'])
    return all_hosts, all_hosts_ip

def is_role_deployed(all_hosts,host,role):
    for item in all_hosts['hosts']:
        current_host = item["id"]
        if host == current_host:
            roles = item["roles"]
            if role not in roles:
                return False
    return True

def is_roles_deployed(roles):
    if roles is None or len(roles) == 0 :
        return True
    for role in roles:
        role_hosts = get_all_role_hosts(role)
        all_hosts = cps_host_list()
        if role_hosts is None or all_hosts is None:
            return False
        for host in role_hosts:
            ret = is_role_deployed(all_hosts,host,role)
            if not ret:
                logger.error("compute role is empty on %s" % host)
                return False
    return True

def get_template_params(server, template):
    logger.info("enter in get_template_params. server:%s;template:%s;" % (server, template))
    url = "/cps/v1/services/%s/componenttemplates/%s/params?commit_state=commited" % (server, template)
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)
    return None


def get_all_hosts_detail(all_hosts):
    all_hosts_detail = {}
    for host in all_hosts:
        host_detail = get_host_detail_info(host)
        if host_detail is None:
            continue
        all_hosts_detail[host] = host_detail
    return all_hosts_detail


def get_host_detail_info(host):
    logger.info("enter in get_host_detail_info. host:%s" % host)
    url = "/cps/v1/hosts/%s" % host
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)
    return None


def update_temp_ins_num(service, template, ins_num):
    logger.info("enter in update_temp_ins_num. service:%s, template:%s, insnum:%s" % (service, template, ins_num))
    body = {'insnum': ins_num}
    url = "/cps/v1/services/%s/componenttemplates/%s" % (service, template)
    return post_cps_http(url, body)


def get_host_template_status(host):
    logger.info("enter in get_host_template_status. host:%s" % host)
    url = "/cps/v1/hosts/%s/components?commit_state=commited&service=all" % host
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)
    return None


def get_role_host_list(role_name):
    logger.info("enter in role_host_list. role_name:%s" % role_name)
    url = "/cps/v1/roles/%s/hosts?commit_state=uncommit" % role_name
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)['hosts']
    return None


def get_template_info(service, template):
    url = "/cps/v1/services/%s/componenttemplates/%s?commit_state=commited" % (service, template)
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)
    return None


def get_template_list():
    url = "/cps/v1/services/all/componenttemplates?commit_state=commited"
    res_text = get_cps_http(url)
    if not res_text is None:
        return json.loads(res_text)
    return None

def update_template_info(service_name, template_name, dict_name):
    logger.info("enter in update_template_info. service_name:%s, template_name:%s" % (service_name, template_name))
    body = {}
    body["description"] = dict_name["description"]
    body["insnum"] = dict_name["insnum"]
    body["hamode"] = dict_name["hamode"]
    url = "/cps/v1/services/%s/componenttemplates/%s" % (service_name, template_name)
    return post_cps_http(url, body)


def update_template_params(service_name, template_name, params):
    logger.info(
        "enter in update_template_params. service_name:%s, template_name:%s" % (service_name, template_name))
    retValue = check_template_params(service_name, template_name, params)
    if not retValue:
        return True
    body = {'cfg': params}
    url = "/cps/v1/services/%s/componenttemplates/%s/params" % (service_name, template_name)
    return post_cps_http(url, body)

def check_template_params(srv,template,params):
    retValue = False
    tmpList = params.keys()
    dictMsg = get_template_params(srv,template)
    if dictMsg is not None and dictMsg.has_key("cfg"):
        keyInfo = dictMsg["cfg"].keys()
        for item in tmpList:
            if item not in keyInfo:
                logger.warning("Warnings:No property found in template %s/%s,ignore this item(%s,%s)" % (template,srv,item,params[item]))
                params.pop(item)
        if params is not None and len(params) != 0:
            retValue = True
    return retValue
        

def cps_commit():
    logger.info("enter in cps_commit.")
    body = {'timeout': 60}
    url = "/cps/v1/commit"
    return post_cps_http(url, body)


def role_host_add(role_name, hosts):
    tmp_hosts = [i for i in hosts]
    for host in hosts:
        if _is_thishost_has_thisrole(role_name, host):
            logger.info("host %s has %s role"%(host,role_name))
            tmp_hosts.remove(host)

    if not tmp_hosts:
        return True
    logger.info("enter in role_host_add. role_name:%s, hosts:%s" % (role_name, tmp_hosts))
    body = {'type': 'include', 'hosts': tmp_hosts}
    url = "/cps/v1/roles/%s/hosts" % role_name
    return post_cps_http(url, body)


def _is_thishost_has_thisrole(role_name, hosts):
    url = "/cps/v1/roles/%s/hosts?commit_state=uncommit"%role_name
    res = get_cps_http(url)
    logger.info("_is_thishost_has_thisrole,rolename: %s, hosts: %s"%(role_name,hosts))
    if res is None:
        return False
    result = json.loads(res)
    hosts_has_thisrole = result.get("hosts")
    logger.info("These hosts_has_this role. role: %s, hosts: %s"
                %(role_name,str(hosts_has_thisrole)))

    if hosts in hosts_has_thisrole:
        return True
    else:
        return False


def role_host_delete(role_name, hosts):
    logger.info("enter in role_host_delete. role_name:%s, hosts:%s" % (role_name, hosts))
    body = {'type': 'include', 'hosts': hosts}
    url = "/cps/v1/roles/%s/hosts" % role_name
    return delete_cps_http(url, body)


def post_cps_http(url, body=None):
    kwargs = {'headers': {"Content-type": "application/json"}, 'verify': False}
    if not body is None:
        kwargs['data'] = json.dumps(body)
    flag, res = base_cps_http(HTTP_POST, url, **kwargs)
    return flag


def put_cps_http(url, body=None):
    kwargs = {'headers': {"Content-type": "application/json"}, 'verify': False}
    if not body is None:
        kwargs['data'] = json.dumps(body)
    flag, res = base_cps_http(HTTP_PUT, url, **kwargs)
    return flag


def delete_cps_http(url, body=None):
    kwargs = {'headers': {"Content-type": "application/json"}, 'verify': False}
    if not body is None:
        kwargs['data'] = json.dumps(body)
    flag, res = base_cps_http(HTTP_DELETE, url, **kwargs)
    return flag


def get_cps_http(url):
    kwargs = {'headers': {"Content-type": "application/json"}, 'verify': False}
    flag, res = base_cps_http(HTTP_GET, url, **kwargs)
    return res

def get_cps_http_with_flag(url):
    kwargs = {'headers': {"Content-type": "application/json"}, 'verify': False}
    flag, res = base_cps_http(HTTP_GET, url, **kwargs)
    return (flag, res)


def get_role_list():
    url = "/cps/v1/roles?commit_state=commited"
    role_list = []
    res_text = get_cps_http(url)
    if not res_text is None:
        roles_info = json.loads(res_text).get("roles", [])
        for role in roles_info:
            role_list.append(role.get("name", ""))
        return role_list
    return None
def get_role_host_list(role):
    url = "/cps/v1/roles/%s/hosts?commit_state=commited"%role
    host_list = []
    res_text = get_cps_http(url)
    if not res_text is None:
        host_list = json.loads(res_text).get("hosts", [])
        return host_list
    return None

def get_role_template_list(role):
    url = "/cps/v1/roles/%s?commit_state=commited"%role
    template_list = []
    res_text = get_cps_http(url)
    if not res_text is None:
        template_list = json.loads(res_text).get("template", [])
        return template_list
    return None
    
def get_host_role_dict_info():
    host_role_dict = {}
    role_list = get_role_list()
    if not role_list:
        return None
    for role in role_list:
        host_list = get_role_host_list(role)
        if not host_list:
            continue
        for host_id in host_list:
            if host_role_dict.has_key(host_id):
                host_role_dict[host_id].append(role)
            else:
                host_role_dict[host_id] = [role]
    return host_role_dict
def get_cpsserver_url():
    """获取cps_url，优先从缓存获取"""
    global cps_url
    if cps_url is None:
        cps_url = get_cps_url_from_env()
    return cps_url


def get_cps_url_from_env():
    """从环境中获取cps_url"""
    try:
        service_ip = os.environ.get("CPS_SERVER")
        if not service_ip:
            config = ConfigParser.ConfigParser()
            config.readfp(open('/etc/huawei/fusionsphere/cfg/serverIp.ini', "rb"))
            service_ip = config.get('IP', 'serverip')
    except Exception, e:
        logger.error("get_cps_url_from_env failed. exception:%s" % e)
        return None
    return service_ip.strip()


def base_cps_http(opt, simple_url, **kwargs):
    """cps http请求基础封装接口"""
    try:
        url = "%s%s" % (get_cpsserver_url(), simple_url)
        res = rest_cps_execute(opt, url, **kwargs)
        if res.status_code < 200 or res.status_code >= 300:
            return False, None
        return True, res.text
    except:
        logger.error(
            "run request :%s, method:%s, data:%s, exception: %s" % (
                url, opt, fsutils.get_safe_message(kwargs), str(traceback.format_exc())))
        return False, None


def rest_cps_execute(opt, url, **kwargs):
    """针对token和https的封装"""
    res = None
    tryTime = 0
    while tryTime < 10:
        try:
            res = rest_cps_execute_for_token_memory(opt, url, **kwargs)
            if res.status_code >= 200 and res.status_code < 300:
                return res
            elif res.status_code == 401:
                tryTime = tryTime + 1
                logger.error("SYS: Authenticate Failed.tryTime=%s"%tryTime)
                #将token置空，方便重新申请token
                fs_keystone_server.keystone_set_cloud_admin_token_for_cps()
                time.sleep(1)
            else:
                tryTime = tryTime + 1
                time.sleep(1)
        except requests.Timeout:
            logger.warning("run request: %s, method: %s, data: %s, request "
                           "Timeout, tryTime=%s" % (url, opt,
                            fsutils.get_safe_message(kwargs), tryTime))
            tryTime = tryTime + 1
            time.sleep(1)
        except:
            logger.error(
                "run request :%s, method:%s, data:%s, exception: %s" % (
                    url, opt, fsutils.get_safe_message(kwargs), str(traceback.format_exc())))
            return res
    return res



def rest_cps_execute_for_token_memory(opt, url, **kwargs):
    """针对token和https的封装"""
    input_arg = {'headers': {'Content-type': 'application/json'}}

    if 'timeout' not in kwargs:
        input_arg['timeout'] = TIME
    else:
        input_arg['timeout'] = kwargs['timeout']

    if change_auth_mode.ChangeAuthMode().is_https():
        url = url.replace("http:", "https:")
    else:
        url = url.replace("https:", "http:")

    if change_auth_mode.ChangeAuthMode().is_auth_mode() == "y":
        token = fs_keystone_server.keystone_get_cloud_admin_token_for_cps()
        input_arg['headers'] = {"X-Auth-Token": token}

    if 'data' in kwargs:
        input_arg['data'] = kwargs['data']

    input_arg['verify'] = kwargs['verify']
    logger.info(
        "run request :%s, method:%s, data:%s" % (url, opt, fsutils.get_safe_message(kwargs)))
    res = requests.request(opt, url, **input_arg)
    logger.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
        url, opt, str(res.status_code), fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
    return res



def get_configs_port():
    return ("443","443")

def template_instance_action(service_name, template_name, action):
    logger.info(
        "enter in template_instance_action. service_name:%s, template_name:%s" % (service_name, template_name))
    body = {'action': action}
    url = "/cps/v1/instances?service=%s&template=%s" % (service_name, template_name)
    return post_cps_http(url, body)
