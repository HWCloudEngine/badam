#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import os
from os.path import join
import sys
import traceback
import requests
import cps_server
import fs_log_util
from fs_system_constant import SECTION_SYS_CONFIG_GLANCE_DOMAIN, SECTION_SYS_CONFIG_KEYSTONE_DOMAIN, SECTION_SYS_CONFIG, SECTION_ROLE_DEPLOY_HOST_MODE, SECTION_ROLE_DEPLOY, SECTION_ROLE_DEPLOY_CTRL_HOST, SYSTEM_INI_PATH
import fs_system_constant
from print_msg import PrintMessage, INTERNAL_ERROR
import fs_system_util
#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


def input_keystone_domain():
    def_keystone_domain = "https://identity.az1.dc1.domainname.com:443"
    keystone_tmp = fs_system_util.get_file_write_data(fs_system_constant.SYSTEM_INI_PATH,
                                   SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_KEYSTONE_DOMAIN)

    if "" != keystone_tmp and keystone_tmp is not None:
        if fs_system_util.check_domain(keystone_tmp):
            def_keystone_domain = keystone_tmp

    while 1:
        try:
            input_str = "Please set domain that keystone installed on [%s] : " % def_keystone_domain
            keystone_domain = raw_input(input_str)
            keystone_domain = keystone_domain.strip()
            if keystone_domain == "":
                keystone_domain = def_keystone_domain
                break
            match = fs_system_util.check_domain(keystone_domain)
            if not match:
                print "please set the correct domain such as 'https://identify.az1.dc1.domainname.com:443'"
                continue
            else:
                break
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            print ["please set the correct keystone domain name.", "请输入一个dc名"]
            LOG.error("failed: %s" % str(traceback.format_exc()))
            continue

    fs_system_util.file_write_data(fs_system_constant.SYSTEM_INI_PATH,
                                   SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_KEYSTONE_DOMAIN, keystone_domain)
    return keystone_domain


def input_glance_domain():
    def_glance_domain = "https://image.az1.dc1.domainname.com:443"
    glance_tmp = fs_system_util.get_file_write_data(fs_system_constant.SYSTEM_INI_PATH,
                                   SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_GLANCE_DOMAIN)

    if "" != glance_tmp and glance_tmp is not None:
        if fs_system_util.check_domain(glance_tmp):
            def_glance_domain = glance_tmp

    while 1:
        try:
            input_str = "Please set domain that glance installed on [%s] : " % def_glance_domain
            glance_domain = raw_input(input_str)
            glance_domain = glance_domain.strip()
            if glance_domain == "":
                glance_domain = def_glance_domain
                break
            match = fs_system_util.check_domain(glance_domain)
            if not match:
                print "please set the correct domain such as 'https://image.az1.dc1.domainname.com:443'"
                continue
            else:
                break
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            print ["please set the correct dc name.", "请输入一个dc名"]
            LOG.error("failed: %s" % str(traceback.format_exc()))
            continue

    fs_system_util.file_write_data(fs_system_constant.SYSTEM_INI_PATH,
                                   SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_GLANCE_DOMAIN, glance_domain)

    return glance_domain


def system_get_local_az():
    local_url = cps_server.get_local_domain()
    local_url_list = local_url.split('.')
    return local_url_list[0]


def system_get_local_dc():
    local_url = cps_server.get_local_domain()
    local_url_list = local_url.split('.')
    return local_url_list[1]


def system_get_domain_postfix():
    local_url = cps_server.get_local_domain()
    local_url_list = local_url.split('.')
    local_az = local_url_list[0]
    local_dc = local_url_list[1]
    domain_post_fix = local_url[len(local_az) + len(local_dc) + 2:]
    return domain_post_fix


def system_get_keystone_domain():
    cf = ConfigParser.ConfigParser()
    keystone_domainname = ""
    if not os.path.exists(SYSTEM_INI_PATH):
        #配置文件不存在，提示用户输入glance的域名，不能直接退出，否则会导致 在token打开的时候，
        #其他节点无法使用安装工具
        keystone_domainname = input_keystone_domain()
    else:
        cf.read(SYSTEM_INI_PATH)
        if  not cf.has_option(SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_KEYSTONE_DOMAIN):
            keystone_domainname = input_keystone_domain()
        else:
            keystone_domainname = cf.get(SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_KEYSTONE_DOMAIN)
    return keystone_domainname


def system_get_glance_domain():
    cf = ConfigParser.ConfigParser()
    glance_domain = ""
    if not os.path.exists(SYSTEM_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % SYSTEM_INI_PATH)
        #配置文件不存在，提示用户输入glance的域名，不能直接退出，否则会导致 在token打开的时候，
        #其他节点无法使用安装工具
        glance_domain = input_glance_domain()
    else:
        cf.read(SYSTEM_INI_PATH)
        if not cf.has_option(SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_GLANCE_DOMAIN):
            glance_domain = input_glance_domain()
        else:
            glance_domain = cf.get(SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_GLANCE_DOMAIN)
    return glance_domain

def keystone_glance_section_exit(type_name):
    flag = True
    if not os.path.exists(SYSTEM_INI_PATH):
        flag = False
    else:
        cf = ConfigParser.ConfigParser()
        cf.read(SYSTEM_INI_PATH)
        if not cf.has_option(SECTION_SYS_CONFIG, type_name):
            flag = False
    return flag





def system_is_keystone_https():
    domain = system_get_keystone_domain()
    return fs_system_util.is_domain_https(domain)


def system_is_glance_https():
    domain = system_get_glance_domain()
    return fs_system_util.is_domain_https(domain)


def system_get_keystone_server():
    domain = system_get_keystone_domain()
    return fs_system_util.get_server_by_domain(domain)


def system_get_glance_server():
    domain = system_get_glance_domain()
    return fs_system_util.get_server_by_domain(domain)


def system_get_glance_domain_postfix():
    domain = system_get_glance_domain()
    return fs_system_util.get_postfix_by_domain(domain)


def system_get_keystone_domain_postfix():
    domain = system_get_keystone_domain()
    return fs_system_util.get_postfix_by_domain(domain)


def system_get_glance_port():
    domain = system_get_glance_domain()
    return fs_system_util.get_port_by_domain(domain)


def system_get_keystone_port():
    domain = system_get_keystone_domain()
    return fs_system_util.get_port_by_domain(domain)


def system_get_keystone_az():
    domain = system_get_keystone_domain()
    return fs_system_util.get_az_by_domain(domain)


def system_get_keystone_dc():
    domain = system_get_keystone_domain()
    return fs_system_util.get_dc_by_domain(domain)


def system_get_glance_dc():
    domain = system_get_glance_domain()
    return fs_system_util.get_dc_by_domain(domain)


def system_get_glance_az():
    domain = system_get_glance_domain()
    return fs_system_util.get_az_by_domain(domain)


def system_get_local_domain():
    local_url = cps_server.get_local_domain()
    local_url_list = local_url.split('.')
    local_az = local_url_list[0]
    local_dc = local_url_list[1]
    domain_post_fix = local_url[len(local_az) + len(local_dc) + 2:]
    return local_dc, local_az, domain_post_fix


def system_is_keystone_at_local():
    try:
        dc_name, local_az, domain_postfix = system_get_local_domain()
        config = ConfigParser.RawConfigParser()
        config.read(SYSTEM_INI_PATH)
        keystone_dc = system_get_keystone_dc()
        keystone_az = system_get_keystone_az()
        return keystone_dc == dc_name and keystone_az == local_az
    except:
        return False


def system_get_ctrl_hosts():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(SYSTEM_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % SYSTEM_INI_PATH)
        PrintMessage.print_msg(INTERNAL_ERROR, True)
        sys.exit(0)
    else:
        cf.read(SYSTEM_INI_PATH)
        control_host = cf.get(SECTION_ROLE_DEPLOY, SECTION_ROLE_DEPLOY_CTRL_HOST)
        return control_host

def system_get_host_mode():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(SYSTEM_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % SYSTEM_INI_PATH)
        PrintMessage.print_msg(INTERNAL_ERROR, True)
        sys.exit(0)
    else:
        cf.read(SYSTEM_INI_PATH)
        control_host = cf.get(SECTION_ROLE_DEPLOY, SECTION_ROLE_DEPLOY_HOST_MODE)
        return control_host

def is_connection_work():
    try:
        method="GET"
        kwargs = {'headers': {"Content-type": "application/json"}, 'verify': False}
        keystone_url = system_get_keystone_domain()
        if keystone_url is None:
            return False
        keystone_url = keystone_url + "/identity/v2.0"
        res = requests.request(method, keystone_url, timeout = 10, **kwargs)
        if res.status_code < 200 or res.status_code > 300:
            LOG.error("connection is abnormal:%s." % res.status_code)
            return False
        else:
            LOG.info("connection is OK.")
            return True
    except:
        LOG.error("connection is abnormal:%s." % traceback.format_exc())
        return False


def default_sys_file_check_and_put():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(SYSTEM_INI_PATH):
        return False
    if not cf.has_option(SECTION_SYS_CONFIG, SECTION_SYS_CONFIG_KEYSTONE_DOMAIN):
        input_keystone_domain()
        return True
    return False
