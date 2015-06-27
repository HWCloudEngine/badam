#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import fs_system_constant
import cps_server
import traceback
import re
import os
from os.path import join
import fs_log_util

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)

change_flag_list = {"Reverse proxy":"false", "Forward proxy":"false", "Default route":"false", "Dns":"false",
               "Http Mode":"false", "Ntp":"false", "Uds":"false", "System service auth mode":"false", "Dc admin":"false",
               "External api":"false", "Internal base":"false"}
def change_all_flag_list(mode):
    global change_flag_list
    for key, value in change_flag_list.iteritems():
        change_flag_list[key] = mode
def is_section_change(section):
    global change_flag_list
    flag = False
    if change_flag_list.has_key(section):
        if "true" == change_flag_list[section]:
            flag = True
    else:
        flag = False
    return flag
def set_section_change_flag(section, flag):
    global change_flag_list

    change_flag_list[section] = flag


def check_domain(domain_url):
    domain_re = "^http(s)://([\w\-]+).([\w\-]+).([\w\-]+).([\w\-.]+):([0-9]|[1-9]\d|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$"
    pattern = re.compile(domain_re)
    match = pattern.match(domain_url)
    return match


def is_domain_https(domain_url):
    match = check_domain(domain_url)
    if match:
        return match.groups()[0] == 's'
    else:
        print "Domain_url is not correct : %s" % domain_url
        logger.error("Domain_url is not correct : %s" % domain_url)


def get_server_by_domain(domain_url):
    match = check_domain(domain_url)
    if match:
        return match.groups()[1]
    else:
        print "Domain_url is not correct : %s" % domain_url
        logger.error("Domain_url is not correct : %s" % domain_url)


def get_az_by_domain(domain_url):
    match = check_domain(domain_url)
    if match:
        return match.groups()[2]
    else:
        print "Domain_url is not correct : %s" % domain_url
        logger.error("Domain_url is not correct : %s" % domain_url)


def get_dc_by_domain(domain_url):
    match = check_domain(domain_url)
    if match:
        return match.groups()[3]
    else:
        print "Domain_url is not correct : %s" % domain_url
        logger.error("Domain_url is not correct : %s" % domain_url)


def get_postfix_by_domain(domain_url):
    match = check_domain(domain_url)
    if match:
        return match.groups()[4]
    else:
        print "Domain_url is not correct : %s" % domain_url
        logger.error("Domain_url is not correct : %s" % domain_url)


def get_port_by_domain(domain_url):
    match = check_domain(domain_url)
    if match:
        return match.groups()[5]
    else:
        print "Domain_url is not correct : %s" % domain_url
        logger.error("Domain_url is not correct : %s" % domain_url)


def get_one_option(section, option):
    config = ConfigParser.RawConfigParser()
    config.read(fs_system_constant.SYSTEM_INI_PATH)
    if config.has_option(section, option):
        return config.get(section, option)
    return None


def get_local_dc_az():
    local_url = cps_server.get_local_domain()
    local_url_list = local_url.split('.')
    local_az = local_url_list[0]
    local_dc = local_url_list[1]
    return local_dc, local_az


def get_domain_fix():
    local_url = cps_server.get_local_domain()
    local_url_list = local_url.split('.')
    local_az = local_url_list[0]
    local_dc = local_url_list[1]
    domain_post_fix = local_url[len(local_az) + len(local_dc) + 2:]
    return "", domain_post_fix


def save_one_option(section, option, value):
    config = ConfigParser.RawConfigParser()
    config.read(fs_system_constant.SYSTEM_INI_PATH)
    if not config.has_section(section):
        config.add_section(section)
    config.set(section, option, value)
    with open(fs_system_constant.SYSTEM_INI_PATH, 'w') as fd:
        config.write(fd)

def file_write_data(file_name, section, key, value):
    """
    修改配置文件中的值,将传入参数的值持久化到配置文件当中。
    """
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(file_name):
        #如果文件不存在，则创建
        ini_file = open(file_name, 'w')
        ini_file.close()
        logger.info("write_data.default.ini doesn't exist,file is %s." % file_name)
    try:
        cf.read(file_name)
        if not cf.has_section(section):
            cf.add_section(section)
        cf.set(section, key, value)
        with open(file_name, 'w') as fd:
            cf.write(fd)
        return True
    except :
        logger.error("write data file. Exception, e:%s" % traceback.format_exc())
        return False

def get_file_write_data(file_name, section, key):
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(file_name):
        return None
    try:
        cf.read(file_name)
        if not cf.has_section(section):
            return None
        if not cf.has_option(section, key):
            return None
        value = cf.get(section, key)
        return  value
    except Exception, err:
        logger.error("write data file. Exception, e:%s, err:%s." % (traceback.format_exc(), err))
        return None
