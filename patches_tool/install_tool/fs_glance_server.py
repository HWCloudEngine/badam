#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import os
from os.path import join
import sys
from fs_glance_constant import GLANCE_INI_PATH, SECTION_GLANCE_PUBLIC, SECTION_GLANCE, SECTION_GLANCE_INTERNAL, SECTION_GLANCE_ADMIN, SECTION_GLANCE_GLOBAL_PUBLIC, SECTION_GLANCE_GLOBAL_INTERNAL, SECTION_GLANCE_GLOBAL_ADMIN, SECTION_GLANCE_ADDRESS, SECTION_GLANCE_GLOBAL_ADDRESS
import fs_log_util
from print_msg import PrintMessage, INTERNAL_ERROR

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


def glance_get_s3_public_url():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(GLANCE_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)
        PrintMessage.print_msg(INTERNAL_ERROR, True)
        sys.exit(0)
    else:
        cf.read(GLANCE_INI_PATH)
        if not cf.has_section(SECTION_GLANCE):
            return ""
        url = cf.get(SECTION_GLANCE, SECTION_GLANCE_PUBLIC)
        return url


def glance_get_s3_admin_url():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(GLANCE_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)
        PrintMessage.print_msg(INTERNAL_ERROR, True)
        sys.exit(0)
    else:
        cf.read(GLANCE_INI_PATH)
        if not cf.has_section(SECTION_GLANCE):
            return ""
        url = cf.get(SECTION_GLANCE, SECTION_GLANCE_ADMIN)
        return url


def glance_get_s3_internal_url():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(GLANCE_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)
        PrintMessage.print_msg(INTERNAL_ERROR, True)
        sys.exit(0)
    else:
        cf.read(GLANCE_INI_PATH)
        if not cf.has_section(SECTION_GLANCE):
            return ""
        url = cf.get(SECTION_GLANCE, SECTION_GLANCE_INTERNAL)
        return url


def glance_get_global_s3_public_url():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(GLANCE_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)
        PrintMessage.print_msg(INTERNAL_ERROR, True)
        sys.exit(0)
    else:
        cf.read(GLANCE_INI_PATH)
        if not cf.has_section(SECTION_GLANCE):
            return ""
        url = cf.get(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_PUBLIC)
        return url


def glance_get_global_s3_admin_url():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(GLANCE_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)
        PrintMessage.print_msg(INTERNAL_ERROR, True)
        sys.exit(0)
    else:
        cf.read(GLANCE_INI_PATH)
        if not cf.has_section(SECTION_GLANCE):
            return ""
        url = cf.get(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_ADMIN)
        return url


def glance_get_global_s3_internal_url():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(GLANCE_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)
        PrintMessage.print_msg(INTERNAL_ERROR, True)
        sys.exit(0)
    else:
        cf.read(GLANCE_INI_PATH)
        if not cf.has_option(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_INTERNAL):
            return None
        url = cf.get(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_INTERNAL)
        return url


def glance_get_global_s3_address():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(GLANCE_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)
        return None
    else:
        cf.read(GLANCE_INI_PATH)
        if not cf.has_option(SECTION_GLANCE,SECTION_GLANCE_GLOBAL_ADDRESS):
            return None
        url = cf.get(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_ADDRESS)
        return url

def glance_get_s3_address():
    cf = ConfigParser.ConfigParser()
    if not os.path.exists(GLANCE_INI_PATH):
        #若配置文件不存在，则直接退出
        LOG.error("default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

        return None
    else:
        cf.read(GLANCE_INI_PATH)
        if not cf.has_option(SECTION_GLANCE, SECTION_GLANCE_ADDRESS):
            return ""
        url = cf.get(SECTION_GLANCE, SECTION_GLANCE_ADDRESS)
        return url


def glance_set_global_s3_address(global_s3_address):
    if not os.path.exists(GLANCE_INI_PATH):
        #如果文件不存在，则创建
        ini_file = open(GLANCE_INI_PATH, 'w')
        ini_file.close()
        LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)
    config = ConfigParser.ConfigParser()
    config.read(GLANCE_INI_PATH)
    if not config.has_section(SECTION_GLANCE):
        config.add_section(SECTION_GLANCE)
    config.set(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_ADDRESS, global_s3_address)
    with open(GLANCE_INI_PATH, 'w') as fd:
        config.write(fd)


def glance_set_global_s3_internal_url(global_s3_internal):
    if not os.path.exists(GLANCE_INI_PATH):
        #如果文件不存在，则创建
        ini_file = open(GLANCE_INI_PATH, 'w')
        ini_file.close()
        LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

    config = ConfigParser.ConfigParser()
    config.read(GLANCE_INI_PATH)
    if not config.has_section(SECTION_GLANCE):
        config.add_section(SECTION_GLANCE)
    config.set(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_INTERNAL, global_s3_internal)
    with open(GLANCE_INI_PATH, 'w') as fd:
        config.write(fd)


def glance_set_global_s3_admin_url(global_s3_admin):
    if not os.path.exists(GLANCE_INI_PATH):
        #如果文件不存在，则创建
        ini_file = open(GLANCE_INI_PATH, 'w')
        ini_file.close()
        LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

    config = ConfigParser.ConfigParser()
    config.read(GLANCE_INI_PATH)
    if not config.has_section(SECTION_GLANCE):
        config.add_section(SECTION_GLANCE)
    config.set(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_ADMIN, global_s3_admin)
    with open(GLANCE_INI_PATH, 'w') as fd:
        config.write(fd)


def glance_set_global_s3_public_url(global_s3_public):
    if not os.path.exists(GLANCE_INI_PATH):
        #如果文件不存在，则创建
        ini_file = open(GLANCE_INI_PATH, 'w')
        ini_file.close()
        LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

    config = ConfigParser.ConfigParser()
    config.read(GLANCE_INI_PATH)
    if not config.has_section(SECTION_GLANCE):
        config.add_section(SECTION_GLANCE)
    config.set(SECTION_GLANCE, SECTION_GLANCE_GLOBAL_PUBLIC, global_s3_public)
    with open(GLANCE_INI_PATH, 'w') as fd:
        config.write(fd)


def glance_set_s3_public_url(s3_public):
    if not os.path.exists(GLANCE_INI_PATH):
        #如果文件不存在，则创建
        ini_file = open(GLANCE_INI_PATH, 'w')
        ini_file.close()
        LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

    config = ConfigParser.ConfigParser()
    config.read(GLANCE_INI_PATH)
    if not config.has_section(SECTION_GLANCE):
        config.add_section(SECTION_GLANCE)
    config.set(SECTION_GLANCE, SECTION_GLANCE_PUBLIC, s3_public)
    with open(GLANCE_INI_PATH, 'w') as fd:
        config.write(fd)


def glance_set_s3_admin_url(s3_admin):
    if not os.path.exists(GLANCE_INI_PATH):
        #如果文件不存在，则创建
        ini_file = open(GLANCE_INI_PATH, 'w')
        ini_file.close()
        LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

    config = ConfigParser.ConfigParser()
    config.read(GLANCE_INI_PATH)
    if not config.has_section(SECTION_GLANCE):
        config.add_section(SECTION_GLANCE)
    config.set(SECTION_GLANCE, SECTION_GLANCE_ADMIN, s3_admin)
    with open(GLANCE_INI_PATH, 'w') as fd:
        config.write(fd)


def glance_set_s3_internal_url(s3_internal):
    if not os.path.exists(GLANCE_INI_PATH):
        #如果文件不存在，则创建
        ini_file = open(GLANCE_INI_PATH, 'w')
        ini_file.close()
        LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

    config = ConfigParser.ConfigParser()
    config.read(GLANCE_INI_PATH)
    if not config.has_section(SECTION_GLANCE):
        config.add_section(SECTION_GLANCE)
    config.set(SECTION_GLANCE, SECTION_GLANCE_INTERNAL, s3_internal)
    with open(GLANCE_INI_PATH, 'w') as fd:
        config.write(fd)


def glance_set_s3_address(s3_address):
    if not os.path.exists(GLANCE_INI_PATH):
        #如果文件不存在，则创建
        ini_file = open(GLANCE_INI_PATH, 'w')
        ini_file.close()
        LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

    config = ConfigParser.ConfigParser()
    config.read(GLANCE_INI_PATH)
    if not config.has_section(SECTION_GLANCE):
        config.add_section(SECTION_GLANCE)
    config.set(SECTION_GLANCE, SECTION_GLANCE_ADDRESS, s3_address)
    with open(GLANCE_INI_PATH, 'w') as fd:
        config.write(fd)


