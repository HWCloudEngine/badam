#!/usr/bin/env python
#-*-coding:utf-8-*-

import os
import ConfigParser
from os.path import join
from fs_keystone_constant import CLOUD_USER, CLOUD_TENANT
import fs_keystone_constant
import fs_keystone_endpoint
import fs_keystone_util
import fs_log_util
from print_msg import PrintMessage, INTERNAL_ERROR


#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class PasswordException(Exception):
    """
    密码错误的异常
    """
    pass


def keystone_get_cloud_password():
    """
    获取dc的密码，若第一次获取，则会提供交互式界面让用户设定密码。
    否则：若缓存中不存在数据则提供交互式命令让用户输入；不然直接将缓存中值返回给用户。
    若连续输入3次密码错误，则抛异常PasswordException
    """
    return fs_keystone_util.KeystoneUtil().get_cloud_password()


def keystone_get_dc_password():
    """
    获取cloud_admin的密码。
    若缓存中存在则直接返回；否则提供交互式界面让用户输入。
    """
    return fs_keystone_util.KeystoneUtil().get_dc_password()


def keystone_get_cloud_token(cf=None):
    """
    提供对外服务，获取token,用cloud_admin的用户获取token。
    @param cf:读取default_sys.ini，若不传入则会重新获取一次
    @return:返回token
    """
    if cf is None:
        cf = ConfigParser.ConfigParser()
        if not os.path.exists(fs_keystone_constant.KEYSTONE_INI_PATH):
            #若配置文件不存在，则直接退出
            LOG.error("default.ini doesn't exist,file is %s." % fs_keystone_constant.KEYSTONE_INI_PATH)
        else:
            cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)

    return fs_keystone_util.KeystoneUtil().keystone_get_token(CLOUD_USER, keystone_get_cloud_password(), CLOUD_TENANT, cf)

def keystone_get_cloud_admin_token_for_cps():
    #将token缓存到内存用，用于 cps 命令的性能优化
    return fs_keystone_util.KeystoneUtil().keystone_get_cloud_admin_token()

def keystone_set_cloud_admin_token_for_cps():
    #将token缓存到内存用，用于 cps 命令的性能优化，当token失效的时候，从新将token置空
    fs_keystone_util.KeystoneUtil().keystone_set_cloud_admin_token()



def keystone_get_dc_token(cf=None):
    """
    提供对外服务，获取token，用dz_admin的用户获取token。
    @param cf:读取default_sys.ini，若不传入则会重新获取一次
    @return:返回token
    """
    if cf is None:
        cf = ConfigParser.ConfigParser()
        if not os.path.exists(fs_keystone_constant.KEYSTONE_INI_PATH):
            #若配置文件不存在，则直接退出
            LOG.error("default.ini doesn't exist,file is %s." % fs_keystone_constant.KEYSTONE_INI_PATH)
            PrintMessage.print_msg(INTERNAL_ERROR, True)
        else:
            cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)

    return fs_keystone_util.KeystoneUtil().keystone_get_token(fs_keystone_util.KeystoneUtil().get_dc_admin_name(),
                                                              keystone_get_dc_password(),
                                                              fs_keystone_util.KeystoneUtil().get_dc_sys_project(),
                                                              cf)


def keystone_get_endpoint(mode, cf=None):
    """
    提供对外服务，输入mode即可查询出对应的internal_url.
    @param mode:目前支持的字段可以参加openstack_endpoint.py,字段例如”cps“.
    @param cf:读取default_sys.ini，若不传入则会重新获取一次
    @return:对应的url，如输入的mode=nova,返回的则为nova的internal_url
    """
    if cf is None:
        cf = ConfigParser.ConfigParser()
        if not os.path.exists(fs_keystone_constant.KEYSTONE_INI_PATH):
            #若配置文件不存在，则直接退出
            LOG.error("default.ini doesn't exist,file is %s." % fs_keystone_constant.KEYSTONE_INI_PATH)
            PrintMessage.print_msg(INTERNAL_ERROR, True)
        else:
            cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)
    return fs_keystone_endpoint.calc_endpoint(cf, mode)


def keystone_get_dc_admin_name():
    return fs_keystone_util.KeystoneUtil().get_dc_admin_name()


def keystone_get_dc_net_project():
    return fs_keystone_util.KeystoneUtil().get_dc_net_project()


def keystone_build_dc_admin():
    return fs_keystone_util.KeystoneUtil().build_dc_admin()


def keystone_get_dc_sys_project():
    return fs_keystone_util.KeystoneUtil().get_dc_sys_project()