#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import json
import os
import cps_server
import fs_log_util
import traceback
import sys
from os.path import join

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
MODE_PATH = join(CURRENT_PATH, 'modes')
#日志定义
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)
mode_dict = None

class Cps_check_modes_bean():
    def __int__(self):
        pass

    def check_modes_bean(self):
        key = ""
        try:
            host_list = cps_server.cps_host_list()["hosts"]
            all_modes = get_modes()
            for key, value in all_modes.iteritems():
                ctrl_hosts = is_this_env_mode(value, host_list)
                if not ctrl_hosts is None:
                    return (value, ctrl_hosts)
            return (None, None)
        except:
            logger.error("check_modes failed %s key=%s." % (traceback.format_exc(), key))
            return (None, None)


def check_modes():
    sys.path.append("/usr/bin/install_tool")
    module = __import__("fs_modes")
    instance = getattr(module, "Cps_check_modes_bean")()
    return instance.check_modes_bean()

def check_modes_not_bean():
    key = ""
    try:
        host_list = cps_server.cps_host_list()["hosts"]
        all_modes = get_modes()
        for key, value in all_modes.iteritems():
            ctrl_hosts = is_this_env_mode(value, host_list)
            if not ctrl_hosts is None:
                return (value, ctrl_hosts)
        return (None, None)
    except:
        logger.error("check_modes failed %s key %s." % (traceback.format_exc(), key))
        return (None, None)



def is_this_env_mode(check_mode, host_list):
    manage_list = check_mode.get_manage_role()
    manage_number = int(check_mode.get_control_number())
    ctrl_hosts = []
    for host_info in host_list:
        if set(manage_list).issubset(set(host_info["roles"])):
            ctrl_hosts.append(host_info["id"])
    if manage_number == len(ctrl_hosts):
        return ctrl_hosts
    return None


def get_name_dict():
    file_list = os.listdir(MODE_PATH)
    mode_dict_temp = {}
    i = 0
    for file_path in file_list:
        i += 1
        mode_temp = Mode(join(MODE_PATH, file_path))
        mode_dict_temp[str(i)] = mode_temp.get_name()
    return mode_dict_temp


def get_modes():
    global mode_dict
    if mode_dict is None:
        mode_dict = create_modes()
    return mode_dict


def get_mode_by_name(mode_name):
    mode_dict_temp = get_modes()
    if mode_name in mode_dict_temp:
        return mode_dict_temp[mode_name]
    return None


def create_modes():
    file_list = os.listdir(MODE_PATH)
    mode_dict_temp = {}
    for file_path in file_list:
        if ".svn" == file_path:
            continue
        mode_temp = Mode(join(MODE_PATH, file_path))
        mode_dict_temp[mode_temp.get_name()] = mode_temp
    return mode_dict_temp


class Mode():
    def __init__(self, file_path):
        self.file_path = file_path
        self.config = ConfigParser.RawConfigParser()
        self.config.read(self.file_path)

    def get_name(self):
        return self.config.get('mode', 'name')

    def get_control_number(self):
        return self.config.get('mode', 'control_number')

    def get_manage_role(self):
        return json.loads(self.config.get('mode', 'manage_role'))

    def get_balance_role(self):
        return json.loads(self.config.get('mode', 'balance_role'))

    def get_agent_role(self):
        return json.loads(self.config.get('mode', 'agent_role'))

    def get_special_template(self):
        return json.loads(self.config.get('mode', 'special_template'))

    def get_necessary_role(self):
        return json.loads(self.config.get('mode', 'necessary_role'))