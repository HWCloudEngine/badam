#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join
import fs_log_util

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)
CHANGE_TYPE = "true"
NO_CHANGE_TYPE = "false"

CINDER_TYPE = "Cinder"
NOVA_TYPE = "Nova"


change_flag_list = {CINDER_TYPE : "false", NOVA_TYPE : "false"}
disk_check_time = 5


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


def get_disk_check_time():
    global disk_check_time
    return disk_check_time

def set_disk_check_time(checkTime):
    global disk_check_time
    disk_check_time = checkTime



