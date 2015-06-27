#!/usr/bin/env python
#coding:utf-8
import fs_log_util
import os
import time
from os.path import join
import cps_server
import fs_keystone_server
from change_auth_mode import ChangeAuthMode as ChangeAuthMode

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class ChangeAuthModeUtil():

    def __init__(self):
        self.auth_mode = ChangeAuthMode()


    def in_auth_mode_close_cps_token(self):
        result = True
        if self.auth_mode.is_auth_mode() == "y":
            token = fs_keystone_server.keystone_get_cloud_token()
            print ""
            print "You have open system service auth mode, and want to modify network or certification, so we will close it."
            print "After you modify, you need to open it again."
            result = self.__close_cps_token(token)
            if not result:
                print "Close system service auth mode failed, please check."
                return False

            #等待服务正常
            sleep_time = 0
            while 1:
                time.sleep(10)
                sleep_time += 5
                if cps_server.Cps_work_bean().is_cps_work():
                    time.sleep(10)
                    if cps_server.Cps_work_bean().is_cps_work():
                        print "Succeed to change system service auth mode!"
                        break
                if sleep_time > 100:
                    print "Fail to change system service auth mode!Cps cli can not use."
                    result = False
                    break
            print ""

        return result

    def __close_cps_token(self, token=None):
        #result 结果成功与否
        #needWait 是否有 "y" 变成 "n"，需要进行等待
        result = True
        result = self.auth_mode.open_close_token(False, token)
        if not result:
            return False

        result = self.auth_mode.commit(False, token)
        if not result:
            return False
        return True

