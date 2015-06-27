#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import os
import traceback
import fs_log_util
import cps_server
import fs_system_constant
from os.path import join
import fs_system_util

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)


class Sys_timezone():
    def __init__(self):
        self.timeZone  = "Asia/Beijing"

    def getTimeZoneList(self):
        fp = None
        zoneList = []
        try:
            fp = open(fs_system_constant.NTP_TIMEZONE_CONF)
            file_context = fp.readlines()
            for i in range(len(file_context)):
                temp = file_context[i].split("\r\n")
                zoneList.append(temp[0])
            return zoneList
        except Exception, e:
             logger.error("get Exception when reading file: e = %s, trace:%s" % (e, str(traceback.format_exc())))
             return None
        finally:
            if fp is not None:
                fp.close()

    def getUsedTimeZone(self):
        print ""


    def create_def_config(self, config):
        logger.info("create_def_config:%s."%config)
        

    def config(self, type_name):
        logger.info("type:%s."%type_name)
        timezoneList = self.getTimeZoneList()
        while 1 :
            inputstr = "Please set system time zone [%s]:"%self.timeZone
            inputTimeZone = raw_input(inputstr)
            if "" == inputTimeZone:
                break
            elif inputTimeZone in timezoneList:
                self.timeZone = inputTimeZone
                break
            else :
                print "Time zone should be in %s"%timezoneList

        fs_system_util.save_one_option(fs_system_constant.SECTION_TIMEZONE_CONFIG,
                                               fs_system_constant.SECTION_IMETZONE_KEY, self.timeZone)


    def validate(self, type, phase):
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        if config.has_option(fs_system_constant.SECTION_TIMEZONE_CONFIG,fs_system_constant.SECTION_IMETZONE_KEY):
            timeZone = config.get(fs_system_constant.SECTION_TIMEZONE_CONFIG,fs_system_constant.SECTION_IMETZONE_KEY)
            if cps_server.update_template_params("ntp", "ntp-client", {'timezone': timeZone}):
                print "Update timezone success."
            else:
                print "Update timezone failed,please check your data."


    def get_section_list(self):
        return [""]


    def get_file_path(self):

        return fs_system_constant.SYSTEM_INI_PATH

    def test(self):
        pass
