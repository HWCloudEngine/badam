#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import os
import time
import sys
import traceback
from fs_glance_constant import GLANCE_INI_PATH, SECTION_GLANCE, SECTION_GLANCE_GLANCE_STORE
import fs_log_util
import cps_server
import fsutils as utils
from os.path import join
from fs_system_server import system_get_local_domain

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class GlanceConfig():
    def __init__(self):
        self.glance_type_file = 'File'
        self.glance_type_uds = 'Uds'
        self.glance_type_swift = 'Swift'
        local_dc, local_az, domain = system_get_local_domain()
        self.default_swift_address = "https://identity.%s.%s.%s:8023/identity-admin/v2.0" % (local_az, local_dc, domain)
        self.default_file_store_datedir = "/opt/HUAWEI/image/glance"
        self.default_s3_store_object_buffer_dir = "/opt/HUAWEI/image/udsTempDir"
        self.def_glance_default_store = self.glance_type_swift


    def get_section_list(self):
        return [SECTION_GLANCE]


    def get_file_path(self):
        return GLANCE_INI_PATH


    def input_glance_store(self, glance_type_file, glance_type_uds, glance_type_swift):
        while 1:
            try:
                glance_default_store = "s"
                print "[1] %s" % glance_type_file
                print "[2] %s" % glance_type_uds
                print "[3] %s" % glance_type_swift
                print "[s] save&quit"
                inputstr = "please set default backend store for glance [1-3|s][s] : "
                glance_default_store = raw_input(inputstr)
                if glance_default_store == "" or glance_default_store == 's':
                    break
                elif glance_default_store != glance_type_uds and glance_default_store != glance_type_file and glance_default_store != glance_type_swift:
                    print "please input correct character,only support file or uds+https!"
                    continue
                else:
                    break
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "please input correct character,only support file or swift or uds+https!"
                LOG.error("failed: %s" % str(traceback.format_exc()))
                continue
        return glance_default_store

    def update_glance(self, cfg_date):
        flag = cps_server.update_template_params('glance', 'glance', cfg_date)
        return flag

    def save_uds(self, glance_default_store):
        config = ConfigParser.RawConfigParser()
        config.read(GLANCE_INI_PATH)
        config.set(SECTION_GLANCE, SECTION_GLANCE_GLANCE_STORE, glance_default_store)

        with open(GLANCE_INI_PATH, 'w') as fd:
            config.write(fd)

    def config_swift(self):
        while 1:
            if self.update_glance({"default_store": "swift"}):
                print "you have choosed swift mode."
                time.sleep(1)
                break
            else:
                print "Set swift_store_auth_address failed!"
                continue

    def config_file(self):
        while 1:
            inputstr = "Please set filesystem_store_datadir:[%s]" % self.default_file_store_datedir
            filesystem_store_datadir = raw_input(inputstr)
            if filesystem_store_datadir == '':
                filesystem_store_datadir = self.default_file_store_datedir
            if self.update_glance({"default_store": "file", "filesystem_store_datadir": filesystem_store_datadir}):
                break
            else:
                print "Set filesystem_store_datadir failed!"
                continue

    def config_uds(self):
        while 1:
            inputstr = "Please set s3_store_object_buffer_dir:[%s]" % self.default_s3_store_object_buffer_dir
            s3_store_object_buffer_dir = raw_input(inputstr)
            if s3_store_object_buffer_dir == '':
                s3_store_object_buffer_dir = self.default_s3_store_object_buffer_dir
            if self.update_glance(
                    {"default_store": "uds+https", "s3_store_object_buffer_dir": s3_store_object_buffer_dir}):
                break
            else:
                print "Set s3_store_object_buffer_dir failed!"
                continue

    def config(self, type_name):
        LOG.info("config type=%s."%type_name)
        while 1:
            try:
                glance_default_store = "s"
                print "[1] %s" % self.glance_type_swift
                print "[2] %s" % self.glance_type_file
                print "[3] %s" % self.glance_type_uds
                print "[s] Save&quit"
                inputstr = "Please set default backend store for glance [1-3|s][s] : "
                glance_default_store = raw_input(inputstr)
                if glance_default_store == "" or glance_default_store == 's':
                    break
                elif glance_default_store == '1':
                    self.config_swift()
                    continue
                elif glance_default_store == '2':
                    self.config_file()
                    continue
                elif glance_default_store == '3':
                    self.config_uds()
                    continue
                else:
                    print "Please input correct character,only support file or uds+https!"
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please input correct character,only support file or swift or uds+https!"
                LOG.error("Failed: %s" % str(traceback.format_exc()))
                continue

        self.save_uds(glance_default_store)
        return True

    def validate(self, type_name, phase):
        LOG.info("config type=%s phase =%s."%(type_name, phase))
        if type_name == utils.TYPE_ONLY_CONFIG:
            cps_server.cps_commit()

    def create_def_config(self, config):
        LOG.info("create_def_config type=%s."%config)
        if not os.path.exists(GLANCE_INI_PATH):
            #如果文件不存在，则创建
            ini_file = open(GLANCE_INI_PATH, 'w')
            ini_file.close()
            LOG.debug("write_data.default.ini doesn't exist,file is %s." % GLANCE_INI_PATH)

        config = ConfigParser.RawConfigParser()
        config.read(GLANCE_INI_PATH)
        if not config.has_section(SECTION_GLANCE):
            config.add_section(SECTION_GLANCE)
        config.set(SECTION_GLANCE, SECTION_GLANCE_GLANCE_STORE, self.def_glance_default_store)
        with open(GLANCE_INI_PATH, 'w') as fd:
            config.write(fd)
