#!/usr/bin/env python
#-*-coding:utf-8-*-
import fs_system_server
import os
import sys
import traceback
import time
import fs_log_util
import cps_server
import fs_system_constant
import fs_system_util
import fs_keystone_constant
import fsinstall
from os.path import join
from fs_system_cfg import SysConfig
from fs_keystone_cfg import Keystone
from fs_proxy_cfg import OpenStackProxyCfgProc
from fs_network_cfg import NetwokCfgProc
from fs_system_network_config import  SystemNetworkConfig
from fs_system_timezone import Sys_timezone
from change_auth_mode_util import ChangeAuthModeUtil as ChangeAuthMode
import fs_keystone_util
#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class SystemConfig():
    def __init__(self):
        #配置项的实例 拆分
        self.syscfgitem = SysConfig()
        self.keystone = Keystone()
        self.proxy_cfg = OpenStackProxyCfgProc()
        self.cps_network = NetwokCfgProc()
        self.api_default = SystemNetworkConfig()
        self.timezone = Sys_timezone()

    def printmessage(self):
        print "[1] Reverse proxy"
        print "[2] Forward proxy"
        print "[3] Dns"
        print "[4] Default route"
        print "[5] Http Mode"
        print "[6] Ntp"
        print "[7] Uds"
        print "[8] System service auth mode"
        print "[9] Dc admin"
        print "[10]External api"
        print "[11]Internal base"
        print "[12]Keystone url"
        print "[13]Glance url"
        print "[s] Save&quit"

    def config(self, type_name):
        LOG.info( "into validate  type = %s."%type_name)
        while 1:
            self.printmessage()
            default_choose = 's'
            inputstr = "Please choose [1-13|s][%s]" % default_choose
            input_num = raw_input(inputstr)
            if input_num == '':
                input_num = default_choose
            if input_num == '1':
                if self.proxy_cfg.config_haproxy():
                    result = ChangeAuthMode().in_auth_mode_close_cps_token()
                    if not result:
                        print "Fail to change system service auth mode!"
                    else:
                        self.proxy_cfg.validate_haproxy()
                        cps_server.cps_commit()
                continue
            elif input_num == '2':
                if self.proxy_cfg.config_apacheproxy():
                    result = ChangeAuthMode().in_auth_mode_close_cps_token()
                    if not result:
                        print "Fail to change system service auth mode!"
                    else:
                        self.proxy_cfg.validate_apacheproxy()
                        cps_server.cps_commit()
                continue
            elif input_num == '3':
                self.syscfgitem.config_dns()
                result = ChangeAuthMode().in_auth_mode_close_cps_token()
                if not result:
                    print "Fail to change system service auth mode!"
                else:
                    self.syscfgitem.validate_dns()
                    cps_server.cps_commit()
                continue
            elif input_num == '4':
                self.api_default.config_default_route()
                self.api_default.default_gateway_validate()
                cps_server.cps_commit()
                continue
            elif input_num == '5':
                try :
                    self.keystone.http_mode_config()
                    ret_flag = self.keystone.validate_http_mode(9)
                    if ret_flag:
                        self.refresh_component_cfg()
                except KeyboardInterrupt:
                    raise KeyboardInterrupt()
                except:
                    LOG.info( "SYS:validate_http_mode occur exception:%s." %traceback.format_exc())
                continue
            elif input_num == '6':
                self.syscfgitem.config_ntp()
                self.syscfgitem.validate_ntp()
                cps_server.cps_commit()

            elif input_num == '7':
                self.syscfgitem.config_uds()
                self.syscfgitem.validate_uds()
                cps_server.cps_commit()
            elif input_num == '8':
                self.syscfgitem.config_safe_mode()
                if fs_system_server.is_connection_work():
                    self.syscfgitem.validate_auth_mode()
                else:
                    print "Notice:Network is not available,can not change system service auth mode."
            elif input_num == '9':
                self.syscfgitem.config_dc_admin()
            elif input_num == '10':
                self.api_default.config_external_api()
                self.api_default.validate_external_api()
            elif input_num == '11':
                self.api_default.config_internal_base()
                self.api_default.validate_internal_base_api()
            elif input_num == '12':
                self.syscfgitem.config_keystone_url()
                result = ChangeAuthMode().in_auth_mode_close_cps_token()
                if not result:
                    print "Fail to change system service auth mode!"
                else:
                    self.syscfgitem.validate_keystone_url()
                    cps_server.cps_commit()
                    self.wait_cps_take_effect()
            elif input_num == '13':
                self.syscfgitem.config_glance_url()
                self.syscfgitem.validate_glance_url()
                cps_server.cps_commit()

            elif input_num == 's':
                break

        fs_system_util.change_all_flag_list("false")
        return True

    def validate(self, type_name, phase):
        LOG.info( "into validate  type = %s, phase = %s."%(type_name, phase))
        flag = False

        if fs_system_util.is_section_change("Reverse proxy"):
            result = ChangeAuthMode().in_auth_mode_close_cps_token()
            if not result:
                print "Fail to change system service auth mode!"
                sys.exit(1)
        #1
        if  fs_system_util.is_section_change("Reverse proxy"):
            LOG.info("into validate Reverse proxy")
            flag = True
            self.proxy_cfg.validate_haproxy()

        #2
        if  fs_system_util.is_section_change("Forward proxy"):
            LOG.info( "into validate Forward proxy")
            flag = True
            self.proxy_cfg.validate_apacheproxy()
        #3
        if  fs_system_util.is_section_change("Dns"):
            LOG.info( "into validate Dns")
            flag = True
            self.syscfgitem.validate_dns()

        #4
        if  fs_system_util.is_section_change("Default route"):
            LOG.info( "into validate Default route")
            flag = True
            self.api_default.default_gateway_validate()

        #这里进行统一生效
        if flag:
            cps_server.cps_commit()
            #由于配置是异步生效，需要等待正反向代理ip生效，
            # 后面的配置需要确保能与keystone服务连通
            self.wait_for_connection_ok()
        #5
        if  fs_system_util.is_section_change("Http Mode"):
            LOG.info("into validate Http Mode")
            self.validate_http_mode_for_endpoint()

        #6
        if  fs_system_util.is_section_change("Ntp"):
            LOG.info( "into validate Ntp")
            self.timezone.validate(None, None)
            self.syscfgitem.validate_ntp()
            cps_server.cps_commit()
        #7
        if  fs_system_util.is_section_change("Uds"):
            LOG.info( "into validate Uds")
            self.syscfgitem.validate_uds()
            cps_server.cps_commit()
        #8
        if  fs_system_util.is_section_change("System service auth mode"):
            LOG.info( "into validate System service auth mode")
            self.syscfgitem.validate_auth_mode()
        #9
        if  fs_system_util.is_section_change("Dc admin"):
            LOG.info( "into validate Dc admin")
            self.syscfgitem.config_dc_admin()
        #10
        if  fs_system_util.is_section_change("External api"):
            LOG.info( "into validate External api")
            self.api_default.validate_external_api()
        #11
        if  fs_system_util.is_section_change("Internal base"):
            LOG.info( "into validate Internal base")
            self.api_default.validate_internal_base_api()

    def refresh_component_cfg(self):
        http_type = self.keystone.get_http_type()
        current_http_type = fs_keystone_util.KeystoneUtil().get_haproxy_http_type()
        is_https_type = fs_system_server.system_is_keystone_https()
        keystone_url = fs_system_server.system_get_keystone_domain()
        glance_url = fs_system_server.system_get_glance_domain()
        running_flag = True
        is_execute_falg = False
        try:
            if is_https_type and http_type == "http":
                print "Begin to update component config!"
                new_keystone_url = keystone_url.replace("https","http")
                new_glance_url = glance_url.replace("https","http")
                fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                               "keystone_domain", new_keystone_url)
                fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                               "glance_domain", new_glance_url)
                if fsinstall.update_component_cfg(True, True):
                    print "Succeed to update component config!"
                else:
                    running_flag = False
                is_execute_falg = True
            if not is_https_type and http_type == "https":
                print "Begin to update component config!"
                new_keystone_url = keystone_url.replace("http","https")
                new_glance_url = glance_url.replace("http","https")
                fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                               "keystone_domain", new_keystone_url)
                fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                               "glance_domain", new_glance_url)
                if fsinstall.update_component_cfg(True, True):
                    print "Succeed to update component config!"
                else:
                    running_flag = False        
                is_execute_falg = True
            if running_flag:
                if current_http_type == "https" and http_type == "http":
                    self.proxy_cfg.validate_haproxy()
                if current_http_type == "http" and http_type == "https":
                    self.proxy_cfg.validate_haproxy()
                cps_server.cps_commit()
            else:
                fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                               "keystone_domain", keystone_url)
                fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                               "glance_domain", glance_url)
            if is_execute_falg:
                self.wait_cps_take_effect()
                
        except:
            fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                             "keystone_domain", keystone_url)
            fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                             "glance_domain", glance_url)
 
    def wait_cps_take_effect(self):
        print "Check cps server status!"
        sleep_time = 0
        while True:
            time.sleep(10)
            sleep_time += 5
            if cps_server.Cps_work_bean().is_cps_work():
                time.sleep(10)
                if cps_server.Cps_work_bean().is_cps_work():
                    print "Cps server status is normal now!"
                    break
            if sleep_time > 100:
                print "please check cps server state.Cps cli can not use!"
                break


    def validate_http_mode_for_endpoint(self):
        LOG.info("into validate Http Mode")
        tryTime = 0
        while  tryTime < 2:
            LOG.info("SYS:into validate Http Mode, time = %s" %tryTime)
            failed = False
            try :
                self.keystone.validate_http_mode(18)
                if not fs_system_server.is_connection_work():
                    LOG.info("SYS:Network may be unreachable." )
                    failed = True
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                LOG.info( "SYS:validate_http_mode occur exception:%s." %traceback.format_exc())
                failed = True

            if failed:
                print "Network may be unreachable,please wait about 30 seconds."
                time.sleep(30)
                tryTime = tryTime + 1
            else:
                break

        if tryTime == 2 :
            print "Network may be unreachable,please check by yourself!"
            LOG.info("SYS:Network may be unreachable,please check by yourself!")
            sys.exit(1)


    def create_def_config(self, config):
        self.syscfgitem.create_def_config(config)


    def get_section_list(self):
        return [fs_system_constant.SECTION_SYS_CONFIG, fs_system_constant.SECTION_DNS_CONFIG,
                fs_system_constant.SECTION_AUTH_MODE_CONFIG,fs_system_constant.SECTION_NTP_CONFIG,
                fs_system_constant.SECTION_UDS_CONFIG,fs_keystone_constant.SECTION_KEYSTONE_CONFIG,
                fs_keystone_constant.HTTP_MODE,fs_keystone_constant.HAPROXY_CONFIG_SECTION,
                fs_keystone_constant.APACHEPROXY_CONFIG_SECTION, fs_system_constant.SECTION_TIMEZONE_CONFIG]


    def get_file_path(self):

        return fs_system_constant.SYSTEM_INI_PATH

    def wait_for_connection_ok(self):
        """
        由于配置之后是异步生效，需要等待正反向代理ip生效,确保能够与keystone连通
        默认等待连接的超时时间为30s左右
        """
        wait_time_str = os.getenv(fs_system_constant.PREINSTALL_WAIT_TIME_ENV,
                                  "40")
        wait_time = int(wait_time_str)
        current_retry_time = 0
        times = 0
        LOG.info("wait for connection to keystone url to work normally")
        while current_retry_time < wait_time:
            if fs_system_server.is_connection_work():
                LOG.info("connection to keystone url is OK!")
                break
            else:
                LOG.info("connection to keystone url is abnormal,"
                         "times=%s, retry to wait" % times)
                time.sleep(20)
                current_retry_time = current_retry_time + 20
                times = times + 1

        if current_retry_time >= wait_time:
            LOG.error("wait times is out, but connection to keystone url is"
                      " still abnormal")

