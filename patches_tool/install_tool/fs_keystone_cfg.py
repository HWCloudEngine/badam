#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import os
import sys
import traceback
import fs_keystone_constant
import time
import fs_keystone_server
import fs_system_server
from fs_keystone_util import KeystoneUtil
import fs_log_util
from openstack_language import INTERNAL_ERROR, SUCCESS_ERROR, CPS_COMMIT_SUCCESS
from print_msg import PrintMessage
import fsutils as utils
from os.path import join
from fs_proxy_cfg import OpenStackProxyCfgProc

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')

LOG = fs_log_util.localLog.get_logger(LOG_FILE)

class Keystone():
    """
    处理keystone相关的配置。目前支持创建endpoints
    """

    cloud_password = None
    endpoints_https = None
    url_http_type = None

    def __init__(self):
        self.proxy_cfg = OpenStackProxyCfgProc()
        self.validate_phase = ""
        pass


    def get_section_list(self):
        return [fs_keystone_constant.SECTION_KEYSTONE_CONFIG, fs_keystone_constant.HTTP_MODE,
                fs_keystone_constant.HAPROXY_CONFIG_SECTION, fs_keystone_constant.APACHEPROXY_CONFIG_SECTION]


    def get_file_path(self):
        return fs_keystone_constant.KEYSTONE_INI_PATH


    def _cloud_password_config(self):
        """
        将界面输入的cloud_password保存。
        """
        self.cloud_password = fs_keystone_server.keystone_get_cloud_password()

    def get_http_type(self):
        http_type = None
        cf = ConfigParser.ConfigParser()
        cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        if cf.has_section("http_mode"):
            if cf.has_option("http_mode","url_http_type"):
                http_type = cf.get("http_mode", "url_http_type")
                
        if http_type is None:
            self.url_http_type = "https"
        else:
            self.url_http_type = http_type
        return self.url_http_type

    def _write_http_mode(self,section):
        cf = ConfigParser.ConfigParser()
        if not os.path.exists(fs_keystone_constant.KEYSTONE_INI_PATH):
            #如果文件不存在，则创建
            ini_file = open(fs_keystone_constant.KEYSTONE_INI_PATH, 'w')
            ini_file.close()
            LOG.debug("write_data.default.ini doesn't exist,file is %s." % fs_keystone_constant.KEYSTONE_INI_PATH)
        try:
            cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)
            if not cf.has_section(section):
                cf.add_section(section)
            cf.set(section, "url_http_type", self.url_http_type)
            cf.write(open(fs_keystone_constant.KEYSTONE_INI_PATH, "w"))
            return True
        except Exception:
            LOG.error("write data file. Exception, e:%s" % traceback.format_exc())
            return False

    def _choose_item(self):
        try:

            self.get_http_type()
            while True:
                PrintMessage.print_msg(["Please choose the items as bellow:", "please choose the items as bellow:"])
                PrintMessage.print_msg(["[1] Haproxy","[1] Haproxy"])
                PrintMessage.print_msg(["[2] Apache proxy","[2] Apache proxy"])
                PrintMessage.print_msg(["[3] Endpoint","[3] Endpoint"])
                PrintMessage.print_msg(["[s] Save&quit","[s] Save&quit"])
                inputstr = PrintMessage.get_msg(["Please input", "Please input"]) + ":[1|2|3|s][s]"
                item = raw_input(inputstr)
                if item == '1':
                    self.proxy_cfg.config_haproxy()
                    continue
                elif item == '2':
                    self.proxy_cfg.config_apacheproxy()
                elif item == '3':
                    ret = self.http_mode_config()
                    if not ret:
                        PrintMessage.print_msg(["Error occurs or you cancel the action,please check ------","error occurs,please check"])
                    continue
                elif item == 's' or item == '':
                    break
                else:
                    PrintMessage.print_msg(["Error input","error input"])
                    continue
        except Exception:
            LOG.error("fail to process.traceback:%s" % traceback.format_exc())
            PrintMessage.print_msg(INTERNAL_ERROR, True) 
            return False
        return True
     
    def http_mode_config(self):
        if self.url_http_type is None:
            self.url_http_type = "https"
        while True:
            inputstr = PrintMessage.get_msg(["please input", "please input"]) + ":[https|http][%s]" % self.url_http_type
            mode = raw_input(inputstr)
            if mode == '':
                mode = self.url_http_type 
            if mode == "https":
                self.url_http_type = mode
                msg_show_str = "http type is %s." % self.url_http_type
                PrintMessage.print_msg([msg_show_str, msg_show_str])
                ret = self.save_http_mode_config() 
                return ret               
            elif mode == "http": 
                PrintMessage.print_msg(["http is not supported temporarily,please use https.","http is not supported temporarily,please use https."])
                continue
            else:
                PrintMessage.print_msg(["error input.please check.","error input,please check."])
                continue


    def save_http_mode_config(self):     
        try:
            self._write_http_mode("http_mode")            
        except :
            print "do action failed!"
            LOG.error("Choose_section failed: %s" % traceback.format_exc())
            return False
        return True

    
    def config(self, install_type):
        """
        keystone相关配置，目前支持的配置为：
        1.输入cloud_admin的密码
        2.输入dc_admin的密码
        3.虚拟机能否部署到管理节点
        4.网络安全组是否应用到虚拟机
        5.创建虚拟机mac池的范围
        """
        #选择是否endpoints用http还是https      
	
        ret_flag = self._choose_item()
        return ret_flag

    def create_def_config(self, cf):
        """
        快速部署时调用，将endpoints_https数据写入default.ini中
        """
        flag = KeystoneUtil().keystone_write_data("http_mode","url_http_type","https")
        if not flag:
            LOG.error("fail to process file.cf=%s"%cf)
            PrintMessage.print_msg(INTERNAL_ERROR, True)
            sys.exit(0)
            
    def validate(self, validate_type, phase):
        #这个只是生成 endpoint就可以。 相关的haproxy apache proxy 不需要关系
        time.sleep(2)
        LOG.info("validate=%s"%validate_type)
        self.validate_phase = phase
        self.validate_http_mode()

    def validate_http_mode(self, waitTime=9):
        if fs_system_server.is_connection_work():
            waitTime = 4
        else:
            timeAll  = waitTime * 10
            print "Waitting about %s seconds to check network status."%timeAll
        times = 0
        while times < waitTime:
            if fs_system_server.is_connection_work():
                ret_code = self.do_action(utils.TYPE_ONLY_CONFIG, "")
                if ret_code:
                    return True 
                else:
                    time.sleep(5)
            else:
                time.sleep(10)
            times = times + 1
        print "Notice:Network is not available,endpoint config would not take effect."
        is_https_type = fs_system_server.system_is_keystone_https() 
        if is_https_type:
            self.url_http_type = "https"
        else:
            self.url_http_type = "http"
        self.save_http_mode_config()
        return False

    def do_action(self, install_type, phase):
        LOG.info("Begin to validate keystone.type is %s,phase is %s." % (str(type), str(phase)))
        #输入cloud_admin的密码
        try:
            self._cloud_password_config()
            cf = ConfigParser.ConfigParser()
            if not os.path.exists(fs_keystone_constant.KEYSTONE_INI_PATH):
                #若配置文件不存在，则直接退出
                LOG.error("default.ini doesn't exist,file is %s." % fs_keystone_constant.KEYSTONE_INI_PATH)
                PrintMessage.print_msg(INTERNAL_ERROR, True)
                sys.exit(0)
            else:
                cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)

            if install_type == utils.TYPE_ONLY_CONFIG:
                self._endpoint_validate(cf)
                PrintMessage.print_msg_ex(CPS_COMMIT_SUCCESS, "keystone")

            #否则，将配置文件中的配置生效
            if install_type == utils.TYPE_ONLY_DEPLOY and phase == utils.PHASE_POST:
                self._endpoint_validate(cf)
                PrintMessage.print_msg_ex(CPS_COMMIT_SUCCESS, "keystone")

        except fs_keystone_server.PasswordException:
            #对于密码错误的情况，直接将该异常抛给框架
            print "Fail to set endpoints,Please confirm your password and network is ok!"
            sys.exit(1)
        except:
            LOG.error("fail to validate.traceback:%s" % traceback.format_exc())
            return False
        LOG.info("End to validate keystone.type is %s,phase is %s." % (str(install_type), str(phase)))
        return True

    def _endpoint_validate(self, cf):
        """
        创建endpoint.
        @return False:可能是密码输错，提示通行输入或联系维护人员；True：继续
        """
        #获取token,创建endpoint需要
        password = self.cloud_password
        def_cloud_admin_token = KeystoneUtil().keystone_get_token("cloud_admin", password, "admin", cf)

        if def_cloud_admin_token is None:
            LOG.error("Fail to get token!")
            sys.exit(1)

        #创建endpoint
        if not KeystoneUtil().keystone_create_endpoints(cf, def_cloud_admin_token, self.validate_phase):
            LOG.error("Fail to set endpoints,Please confirm your network is ok!")
            sys.exit(1)
        PrintMessage.print_msg_ex(SUCCESS_ERROR, "endpoints")

    def _input_output(self, input_msg):
        """
        界面交互函数。
        @param input_msg:例如【“test”，“你好”】
        @return：用户的输入
        """
        output_msg = raw_input(input_msg)
        return output_msg
