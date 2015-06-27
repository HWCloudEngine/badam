#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser

import os
import sys
import traceback
import cps_server
import fs_keystone_server
import fs_log_util
import fs_neutron_constant
from fs_neutron_util import NeutronUtil
from openstack_language import VXLAN_INPUT, NETWORK_TYPE_INPUT, SECURITY_INPUT, SECURITY_TIP, VM_SECURITY_INPUT, INPUT_ERROR, CONFIG_DATA_OR_NOT, INTERNAL_ERROR, REFER_LOG_ERROR, SUCCESS_ERROR
from print_msg import PrintMessage
import fsutils as utils
from os.path import join


#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class Neutron():
    """
    neutron组件的部署，目前支持:设置mac_rang
    """

    def __init__(self):
        pass

    vm_security = None
    vxlan_flag = "y"


    def get_section_list(self):
        return [fs_neutron_constant.SECTION_NEUTRON_CONFIG]


    def get_file_path(self):
        return fs_neutron_constant.NEUTRON_INI_PATH


    def _vm_security_config(self):
        """
        网络安全组是否应用到虚拟机
        """
        config_flag = 'n'
        while 1:
            PrintMessage.print_msg(SECURITY_TIP, True)
            config_flag = raw_input(PrintMessage.get_msg(SECURITY_INPUT))
            if config_flag == '':
                config_flag = 'n'
            if config_flag == 'y' or config_flag == 'n':
                break
            PrintMessage.print_msg(INPUT_ERROR, True)
            continue

        if config_flag == 'y':
            while 1:
                vm_security_temp = raw_input(PrintMessage.get_msg_ex(VM_SECURITY_INPUT, self.vm_security))
                if vm_security_temp == "y" or vm_security_temp == "n":
                    self.vm_security = vm_security_temp
                    break
                elif vm_security_temp == "":
                    break
                else:
                    PrintMessage.print_msg(INPUT_ERROR, True)

    def _set_vxlan_flag(self):
        """
        是否启用vxlan功能
        """
        config_flag = 'n'
        while 1:
            config_flag = raw_input(PrintMessage.get_msg(NETWORK_TYPE_INPUT))
            if config_flag == '':
                config_flag = 'n'
            if config_flag == 'y' or config_flag == 'n':
                break
            PrintMessage.print_msg(INPUT_ERROR, True)
            continue

        if config_flag == 'y':
            while 1:
                vm_security_temp = raw_input(PrintMessage.get_msg_ex(VXLAN_INPUT, self.vxlan_flag))
                if vm_security_temp == "y" or vm_security_temp == "n":
                    self.vxlan_flag = vm_security_temp
                    break
                elif vm_security_temp == "":
                    break
                else:
                    PrintMessage.print_msg(INPUT_ERROR, True)

    def config(self, type_name):
        """
        openstack相关配置，目前支持的配置为：
        1.输入cloud_admin的密码
        2.输入dc_admin的密码
        3.虚拟机能否部署到管理节点
        4.网络安全组是否应用到虚拟机
        5.创建虚拟机mac池的范围
        """
        #在配置前先将前一次配置的值导入
        LOG.debug("config=%s."%type_name)

        data_list = [fs_neutron_constant.SECTION_NEUTRON_CONFIG_SECURITY, fs_neutron_constant.SECTION_NEUTRON_CONFIG_USE_VXLAN]
        data = NeutronUtil().neutron_get_data(fs_neutron_constant.SECTION_NEUTRON_CONFIG, data_list)
        if data is not None:
            self.vm_security = data[0]
            self.vxlan_flag = data[1]

        #网络安全组是否应用到虚拟机
        self._vm_security_config()
        #是否启用vxlan功能
        self._set_vxlan_flag()

        #与用户确认配置是否OK
        flag = self._confirm_data()
        return flag

    def _confirm_data(self):
        """
        咨询用户是否确认上述配置，若确认则返回True,若不确认则继续修改，若取消则直接退出。
        """
        while 1:
            continue_data = self._input_output(PrintMessage.get_msg(CONFIG_DATA_OR_NOT))
            if continue_data == "s" or continue_data == "":
                #确认配置，则把配置保存到default.ini中，进行数据持久化
                datas = {fs_neutron_constant.SECTION_NEUTRON_CONFIG_SECURITY: self.vm_security,
                         fs_neutron_constant.SECTION_NEUTRON_CONFIG_USE_VXLAN: self.vxlan_flag}
                flag = NeutronUtil().neutron_write_data(fs_neutron_constant.SECTION_NEUTRON_CONFIG, datas)
                if not flag:
                    LOG.error("fail to process file.")
                    PrintMessage.print_msg(INTERNAL_ERROR, True)
                    sys.exit(0)
                return True
            elif continue_data == "c":
                #取消配置
                return False
            else:
                PrintMessage.print_msg(INPUT_ERROR, True)

    def create_def_config(self, cf):
        """
        快速部署时调用，将数据写入default.ini中
        """
        datas = {fs_neutron_constant.SECTION_NEUTRON_CONFIG_SECURITY: "y",
                 fs_neutron_constant.SECTION_NEUTRON_CONFIG_USE_VXLAN: "y"}
        flag = NeutronUtil().neutron_write_data(fs_neutron_constant.SECTION_NEUTRON_CONFIG, datas)
        if not flag:
            LOG.error("fail to process file.")
            PrintMessage.print_msg(INTERNAL_ERROR, True)
            sys.exit(0)

    def _security_groups_validate(self, cf):
        """
        处理网络安全组是否应用到虚拟机。
        """
        security_group_or_not = cf.get(fs_neutron_constant.SECTION_NEUTRON_CONFIG, fs_neutron_constant.SECTION_NEUTRON_CONFIG_SECURITY)

        if security_group_or_not == 'y':
            #打开网络安全组
            if not NeutronUtil().open_security_group(cf):
                PrintMessage.print_msg_ex(REFER_LOG_ERROR, "open security group")
                sys.exit(1)
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "open security group")
        elif security_group_or_not == 'n':
            #关闭网络安全组
            if not NeutronUtil().close_security_group(cf):
                PrintMessage.print_msg_ex(REFER_LOG_ERROR, "close security group")
                sys.exit(1)
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "close security group")

    def _vxlan_flag_validate(self, cf):
        """
        处理vxlan是否使用的功能
        """
        vxlan_flag = cf.get(fs_neutron_constant.SECTION_NEUTRON_CONFIG, fs_neutron_constant.SECTION_NEUTRON_CONFIG_USE_VXLAN)
        if vxlan_flag == 'y':
            #打开vxlan功能
            if not NeutronUtil().open_vxlan_flag(cf):
                PrintMessage.print_msg_ex(REFER_LOG_ERROR, "open vxlan flag")
                sys.exit(1)
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "open vxlan flag")
        elif vxlan_flag == 'n':
            #关闭vxlan功能
            if not NeutronUtil().close_vxlan_flag(cf):
                PrintMessage.print_msg_ex(REFER_LOG_ERROR, "close vxlan flag")
                sys.exit(1)
            PrintMessage.print_msg_ex(SUCCESS_ERROR, "close vxlan flag")


    def validate(self, type, phase):
        """
        将配置文件中的值生效。主要做如下处理：
        3.处理网络安全组是否应用
        4.创建虚拟机mac池的范围
        @type：阶段，目前应该都为3.1."deploy"2."deploy & config"3."config"
        """
        LOG.info("Begin to validate neutron.type is %s,phase is %s." % (str(type), str(phase)))
        #只有需要修改mac_rang时才需要修改密码

        try:
            cf = ConfigParser.ConfigParser()
            if not os.path.exists(fs_neutron_constant.NEUTRON_INI_PATH):
                #若配置文件不存在，则直接退出
                LOG.error("default.ini doesn't exist,file is %s." % fs_neutron_constant.NEUTRON_INI_PATH)
                PrintMessage.print_msg(INTERNAL_ERROR, True)
                sys.exit(0)
            else:
                cf.read(fs_neutron_constant.NEUTRON_INI_PATH)

            if type == utils.TYPE_ONLY_CONFIG:
                self._security_groups_validate(cf)
                self._vxlan_flag_validate(cf)
                flag = cps_server.cps_commit()
                if not flag:
                    PrintMessage.print_msg(INTERNAL_ERROR, True)
                    sys.exit(0)

            #否则，将配置文件中的配置生效
            if type == utils.TYPE_ONLY_DEPLOY and phase == utils.PHASE_POST:
                self._security_groups_validate(cf)
                self._vxlan_flag_validate(cf)
                flag = cps_server.cps_commit()
                if not flag:
                    PrintMessage.print_msg(INTERNAL_ERROR, True)
                    sys.exit(0)

        except fs_keystone_server.PasswordException:
            #对于密码错误的情况，直接将该异常抛给框架
            raise fs_keystone_server.PasswordException("quit due to 3 failed password")
        except Exception:
            LOG.error("fail to validate.traceback:%s" % traceback.format_exc())
            PrintMessage.print_msg(INTERNAL_ERROR, True)
            sys.exit(0)
        LOG.info("End to validate openstack.type is %s,phase is %s." % (str(type), str(phase)))


    def _input_output(self, input_msg):
        """
        界面交互函数。
        @param input_msg:例如【“test”，“你好”】
        @return：用户的输入
        """
        output_msg = raw_input(input_msg)
        return output_msg