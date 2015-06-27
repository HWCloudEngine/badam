#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import os
import fs_log_util
import cps_server
import fsutils as utils
from os.path import join
from fs_network_constant import NetworkConstant
from fs_network_openstack_util import OpenStackNetwokCfgProc
#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class SystemNetworkConfig():
    def __init__(self):
        #配置项的实例 拆分
        self.networkcfg = OpenStackNetwokCfgProc()
        pass

    def config_default_route(self):
        cps_network_client_params = cps_server.get_template_params("cps", "network-client")
        default_gateway = cps_network_client_params["cfg"]["default_gateway"]
        while 1:
            gateway_input = raw_input("Please set default_gateway [%s]" % default_gateway)
            if gateway_input == "":
                gateway_input = default_gateway
                break
            if utils.is_ip(gateway_input):
                break
            else:
                print "input illegal, input again"
                continue
        config = ConfigParser.RawConfigParser()
        config.read(NetworkConstant.NETWORK_INI_PATH)
        if not config.has_section(NetworkConstant.NETWORK_SECTION):
            config.add_section(NetworkConstant.NETWORK_SECTION)
        config.set(NetworkConstant.NETWORK_SECTION,
                   NetworkConstant.NETWORK_ROUTE_OPTION, gateway_input)
        with open(NetworkConstant.NETWORK_INI_PATH, 'w') as fd:
            config.write(fd)

    def default_gateway_validate(self):
        config = ConfigParser.RawConfigParser()
        config.read(NetworkConstant.NETWORK_INI_PATH)
        if config.has_option(NetworkConstant.NETWORK_SECTION,
                             NetworkConstant.NETWORK_ROUTE_OPTION):
            gateway = config.get(NetworkConstant.NETWORK_SECTION,
                                 NetworkConstant.NETWORK_ROUTE_OPTION)
            if not cps_server.update_template_params("cps", "network-client", {"default_gateway": gateway}):
                print "Default route validate failed"
                return


    def config_internal_base(self):
        is_build = ""
        while 1:
            input_str = raw_input("Do you want to build internal_base?[y|n][y]")
            if input_str == "" or input_str == "y":
                is_build = "y"
                break
            if input_str == 'n':
                is_build = "n"
                break
            print "please input again,only support:['y', 'n']"
            continue
        config = ConfigParser.RawConfigParser()
        config.read(NetworkConstant.NETWORK_INI_PATH)
        if not config.has_section(NetworkConstant.NETWORK_SECTION):
            config.add_section(NetworkConstant.NETWORK_SECTION)
        config.set(NetworkConstant.NETWORK_SECTION,
                   NetworkConstant.NETWORK_OPTION_INTERNAL_BASE_FLAG, is_build)
        with open(NetworkConstant.NETWORK_INI_PATH, 'w') as fd:
            config.write(fd)


    def validate_internal_base_api(self):
        self.networkcfg.validate_internal_base_api()

    def config_external_api(self):
        self.networkcfg.config_external_api()

    def validate_external_api(self):
        self.networkcfg.validate_api_ex()


    def config(self, type_name):
        LOG.info("config type =%s."%type_name)
        self.config_default_route()
        self.config_internal_base()
        return True

    def validate(self, type_name, phase):
        LOG.info("config type =%s phase=%s."%(type_name, phase))
        self.default_gateway_validate()
        self.validate_internal_base_api()





    def create_def_config(self, config):
        pass

    def get_section_list(self):
        pass

    def get_file_path(self):
        pass



