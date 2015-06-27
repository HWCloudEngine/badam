#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
import netaddr
import traceback
import sys
import fs_log_util
import json
import cps_server
import fsCpsCliOpt
import ConfigParser
import fsutils as utils
from os.path import join
from print_msg import PrintMessage as PrintUtil
import fs_keystone_constant as KeystoneConstant


def_network_mask = '24'
def_network_port = '443'
def_network_gateway = ""

HTTPS_MODE = 'https'
HTTP_MODE = 'http'

UNDEFINED_PORT = -1
UNDEFINED_GARTEWAY = -1
PROXY_SERVICES = 'proxy_services'

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)

def _str_to_dict(input_strs):
    return eval(input_strs.replace('"', '').replace(' ', '').replace('{', 'dict(').replace('}', '")').replace(':','="').replace(',', '",').replace(')"', ')'))

class OpenStackProxyCfgProc():

    def __init__(self):
        self.cps_server_url = cps_server.get_cpsserver_url()
        self._save_haproxy_config(self.get_haproxy_interfaces())

    def _save_haproxy_config(self, interfaces):
        if not os.path.exists(KeystoneConstant.KEYSTONE_INI_PATH):
            #如果文件不存在，则创建
            ini_file = open(KeystoneConstant.KEYSTONE_INI_PATH, 'w')
            ini_file.close()
            logger.debug("write_data.default.ini doesn't exist,file is %s." % KeystoneConstant.KEYSTONE_INI_PATH)

        cpsconfig = ConfigParser.RawConfigParser()
        cpsconfig.read(KeystoneConstant.KEYSTONE_INI_PATH)
        sectionList = cpsconfig.sections()
        if KeystoneConstant.HAPROXY_CONFIG_SECTION not in sectionList:
            cpsconfig.add_section(KeystoneConstant.HAPROXY_CONFIG_SECTION)

        cpsconfig.set(KeystoneConstant.HAPROXY_CONFIG_SECTION, KeystoneConstant.HAPROXY_EXTERNAL_API_IP, json.dumps(interfaces))

        cpsconfig.write(open(KeystoneConstant.KEYSTONE_INI_PATH, "w"))
    
    def _read_haproxy_config(self):
        ini_file = KeystoneConstant.KEYSTONE_INI_PATH

        try:
            cpsconfig = ConfigParser.RawConfigParser()
            cpsconfig.read(ini_file)
            sectionList = cpsconfig.sections()

            #自己生效的文件中是没有相关的配置信息的 CinderConstant.HOST_SECTION_KEY
            if KeystoneConstant.HAPROXY_CONFIG_SECTION not in sectionList:
                return None
            
            interfaces_str = cpsconfig.get(KeystoneConstant.HAPROXY_CONFIG_SECTION, KeystoneConstant.HAPROXY_EXTERNAL_API_IP)
            interfaces = _str_to_dict(interfaces_str)
            frontssl = self.get_haproxy_frontendssl(interfaces)
            backendssl = self.get_haproxy_backendssl(interfaces)

            params = {"external_api_ip": json.dumps(interfaces), "frontssl": frontssl, "backendssl": backendssl}
            return params
        except:
            logger.error("parse exception: %s" % (traceback.format_exc()))
            logger.error(traceback.format_exc())
            sys.exit(1)
    
    def _save_apacheproxy_config(self, interfaces):
        if not os.path.exists(KeystoneConstant.KEYSTONE_INI_PATH):
            #如果文件不存在，则创建
            ini_file = open(KeystoneConstant.KEYSTONE_INI_PATH, 'w')
            ini_file.close()
            logger.debug("write_data.default.ini doesn't exist,file is %s." % KeystoneConstant.KEYSTONE_INI_PATH)    
        
        cpsconfig = ConfigParser.RawConfigParser()
        cpsconfig.read(KeystoneConstant.KEYSTONE_INI_PATH)
        sectionList = cpsconfig.sections()
        if KeystoneConstant.APACHEPROXY_CONFIG_SECTION not in sectionList:
            cpsconfig.add_section(KeystoneConstant.APACHEPROXY_CONFIG_SECTION)        
        
        cpsconfig.set(KeystoneConstant.APACHEPROXY_CONFIG_SECTION, KeystoneConstant.APACHEPROXY_EXTERNAL_API_IP, json.dumps(interfaces))

        cpsconfig.write(open(KeystoneConstant.KEYSTONE_INI_PATH, "w"))        
    
    def _read_apacheproxy_config(self):
        ini_file = KeystoneConstant.KEYSTONE_INI_PATH

        try:
            cpsconfig = ConfigParser.RawConfigParser()
            cpsconfig.read(ini_file)
            sectionList = cpsconfig.sections()

            #自己生效的文件中是没有相关的配置信息的
            if KeystoneConstant.APACHEPROXY_CONFIG_SECTION not in sectionList:
                return None

            interfaces_str = cpsconfig.get(KeystoneConstant.APACHEPROXY_CONFIG_SECTION, KeystoneConstant.APACHEPROXY_EXTERNAL_API_IP)
            interfaces = _str_to_dict(interfaces_str)
            remote_match = self.get_apacheproxy_remote_match(interfaces)

            params = {"external_api_ip": json.dumps(interfaces), "proxy_remote_match": remote_match}
            return params
        except:
            logger.error("parse exception: %s" % (traceback.format_exc()))
            logger.error(traceback.format_exc())
            sys.exit(1)

    def find_backendservice_port(self, interfaces, backendservice):
        for interface in interfaces:
            if interface['backendservice'] == backendservice:
                return interface['frontendport']

        return UNDEFINED_PORT

    def find_systeminterface_gateway(self, interfaces, systeminterface):
        for interface in interfaces:
            if interface['systeminterface'] == systeminterface:
                if str(interface['gateway']) != "":
                    return interface['gateway']
        return UNDEFINED_GARTEWAY

    def _validate_gw_in_pools(self, ip, mask,old_gateway):
        subnet = netaddr.IPNetwork(str(ip)+"/"+str(mask), version=4).cidr
        subnet_first_ip = netaddr.IPAddress(subnet.first + 1)
        subnet_last_ip = netaddr.IPAddress(subnet.last - 1)
        pool_range = netaddr.IPRange(
            subnet_first_ip,
            subnet_last_ip)
        if netaddr.IPAddress(old_gateway) in pool_range:
            return True

    def print_haproxy_interfaces(self, interfaces):
        index = 1
        for interface in interfaces:
            interface['index'] = index
            index += 1

        utils.print_list(interfaces, ['index', 'frontendip', 'mask', 'frontendport',
                                      'gateway', 'systeminterface', 'backendservice'])

        for interface in interfaces:
            del interface['index']

    def print_apacheproxy_interfaces(self, interfaces):
        index = 1
        for interface in interfaces:
            interface['index'] = index
            index += 1

        utils.print_list(interfaces, ['index', 'ip', 'mask', 'gateway', 'systeminterface'])

        for interface in interfaces:
            del interface['index']

    def print_network_list(self, sys_interfaces):


        index = 1
        for interface in sys_interfaces:
            interface['index'] = index
            index += 1

        utils.print_list(sys_interfaces, ['index', 'name', 'vlan', 'gateway'])
        return len(sys_interfaces)

    def print_haproxy_interface(self, interface):
        utils.print_dict(interface)

    def print_apacheproxy_interface(self, interface):
        utils.print_dict(interface)

    def get_haproxy_interfaces(self):
        res_text = cps_server.get_template_params('haproxy', 'haproxy')
        interfaces = json.loads(res_text['cfg']['external_api_ip'])

        return interfaces

    def get_doc_regex(self, regex):
        return str(regex).replace('\.', '.').replace('.*', '')

    def get_apacheproxy_interfaces(self):
        res_text = cps_server.get_template_params('apacheproxy', 'apacheproxy')
        interfaces = json.loads(res_text['cfg']['external_api_ip'])
        proxy_remote_match = json.loads(res_text['cfg']['proxy_remote_match'])

        for interface in interfaces:
            for item in proxy_remote_match:
                if interface['ip'] == item['ProxySourceAddress']:
                    interface[PROXY_SERVICES] = self.get_doc_regex(item['regex'])

        return interfaces

    def get_valid_interfaces(self):
        all_interfaces = cps_server.get_sys_interfaces_list()
        del_interfaces_names = ['internal_base', 'storage_data0', 'storage_data1', 'tunnel_bearing']
        valid_interface = []

        for interface in all_interfaces:
            if interface['name'] not in del_interfaces_names:
                valid_interface.append(interface)

        return valid_interface

    def confirm_add(self):
        while True:
            inputstr = PrintUtil.get_msg(["Please confirm the config data, 'y' for continue, 'n' for cancel![y/n][y]:",
                                          "请确认配置数据！继续为‘y’,取消为‘n’[y/n][y]："])
            choise = raw_input(inputstr)

            if choise == "y" or choise == "":
                return True
            elif choise == "n":
                return False
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [y/n]!"

    def confirm_delete(self):
        while True:
            inputstr = PrintUtil.get_msg(["Please confirm the delete data, 'y' for continue, 'n' for cancel![y/n][y]:",
                                          "请确认删除数据！继续为‘y’,取消为‘n’[y/n][y]："])
            choise = raw_input(inputstr)

            if choise == "y" or choise == "":
                return True
            elif choise == "n":
                return False
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [y/n]!"

    def choose_add_interface(self):
        sys_interfaces = self.get_valid_interfaces()
        if sys_interfaces is []:
            PrintUtil.print_msg("No vailable interface!", "没有可用平面")
            sys.exit(1)

        self.print_network_list(sys_interfaces)
        num = len(sys_interfaces)
        legal_choise = [str(i) for i in range(1, num + 1)]

        while True:
            inputstr = PrintUtil.get_msg(["please choose interface, input index", "请选择平面，输入编号"]) + ("[1-%s]:" % str(num))
            choise = raw_input(inputstr)
            choise = choise.strip()

            if choise in legal_choise:
                return sys_interfaces[int(choise) - 1]['name']
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [1-%s]!" % num

    def choose_haproxy_backendservice(self, interfaces):
        while True:
            print "[1] all"
            print "[2] nova-novncproxy"
            print "[3] cps-web"

            inputstr = PrintUtil.get_msg(["Please set backendservice", "请选择后端服务"]) + " [1-3]:"
            choise = raw_input(inputstr)
            if choise == "1":
                return "all"
            elif choise == "2":
                return "nova-novncproxy"
            elif choise == "3":
                return "cps-web"
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [1-2]!"

    def choose_method(self):
        while True:
            print "[1] Add proxy"
            print "[2] Remove proxy"

            inputstr = PrintUtil.get_msg(["Please choose", "请选择"]) + " [1-2|q][q]:"
            choise = raw_input(inputstr)
            if choise == "":
                return "q"
            elif choise in ["1", "2", "q"]:
                return choise
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [1-2|q]!"

    def is_new_haproxy_legal(self, new_interface, interfaces):
        for interface in interfaces:
            if interface['frontendip'] == new_interface['frontendip'] and interface['mask'] == new_interface['mask'] \
                and interface['frontendport'] == new_interface['frontendport']:
                return False

        return True

    def is_new_apacheproxy_legal(self, new_interface, interfaces):
        for interface in interfaces:
            if interface['ip'] == new_interface['ip'] and interface['mask'] == new_interface['mask']:
                return False

        return True

    def add_haproxy(self, interfaces):
        systeminterface = self.choose_add_interface()
        if systeminterface == None:
            return False
        backendservice = self.choose_haproxy_backendservice(interfaces)
        prompt = PrintUtil.get_msg(["please set frontend ip:", "请输入前端IP："])
        front_ip = utils.check_user_input(prompt, utils.check_ip)

        prompt = PrintUtil.get_msg(["please set network mask", "请设置网络掩码"]) + ("[%s]:" % def_network_mask)
        mask = utils.check_user_input(prompt, utils.check_mask, def_network_mask)

        port = self.find_backendservice_port(interfaces, backendservice)
        if  port == UNDEFINED_PORT:
            prompt = PrintUtil.get_msg(["please set frontend port", "请设置前端端口"]) + ("[%s]:" % def_network_port)
            port = utils.check_user_input(prompt, utils.check_port, def_network_port)
        else:
            PrintUtil.print_msg(["Automatically set frontend port: " + str(port), "自动设置前段端口：" + str(port)])

        gateway = self.find_systeminterface_gateway(interfaces, systeminterface)

        if gateway == UNDEFINED_GARTEWAY:
            prompt = PrintUtil.get_msg(["please set gateway[]:", "请设置网关:"])
            gateway = utils.check_user_input(prompt, utils.check_ip, def_network_gateway)
        else:
            if not self._validate_gw_in_pools(front_ip,mask,gateway):
                gateway = ""
            else:
                PrintUtil.print_msg(["Automatically set gateway: " + str(gateway), "自动设置网关：" + str(gateway)])

        new_interface = {
            'systeminterface': systeminterface,
            'mask': mask,
            'gateway': gateway,
            'backendservice': backendservice,
            'frontendport': port,
            'frontendip': front_ip,
        }

        self.print_haproxy_interface(new_interface)
        flag = self.confirm_add()
        if flag:
            if self.is_new_haproxy_legal(new_interface, interfaces):
                interfaces.append(new_interface)
                return True
            else:
                PrintUtil.print_msg(["ip address and port is conflicted, add failed!", "ip地址和端口冲突，添加失败"])
                return False
        else:
            return False

    def add_apacheproxy(self, interfaces):
        systeminterface = self.choose_add_interface()
        if systeminterface == None:
            return False

        prompt = PrintUtil.get_msg(["please set ip:", "请输入IP："])
        front_ip = utils.check_user_input(prompt, utils.check_ip)

        prompt = PrintUtil.get_msg(["please set network mask", "请设置网络掩码"]) + ("[%s]:" % def_network_mask)
        mask = utils.check_user_input(prompt, utils.check_mask, def_network_mask)

        gateway = self.find_systeminterface_gateway(interfaces, systeminterface)
        if gateway == UNDEFINED_GARTEWAY:
            prompt = PrintUtil.get_msg(["please set gateway[]:", "请设置网关:"])
            gateway = utils.check_user_input(prompt, utils.check_ip, def_network_gateway)
        else:
            if not self._validate_gw_in_pools(front_ip,mask,gateway):
                gateway = ""
            else:
                PrintUtil.print_msg(["Automatically set gateway: " + str(gateway), "自动设置网关：" + str(gateway)])

        prompt = PrintUtil.get_msg(['please set proxy services, such as "network | identity | compute"[default value is proxy all services]: ',
                                    '请设置代理服务，例如"network | identity | compute"[默认值为代理所有服务]: '])
        proxy_services = raw_input(prompt)

        new_interface = {
            'systeminterface': systeminterface,
            'mask': mask,
            'gateway': gateway,
            'ip': front_ip,
            PROXY_SERVICES: proxy_services.strip()
        }

        self.print_apacheproxy_interface(new_interface)
        flag = self.confirm_add()
        if flag:
            if self.is_new_apacheproxy_legal(new_interface, interfaces):
                interfaces.append(new_interface)
                return True
            else:
                PrintUtil.print_msg(["ip address is conflicted, add failed!", "ip地址冲突，添加失败"])
                return False
        else:
            return False


    def remove_haproxy(self, interfaces):
        if interfaces is []:
            PrintUtil.print_msg("No available Haproxy", "没有存在的Haproxy")
            return False

        num = len(interfaces)
        legal_choise = [str(i) for i in range(1, num + 1)]

        while True:
            inputstr = PrintUtil.get_msg(["remove Haproxy index", "请选择删除平面索引值"]) + " [1-%s|q][q]:" % num
            choise = raw_input(inputstr)
            if choise == "" or choise == "q":
                return False
            elif choise in legal_choise:
                choise = int(choise)
                break
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [1-%s|q]!" % num

        self.print_haproxy_interface(interfaces[choise - 1])
        flag = self.confirm_delete()
        if flag:
            del interfaces[choise - 1]
            return True
        else:
            return False

    def remove_apacheproxy(self, interfaces):
        if interfaces is []:
            PrintUtil.print_msg("No available Apacheproxy", "没有存在的Apacheproxy")
            return False

        num = len(interfaces)
        legal_choise = [str(i) for i in range(1, num + 1)]

        while True:
            inputstr = PrintUtil.get_msg(["remove Apacheproxy index", "请选择删除平面索引值"]) + " [1-%s|q][q]:" % num
            choise = raw_input(inputstr)
            if choise == "" or choise == "q":
                return False
            elif choise in legal_choise:
                choise = int(choise)
                break
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [1-%s|q]!" % num

        self.print_apacheproxy_interface(interfaces[choise - 1])
        flag = self.confirm_delete()
        if flag:
            del interfaces[choise - 1]
            return True
        else:
            return False

    def get_protocol (self):
        http_type = None
        cf = ConfigParser.ConfigParser()
        cf.read(KeystoneConstant.KEYSTONE_INI_PATH)
        if cf.has_section("http_mode"):
            if cf.has_option("http_mode","url_http_type"):
                http_type = cf.get("http_mode", "url_http_type")

        if http_type is None:
            return HTTPS_MODE
        else:
            return http_type

    def get_haproxy_backendssl(self, interfaces):
        if not interfaces:
            return '[]'

        if self.get_protocol() == HTTPS_MODE:
            backendssl_value = '[{"backendservice":"identity","ssl":"true","certfile":"keystone.crt","keyfile":"keystone.key"},' \
                            '{"backendservice":"image","ssl":"true","certfile":"glance.crt","keyfile":"glance.key"},' \
                            '{"backendservice":"baremetal","ssl":"true","certfile":"ironic-api.crt","keyfile":"ironic-api.key"},' \
                            '{"backendservice":"compute","ssl":"true","certfile":"nova-api.crt","keyfile":"nova-api.key"},' \
                            '{"backendservice":"network","ssl":"true","certfile":"neutron-server.crt","keyfile":"neutron-server.key"},' \
                            '{"backendservice":"orchestration","ssl":"true","certfile":"heat.crt","keyfile":"heat.key"},' \
                            '{"backendservice":"objectstore","ssl":"false"},' \
                            '{"backendservice":"volume","ssl":"true","certfile":"cinder-api.crt","keyfile":"cinder-api.key"},' \
                            '{"backendservice":"metering","ssl":"true","certfile":"ceilometer-api.crt","keyfile":"ceilometer-api.key"},' \
                            '{"backendservice":"nova-novncproxy","ssl":"true","certfile":"nova-novncproxy.crt","keyfile":"nova-novncproxy.key"},' \
                            '{"backendservice":"cps","ssl":"true","certfile":"cps-server.crt","keyfile":"cps-server.key"},' \
                            '{"backendservice":"backup","ssl":"true","certfile":"backup-server.crt","keyfile":"backup-server.key"},' \
                            '{"backendservice":"backup-package","ssl":"true","certfile":"backup-package.crt","keyfile":"backup-package.key"},'\
                            '{"backendservice":"log","ssl":"true","certfile":"log-server.crt","keyfile":"log-server.key"},' \
                            '{"backendservice":"upg","ssl":"true","certfile":"upg-server.crt","keyfile":"upg-server.key"},' \
                            '{"backendservice":"hws","ssl":"true","certfile":"hws-server.crt","keyfile":"hws-server.key"},' \
                            '{"backendservice":"hws-websocket","ssl":"true","certfile":"hws-server.crt","keyfile":"hws-server.key"},' \
                            '{"backendservice":"info-collect","ssl":"true","certfile":"info-collect-server.crt","keyfile":"info-collect-server.key"},' \
                            '{"backendservice":"cloudformation","ssl":"true","certfile":"cloudformation.crt","keyfile":"cloudformation.key"},' \
                            '{"backendservice":"dsware-server1","ssl":"true","certfile":"","keyfile":""},' \
                            '{"backendservice":"dsware-server2","ssl":"true","certfile":"","keyfile":""},' \
                            '{"backendservice":"dsware-server3","ssl":"true","certfile":"","keyfile":""},' \
                            '{"backendservice":"cps-web","ssl":"true","certfile":"cps-web.crt","keyfile":"cps-web.key"},' \
                            '{"backendservice":"oam","ssl":"true","certfile":"oam-network-server.crt","keyfile":"oam-network-server.key"}]'
        else:
            backendssl_value = '[{"backendservice":"identity","ssl":"false","certfile":"keystone.crt","keyfile":"keystone.key"},' \
                            '{"backendservice":"image","ssl":"false","certfile":"glance.crt","keyfile":"glance.key"},' \
                            '{"backendservice":"baremetal","ssl":"false","certfile":"ironic-api.crt","keyfile":"ironic-api.key"},' \
                            '{"backendservice":"compute","ssl":"false","certfile":"nova-api.crt","keyfile":"nova-api.key"},' \
                            '{"backendservice":"network","ssl":"false","certfile":"neutron-server.crt","keyfile":"neutron-server.key"},' \
                            '{"backendservice":"orchestration","ssl":"false","certfile":"heat.crt","keyfile":"heat.key"},' \
                            '{"backendservice":"objectstore","ssl":"false"},' \
                            '{"backendservice":"volume","ssl":"false","certfile":"cinder-api.crt","keyfile":"cinder-api.key"},' \
                            '{"backendservice":"metering","ssl":"false","certfile":"ceilometer-api.crt","keyfile":"ceilometer-api.key"},' \
                            '{"backendservice":"nova-novncproxy","ssl":"false","certfile":"nova-novncproxy.crt","keyfile":"nova-novncproxy.key"},' \
                            '{"backendservice":"cps","ssl":"false","certfile":"cps-server.crt","keyfile":"cps-server.key"},' \
                            '{"backendservice":"backup","ssl":"false","certfile":"backup-server.crt","keyfile":"backup-server.key"},' \
                            '{"backendservice":"backup-package","ssl":"false","certfile":"backup-package.crt","keyfile":"backup-package.key"},'\
                            '{"backendservice":"log","ssl":"false","certfile":"log-server.crt","keyfile":"log-server.key"},' \
                            '{"backendservice":"upg","ssl":"false","certfile":"upg-server.crt","keyfile":"upg-server.key"},' \
                            '{"backendservice":"hws","ssl":"false","certfile":"hws-server.crt","keyfile":"hws-server.key"},' \
                            '{"backendservice":"hws-websocket","ssl":"false","certfile":"hws-server.crt","keyfile":"hws-server.key"},' \
                            '{"backendservice":"info-collect","ssl":"false","certfile":"info-collect-server.crt","keyfile":"info-collect-server.key"},' \
                            '{"backendservice":"cloudformation","ssl":"false","certfile":"cloudformation.crt","keyfile":"cloudformation.key"},' \
                            '{"backendservice":"dsware-server1","ssl":"false","certfile":"","keyfile":""},' \
                            '{"backendservice":"dsware-server2","ssl":"false","certfile":"","keyfile":""},' \
                            '{"backendservice":"dsware-server3","ssl":"false","certfile":"","keyfile":""},' \
                            '{"backendservice":"cps-web","ssl":"false","certfile":"cps-web.crt","keyfile":"cps-web.key"},' \
                            '{"backendservice":"oam","ssl":"false","certfile":"oam-network-server.crt","keyfile":"oam-network-server.key"}]'

        return backendssl_value

    def get_haproxy_frontendssl(self, interfaces):
        if self.get_protocol() == HTTPS_MODE:
            frontendssl_value = []
            for interface in interfaces:
                if interface["backendservice"] == 'all':
                    one_front_ssl = {"frontendip": interface["frontendip"], "backendservice": interface["backendservice"],
                                     "frontendport": interface["frontendport"], "certfile": "", "keyfile": "",
                                     "ssl": "true"}
                elif interface["backendservice"] == 'nova-novncproxy':
                    one_front_ssl = {"frontendip": interface["frontendip"], "backendservice": interface["backendservice"],
                                     "frontendport": interface["frontendport"], "certfile": "", "keyfile": "",
                                     "ssl": "true"}
                elif interface["backendservice"] == 'cps-web':
                    one_front_ssl = {"frontendip": interface["frontendip"], "backendservice": interface["backendservice"],
                                     "frontendport": interface["frontendport"], "certfile": "", "keyfile": "",
                                     "ssl": "true"}
                frontendssl_value.append(one_front_ssl)

            return  json.dumps(frontendssl_value)
        else:
            return json.dumps([])

    def _validate_novncproxy(self, params):
        novncproxy_port = self.find_backendservice_port(json.loads(params["external_api_ip"]), 'nova-novncproxy')
        if novncproxy_port != UNDEFINED_PORT:
            local_domain = cps_server.get_local_domain()
            if self.get_protocol() == HTTPS_MODE:
                novncproxy_base_url = "https://nova-novncproxy.%s:%s/vnc_auto.html" % (local_domain, novncproxy_port)
            else:
                novncproxy_base_url = "http://nova-novncproxy.%s:%s/vnc_auto.html" % (local_domain, novncproxy_port)
            cfg_params = {"novncproxy_base_url": novncproxy_base_url}
            fsCpsCliOpt.updateTemplateParams(self.cps_server_url, "nova", "nova-compute", cfg_params)
            fsCpsCliOpt.updateTemplateParams(self.cps_server_url, "nova", "nova-novncproxy", cfg_params)

    def validate_haproxy(self):
        PrintUtil.print_msg(["Begin to set Reverse proxy!", "Begin to set Reverse proxy!"])
        params = self._read_haproxy_config()

        if params is None:
            PrintUtil.print_msg(["Failed to set Reverse proxy, section %s not found" % KeystoneConstant.HAPROXY_CONFIG_SECTION ,
                                 "Failed to set Reverse proxy, section %s not found" % KeystoneConstant.HAPROXY_CONFIG_SECTION])
            return

        ret = fsCpsCliOpt.updateTemplateParams(self.cps_server_url, "haproxy", "haproxy", params)
        self._validate_novncproxy(params)
        PrintUtil.print_msg(["Succeed to set Reverse proxy!", "Succeed to set Reverse proxy!"])

        msg = "validate Reverse proxy, result=%s" % (str(ret))
        logger.info(msg)

    def _get_apacheproxy_regex(self, proxy_services):
        proxy_services = proxy_services.strip()
        if proxy_services == '':
            return '.*'

        regex = ''
        proxy_services_list = proxy_services.split('|')

        for service in proxy_services_list:
            service = service.strip()
            if service:
                regex += '.*' + service.replace('.', '\.') + '.*|'

        return regex[0:len(regex)-1]


    def get_apacheproxy_remote_match(self, interfaces):
        remote_match = []
        vhost_port = 8081
        for interface in interfaces:
            value = {
                "regex": self._get_apacheproxy_regex(interface[PROXY_SERVICES]),
                "vhost_port": vhost_port,
                "ProxySourceAddress": interface['ip']
            }
            del interface[PROXY_SERVICES]
            vhost_port += 1
            remote_match.append(value)

        return json.dumps(remote_match)

    def validate_apacheproxy(self):
        PrintUtil.print_msg(["Begin to set Forward proxy!", "Begin to set Forward proxy!"])
        params = self._read_apacheproxy_config()

        if params is None:
            PrintUtil.print_msg(["Failed to set Forward proxy, section %s not found" % KeystoneConstant.APACHEPROXY_CONFIG_SECTION,
                                 "Failed to set Forward proxy, section %s not found" % KeystoneConstant.APACHEPROXY_CONFIG_SECTION])
            return

        ret = fsCpsCliOpt.updateTemplateParams(self.cps_server_url, "apacheproxy", "apacheproxy", params)
        PrintUtil.print_msg(["Succeed to set Forward proxy!", "Succeed to set Forward proxy!"])

        msg = "validate Forward proxy, result=%s" % (str(ret))
        logger.info(msg)

    def config_haproxy(self):
        interfaces = self.get_haproxy_interfaces()
        self.print_haproxy_interfaces(interfaces)
        flag = False

        while not flag:
            choise = self.choose_method()
            if choise == 'q':
                return False
            elif choise == '1':
                flag = self.add_haproxy(interfaces)
            elif choise == '2':
                flag = self.remove_haproxy(interfaces)

        self._save_haproxy_config(interfaces)
        return True
        

    def config_apacheproxy(self):
        interfaces = self.get_apacheproxy_interfaces()
        self.print_apacheproxy_interfaces(interfaces)
        flag = False

        while not flag:
            choise = self.choose_method()
            if choise == 'q':
                return False
            elif choise == '1':
                flag = self.add_apacheproxy(interfaces)
            elif choise == '2':
                flag = self.remove_apacheproxy(interfaces)

        self._save_apacheproxy_config(interfaces)
        return True