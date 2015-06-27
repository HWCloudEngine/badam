#!/usr/bin/env python
#-*-coding:utf-8-*-

import sys
import copy
import requests
import json
import commands
import ConfigParser
import traceback
import fs_keystone_server
import fs_log_util
import cps_server
import fsCpsCliOpt
import fsutils as utils
import fs_network_constant
from print_msg import PrintMessage as PrintUtil
from os.path import join
import os
import socket
import struct
import fs_network_util
from fs_network_constant import NetworkConstant


MY_SECTION = "openstack_network_cfg"
# 初始值

STR_GATEWAY = "gateway"
STR_SUBNET = "subnet"
STR_VLAN = "vlan"
STR_POOL_START = "poolstart"
STR_POOL_END = "poolend"
STR_PROVIDER = "provider_name"
CPS_API_FLAG = "cps_external_api"
NET_EXIST = "net_exist"
SUB_EXIST = "sub_exist"

ST_DIRTY = "dirty"
ST_ADD = "add"
ST_ORIG = "orig"
def_external_om_subnet = '192.168.0.0/24'
def_external_om_vlan = '4005'
def_external_om_poolstart = '192.168.0.8'
def_external_om_poolend = '192.168.0.32'
def_external_om_gateway = '192.168.0.1'
def_external_om_provider = "physnet1"

def_external_api_subnet = '192.168.0.0/24'
def_external_api_vlan = '4004'
def_external_api_poolstart = '192.168.0.64'
def_external_api_poolend = '192.168.0.80'
def_external_api_gateway = '192.168.0.1'
def_external_api_provider = "physnet1"

def_network_mask = '24'
def_network_port = '443'

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)

VLAN_ID_CONFLICT = ["vlan id conflict, vlan id: %s", "vlan号冲突，vlan号：%s"]

def runCommand(cmd):
    try:
        (status, output) = commands.getstatusoutput(cmd)
        logger.info("run cmd :%s,status %s output %s" % (cmd, status, output))
        return status, output
    except Exception, e:
        logger.error(e)
    return 1, output

def createNet(name, net_type, vlanid, provider, shared, dcadmin_token, neutron_url):
    method = "POST"
    kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dcadmin_token}}
    kwargs['verify'] = False
    if net_type == 'vlan':
        body = {
            "network": {"name": name, "provider:physical_network": provider, "admin_state_up": True, "shared": False,
                        "provider:network_type": net_type, "provider:segmentation_id": vlanid}}
    elif net_type == 'flat':
        body = {
            "network": {"name": name, "provider:physical_network": provider, "admin_state_up": True, "shared": False,
                        "provider:network_type": net_type}}
    elif net_type == 'vxlan':
        body = {"network": {"name": name, "admin_state_up": True, "shared": False, "provider:network_type": net_type,
                            "provider:segmentation_id": vlanid}}
    else:
        return None

    kwargs['data'] = json.dumps(body)
    url = "%s/v2.0/networks.json" % neutron_url
    try:
        res = requests.request(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))

        print "create network,name=%s,type=%s,vlanid=%s" % (name, net_type, vlanid)
        return json.loads(res.text)['network']['id']
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s, shared = %s." % (url, method, e, shared))
        return None


def deleteNet(networkid, dcadmin_token, neutron_url):
    method = "DELETE"
    kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dcadmin_token}}
    kwargs['verify'] = False
    url = "%s/v2.0/networks/%s" % (neutron_url, networkid)
    try:
        res = requests.request(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False


def getNet(dcadmin_token, neutron_url):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dcadmin_token}}
    kwargs['verify'] = False
    url = "%s/v2.0/networks" % (neutron_url)
    try:
        res = requests.request(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        logger.info("run request :%s, method:%s,the response info is :%s" % (url, method, res.text))
        return json.loads(res.text)
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None


def createSubnet(netname, netid, name, cidr, poolstart, poolend, gateway_ip, dcadmin_token, neutron_url, dnsserver_ip):
    method = "POST"
    kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dcadmin_token}}
    kwargs['verify'] = False
    if gateway_ip == '':
        body = {"subnet": {"network_id": netid, "ip_version": 4, "cidr": cidr, "name": name,
                       "allocation_pools": [{"start": poolstart, "end": poolend}],
                       "dns_nameservers": [dnsserver_ip]}}
    else:
        body = {"subnet": {"network_id": netid, "ip_version": 4, "cidr": cidr, "name": name,
                       "allocation_pools": [{"start": poolstart, "end": poolend}], "gateway_ip": gateway_ip,
                       "dns_nameservers": [dnsserver_ip]}}
    kwargs['data'] = json.dumps(body)
    url = "%s/v2.0/subnets.json" % neutron_url
    try:
        res = requests.request(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        print "create subnet,net=%s,subnet=%s,cidr=%s,poolstart=%s,poolend=%s" % (
            netname, name, cidr, poolstart, poolend)
        return json.loads(res.text)
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None


def deleteSubnet(subnetid, dcadmin_token, neutron_url):
    method = "DELETE"
    kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dcadmin_token}}
    kwargs['verify'] = False
    url = "%s/v2.0/subnets/%s" % (neutron_url, subnetid)
    try:
        res = requests.request(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False


def getSubnet(dcadmin_token, neutron_url):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dcadmin_token}}
    kwargs['verify'] = False
    url = "%s/v2.0/subnets" % (neutron_url)
    try:
        res = requests.request(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        return json.loads(res.text)
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None


class OpenStackNetwokCfgProc():
    def __init__(self):
        self.part_map = {
            "4": self.config_external_api
        }
        self.token = None
        self.cloud_pass = None
        self.init_flag = False
        self.configParse = ConfigParser.ConfigParser()
        self.configParse.read(fs_network_constant.NetworkConstant.NETWORK_INI_PATH)

        self.cps_server_url = cps_server.get_cpsserver_url()
        self.haproxy_conf = None
        self.apacheproxy_conf = None
        self.external_api_conf = None
        self.cur_external_api_info = None
        self.internal_base_conf = {"state": ST_ORIG, "exist": "false", "net_exist": "false"}
        self.external_om_conf = {}

    def nw_init(self):
        self.cloud_pass = fs_keystone_server.keystone_get_dc_password()
        self.token = fs_keystone_server.keystone_get_dc_token()
        self.neutron_url = fs_keystone_server.keystone_get_endpoint("neutron")['neutron']['internal_url']
        self.get_cur_internal_base_conf()
        self.get_cur_external_api_info()
        self.init_flag = True

    def get_cur_external_api_info(self):
        cur_info = {}
        net_info = getNet(self.token, self.neutron_url)
        if net_info is not None:
            net_list = net_info["networks"]
            for each_item in net_list:
                net_name = each_item["name"]
                if net_name.find("external_api") != -1:
                    cur_info["net_id"] = each_item["id"]
                    cur_info[STR_VLAN] = each_item["provider:segmentation_id"]
                    cur_info[STR_PROVIDER] = each_item["provider:physical_network"]


        # 子网信息
        subnet_info = getSubnet(self.token, self.neutron_url)
        if subnet_info is not None:
            subnet_list = subnet_info["subnets"]
            for item in subnet_list:
                subnet_name = item["name"]
                if subnet_name.find("external_api") != -1:
                    cur_info["subnet_id"] = item["id"]
                    cur_info[STR_SUBNET] = item["cidr"]
                    cur_info[STR_GATEWAY] = item["gateway_ip"]
                    pool_info = item["allocation_pools"][0]
                    cur_info[STR_POOL_START] = pool_info["start"]
                    cur_info[STR_POOL_END] = pool_info["end"]

        self.cur_external_api_info = cur_info

    def get_cur_external_om_conf(self):
        name_external_om = "external_om"

        orig_external_om_sysintf = None
        sysintf_list = cps_server.get_sys_interfaces_list()
        for ont_sysintf in sysintf_list:
            if ont_sysintf["name"] == name_external_om:
                orig_external_om_sysintf = ont_sysintf
        if orig_external_om_sysintf is None:
            return

        # 更新信息
        if orig_external_om_sysintf.has_key(STR_SUBNET):
            self.external_om_conf[STR_SUBNET] = orig_external_om_sysintf[STR_SUBNET]
        else:
            self.external_om_conf[STR_SUBNET] = ""
        if orig_external_om_sysintf.has_key(STR_VLAN):
            self.external_om_conf[STR_VLAN] = orig_external_om_sysintf[STR_VLAN]
        else:
            self.external_om_conf[STR_VLAN] = ""
        if orig_external_om_sysintf.has_key(STR_GATEWAY):
            self.external_om_conf[STR_GATEWAY] = orig_external_om_sysintf[STR_GATEWAY]
        else:
            self.external_om_conf[STR_GATEWAY] = ""
        if orig_external_om_sysintf.has_key("ippool"):
            self.external_om_conf[STR_POOL_START] = orig_external_om_sysintf["ippool"]["start"]
            self.external_om_conf[STR_POOL_END] = orig_external_om_sysintf["ippool"]["end"]
        else:
            self.external_om_conf[STR_POOL_START] = ""
            self.external_om_conf[STR_POOL_END] = ""
            # provider
        if orig_external_om_sysintf.has_key(STR_PROVIDER):
            self.external_om_conf[STR_PROVIDER] = orig_external_om_sysintf[STR_PROVIDER]
        else:
            self.external_om_conf[STR_PROVIDER] = ""

        self.external_om_conf["exist"] = "true"

    def get_cur_internal_base_conf(self):
        # external_api和internal_base网络
        net_info = getNet(self.token, self.neutron_url)
        if net_info is not None:
            net_list = net_info["networks"]
            for each_item in net_list:
                net_name = each_item["name"]
                if net_name.find("internal_base") != -1:
                    # 找到了
                    self.internal_base_conf["net_id"] = each_item["id"]
                    self.internal_base_conf[STR_VLAN] = each_item["provider:segmentation_id"]
                    self.internal_base_conf[NET_EXIST] = "true"

        # 从subnet中获取信息
        subnet_info = getSubnet(self.token, self.neutron_url)
        if subnet_info is not None:
            subnet_list = subnet_info["subnets"]
            for item in subnet_list:
                subnet_name = item["name"]
                if subnet_name.find("sub_internal_base") != -1:
                    self.internal_base_conf["subnet_id"] = item["id"]
                    self.internal_base_conf[STR_SUBNET] = item["cidr"]
                    self.internal_base_conf[STR_GATEWAY] = item["gateway_ip"]
                    pool_info = item["allocation_pools"][0]
                    self.internal_base_conf[STR_POOL_START] = pool_info["start"]
                    self.internal_base_conf[STR_POOL_END] = pool_info["end"]
                    self.internal_base_conf["exist"] = "true"
                    self.internal_base_conf["dnsserver_mng_ip"] = item["dns_nameservers"][0]

    def pre_config_external_api(self):
        # 打印当前的配置并决策默认值
        def_external_api_value = {}
        cur_vlan = None
        cur_provider = None
        sysintfnw_list = fs_network_util.get_sysintfnw_list()
        for item in sysintfnw_list:
            if item["name"] == NetworkConstant.STR_NET_TYPE_API:
                cur_vlan = item[STR_VLAN]
                cur_provider = item[STR_PROVIDER]
        if cur_vlan is None:
            warning_msg = "Please build external_api by cps cli before configuration."
            logger.info(warning_msg)
            print warning_msg
            return

        print "-------------- external api info --------------"

        utils.print_dict(self.cur_external_api_info)
        tmp_info = self.cur_external_api_info
        if tmp_info.has_key(STR_SUBNET):
            def_external_api_value[STR_SUBNET] = tmp_info[STR_SUBNET]
        else:
            def_external_api_value[STR_SUBNET] = def_external_api_subnet

        if tmp_info.has_key(STR_VLAN):
            def_external_api_value[STR_VLAN] = tmp_info[STR_VLAN]
        else:
            def_external_api_value[CPS_API_FLAG] = "not existed"
            def_external_api_value[STR_VLAN] = def_external_api_vlan

        if tmp_info.has_key(STR_GATEWAY):
            def_external_api_value[STR_GATEWAY] = tmp_info[STR_GATEWAY]
        else:
            def_external_api_value[STR_GATEWAY] = def_external_api_gateway

        if tmp_info.has_key(STR_POOL_START):
            def_external_api_value[STR_POOL_START] = tmp_info[STR_POOL_START]
        else:
            def_external_api_value[STR_POOL_START] = def_external_api_poolstart

        if tmp_info.has_key(STR_POOL_END):
            def_external_api_value[STR_POOL_END] = tmp_info[STR_POOL_END]
        else:
            def_external_api_value[STR_POOL_END] = def_external_api_poolend

        if tmp_info.has_key(STR_PROVIDER):
            def_external_api_value[STR_PROVIDER] = tmp_info[STR_PROVIDER]
        else:
            def_external_api_value[STR_PROVIDER] = def_external_api_provider

        return def_external_api_value

    def has_external_om_sysintfmapping(self, one_hostcfg):
        name_external_om = "external_om"
        sysintfmapping_list = one_hostcfg["sysintfnwmapping"]
        for item in sysintfmapping_list:
            if item["name"] == name_external_om:
                return True
        return False

    def has_provider_mapping(self, one_hostcfg, provider_name):
        providermapping_list = one_hostcfg["providermapping"]
        for item in providermapping_list:
            if item["name"] == provider_name:
                return True
        return False

    def config_external_om(self):
        # 先打印下当前的信息
        print "-------------- external om info --------------"
        utils.print_dict(self.external_om_conf)

        cur_subnet = def_external_om_subnet
        cur_vlan = def_external_om_vlan
        cur_gateway = def_external_om_gateway
        cur_pool_start = def_external_om_poolstart
        cur_pool_end = def_external_om_poolend
        cur_provider = def_external_om_provider
        if self.external_om_conf["exist"] == "true":
            cur_subnet = self.external_om_conf[STR_SUBNET]
            cur_vlan = str(self.external_om_conf[STR_VLAN])
            cur_gateway = self.external_om_conf[STR_GATEWAY]
            cur_pool_start = self.external_om_conf[STR_POOL_START]
            cur_pool_end = self.external_om_conf[STR_POOL_END]
            cur_provider = self.external_om_conf[STR_PROVIDER]

        # 网络地址
        prompt = PrintUtil.get_msg(["please set cidr for external_om network",
                                    "请输入external_om网络的网络地址"]) + (" [%s]:" % cur_subnet)
        external_om_subnet = utils.get_user_input_default_check(prompt, cur_subnet, utils.is_subnet)
        # vlan
        prompt = PrintUtil.get_msg(["please set vlan id for external_om network",
                                    "请输入external_om网络的vlan"]) + (" [%s]:" % cur_vlan)
        external_om_vlan = utils.get_user_input_default_check(prompt, cur_vlan,
                                                              fs_network_util.NetworkHostcfgMgr.check_is_digit)
        # 网关
        prompt = PrintUtil.get_msg(["please set gateway for external_om network",
                                    "请输入external_om网络的网关"]) + (" [%s]:" % cur_gateway)
        external_om_gateway = utils.get_user_input_default_check(prompt, cur_gateway, utils.is_ip)
        # 起始ip地址
        prompt = PrintUtil.get_msg(["please set subnet ip pool start address that created in neutron for external_om "
                                    "network",
                                    "请输入external_om网络的ip池的起始ip地址"]) + (" [%s]:" % cur_pool_start)
        external_om_poolstart = utils.get_user_input_default_check(prompt, cur_pool_start, utils.is_ip)
        # 终止ip地址
        prompt = PrintUtil.get_msg(["please set subnet ip pool end address that created in neutron for external_om "
                                    "network",
                                    "请输入external_om网络的ip池的终止ip地址"]) + (" [%s]:" % cur_pool_end)
        external_om_poolend = utils.get_user_input_default_check(prompt, cur_pool_end, utils.is_ip)

        # provider
        cur_provider_list = cps_server.get_provider_list()
        utils.print_list(cur_provider_list, ["name", "vlanpool", "description"])
        name_list = []
        for one_provider in cur_provider_list:
            name_list.append(one_provider["name"])
        prompt = PrintUtil.get_msg(["please set provider for external_om",
                                    "请输入external_om网络的provider"]) + (" [%s]:" % cur_provider)
        external_om_provider = utils.get_use_input_check_2(prompt, cur_provider, name_list)

        # 分别处理
        if self.external_om_conf["exist"] == "false":
            self.external_om_conf["state"] = ST_ADD
            self.external_om_conf["exist"] = "true"
            self.external_om_conf[STR_SUBNET] = external_om_subnet
            self.external_om_conf[STR_VLAN] = external_om_vlan
            self.external_om_conf[STR_GATEWAY] = external_om_gateway
            self.external_om_conf[STR_POOL_START] = external_om_poolstart
            self.external_om_conf[STR_POOL_END] = external_om_poolend
            self.external_om_conf[STR_PROVIDER] = external_om_provider
        else:
            if (external_om_subnet != cur_subnet or
                        external_om_vlan != cur_vlan or
                        external_om_gateway != cur_gateway or
                        external_om_poolstart != cur_pool_start or
                        external_om_poolend != cur_pool_end or
                        external_om_provider != cur_provider):
                if self.external_om_conf["state"] == ST_ORIG:
                    self.external_om_conf["state"] = ST_DIRTY
                self.external_om_conf[STR_SUBNET] = external_om_subnet
                self.external_om_conf[STR_VLAN] = external_om_vlan
                self.external_om_conf[STR_GATEWAY] = external_om_gateway
                self.external_om_conf[STR_POOL_START] = external_om_poolstart
                self.external_om_conf[STR_POOL_END] = external_om_poolend
                self.external_om_conf[STR_PROVIDER] = external_om_provider
        logger.error("om_conf=" + str(self.external_om_conf))

    def config_external_api(self):
        if self.init_flag is False:
            self.nw_init()
        # 前处理
        def_value = self.pre_config_external_api()

        def_value[STR_VLAN] = None
        sysintfnw_list = fs_network_util.get_sysintfnw_list()
        for item in sysintfnw_list:
            if item["name"] == NetworkConstant.STR_NET_TYPE_API:
                def_value[STR_VLAN] = item[STR_VLAN]
                def_value[STR_PROVIDER] = item.get(STR_PROVIDER, 'physnet1')

        if def_value[STR_VLAN] is None:
            warning_msg = "Please build external_api by cps cli before configuration."
            logger.info(warning_msg)
            print warning_msg
            return

        cur_subnet = def_value[STR_SUBNET]
        cur_vlan = def_value[STR_VLAN]
        cur_gateway = def_value[STR_GATEWAY]
        cur_pool_start = def_value[STR_POOL_START]
        cur_pool_end = def_value[STR_POOL_END]
        cur_provider = def_value[STR_PROVIDER]

        # vlan
        external_api_vlan = cur_vlan
        external_api_provider = cur_provider
        # 网络地址
        prompt = PrintUtil.get_msg(["please set subnet for external_api network",
                                    "请输入external_api网络的网络地址"]) + (" [%s]:" % cur_subnet)
        external_api_subnet = utils.get_user_input_default_check(prompt, cur_subnet, utils.is_subnet)

        # 起始ip地址
        prompt = "please set subnet ip pool start address that created in neutron for external_api " + (" [%s]:" % cur_pool_start)
        
        while 1:
            try:
                external_api_poolstart = raw_input(prompt).strip()
                if external_api_poolstart == "":
                    external_api_poolstart = str(cur_pool_start)
                if utils.is_ip(external_api_poolstart):
                    if utils.is_ip_in_subnet(external_api_poolstart,external_api_subnet):
                        break
        
                print "input illegal, input again"
                continue
        
            except KeyboardInterrupt:
                sys.exit(1)
            except Exception:
                print "please input again"
                continue
        
        # 终止ip地址
        prompt = "please set subnet ip pool end address that created in neutron for external_api " + (" [%s]:" % cur_pool_end)
        
        while 1:
            try:
                external_api_poolend = raw_input(prompt).strip()
                if external_api_poolend == "":
                    external_api_poolend = str(cur_pool_end)
                if utils.is_ip(external_api_poolend):
                    if utils.is_ip_in_subnet(external_api_poolend,external_api_subnet):
                        if utils.is_secondip_larger(external_api_poolstart,external_api_poolend):
                            break
        
                print "input illegal, input again"
                continue
        
            except KeyboardInterrupt:
                sys.exit(1)
            except Exception:
                print "please input again"
                continue
        
        
        # 网关
        prompt = "please set gateway for external_api network" + " such as %s or empty:" % cur_gateway
        
        while 1:
            try:
                external_api_gateway = raw_input(prompt).strip()
                if external_api_gateway == "":
                    break
                if utils.is_ip(external_api_gateway):
                    if utils.is_gateway_legal(external_api_gateway,external_api_subnet,external_api_poolstart,external_api_poolend):
                        break
        
                print "input illegal, input again"
                continue
        
            except KeyboardInterrupt:
                sys.exit(1)
            except Exception:
                print "please input again"
                continue

        # 分别处理
        self.external_api_conf = {}
        self.external_api_conf[STR_SUBNET] = external_api_subnet
        self.external_api_conf[STR_VLAN] = external_api_vlan
        self.external_api_conf[STR_GATEWAY] = external_api_gateway
        self.external_api_conf[STR_POOL_START] = external_api_poolstart
        self.external_api_conf[STR_POOL_END] = external_api_poolend
        self.external_api_conf[STR_PROVIDER] = external_api_provider
        logger.error("api_conf=" + str(self.external_api_conf))

        #保存到配置文件中
        self.save_external_api_info(external_api_vlan, external_api_subnet, external_api_gateway,external_api_poolstart, external_api_poolend)

    def save_external_api_info(self, vlan, subnet, gateway, poolstart, poolend):
        print "save"
        config = ConfigParser.RawConfigParser()
        config.read(NetworkConstant.NETWORK_INI_PATH)
        if not config.has_section(NetworkConstant.NETWORK_SECTION):
            config.add_section(NetworkConstant.NETWORK_SECTION)
        config.set(NetworkConstant.NETWORK_SECTION, NetworkConstant.EXTERNAL_API_VLAN, vlan)
        config.set(NetworkConstant.NETWORK_SECTION, NetworkConstant.EXTERNAL_API_SUBNET, subnet)
        config.set(NetworkConstant.NETWORK_SECTION, NetworkConstant.EXTERNAL_API_GATEWAY, gateway)
        config.set(NetworkConstant.NETWORK_SECTION, NetworkConstant.EXTERNAL_API_POOL_START, poolstart)
        config.set(NetworkConstant.NETWORK_SECTION, NetworkConstant.EXTERNAL_API_POOL_END, poolend)
        with open(NetworkConstant.NETWORK_INI_PATH, 'w') as fd:
            config.write(fd)


    def parse_external_api_info(self):
        config = ConfigParser.RawConfigParser()
        config.read(fs_network_constant.NetworkConstant.NETWORK_INI_PATH)
        try:
            vlan = config.get(fs_network_constant.NetworkConstant.NETWORK_SECTION,fs_network_constant.NetworkConstant.EXTERNAL_API_VLAN)
            subnet = config.get(fs_network_constant.NetworkConstant.NETWORK_SECTION,fs_network_constant.NetworkConstant.EXTERNAL_API_SUBNET)
            gateway = config.get(fs_network_constant.NetworkConstant.NETWORK_SECTION,fs_network_constant.NetworkConstant.EXTERNAL_API_GATEWAY)
            pool_start = config.get(fs_network_constant.NetworkConstant.NETWORK_SECTION,fs_network_constant.NetworkConstant.EXTERNAL_API_POOL_START)
            pool_end = config.get(fs_network_constant.NetworkConstant.NETWORK_SECTION,fs_network_constant.NetworkConstant.EXTERNAL_API_POOL_END)
        except :
            logger.error("parse_external_api_info exception: %s" % (traceback.format_exc()))
            return (False, None, None, None, None, None)

        if vlan is None or subnet is None or gateway is None or pool_start is None or  pool_end is None:
            return (False, None, None, None, None, None)

        return (True,vlan, subnet, gateway, pool_start, pool_end)


    def validate_cps_api(self, vlan):
        content = {"name": "external_api", "vlan": vlan}
        flag = cps_server.update_sys_interfaces(content)
        msg = "validate cps external_api vlan=%s, ret=%s" % (vlan, str(flag))
        logger.error(msg)
        print msg

    def validate_api_ex(self):
        # 将生效这个部分中的数据获取 转化成从配置文件中读取
        (flag, vlan, subnet, gateway, pool_start, pool_end) = self.parse_external_api_info()
        if self.init_flag is False:
            self.nw_init()

        if not flag:
            return
        if self.external_api_conf is None:
            self.external_api_conf = {}

        provider = ""
        sysintfnw_list = fs_network_util.get_sysintfnw_list()
        for item in sysintfnw_list:
            if item["name"] == NetworkConstant.STR_NET_TYPE_API:
                provider = item.get(STR_PROVIDER, 'physnet1')

        self.external_api_conf[STR_VLAN] = vlan
        self.external_api_conf[STR_SUBNET] = subnet
        self.external_api_conf[STR_GATEWAY] = gateway
        self.external_api_conf[STR_POOL_START] = pool_start
        self.external_api_conf[STR_POOL_END] = pool_end
        self.external_api_conf[STR_PROVIDER] = provider

        if self.cur_external_api_info.has_key(STR_VLAN) and self.cur_external_api_info.has_key(STR_SUBNET) \
           and self.cur_external_api_info.has_key(STR_POOL_START) and self.cur_external_api_info.has_key(STR_POOL_END) \
           and self.cur_external_api_info.has_key(STR_PROVIDER) and self.cur_external_api_info.has_key(STR_GATEWAY):
            if str( self.cur_external_api_info[STR_VLAN] ) == self.external_api_conf[STR_VLAN]:
                if str( self.cur_external_api_info[STR_SUBNET] ) == self.external_api_conf[STR_SUBNET]:
                    if str( self.cur_external_api_info[STR_POOL_START] ) == self.external_api_conf[STR_POOL_START]:
                        if str( self.cur_external_api_info[STR_POOL_END] ) == self.external_api_conf[STR_POOL_END]:
                            if str( self.cur_external_api_info[STR_PROVIDER] ) == self.external_api_conf[STR_PROVIDER]:
                                if ( not self.cur_external_api_info[STR_GATEWAY] ) and "" == self.external_api_conf[STR_GATEWAY]:
                                    print "the same external_api network is existed"
                                    return
                                if str( self.cur_external_api_info[STR_GATEWAY] ) == str( self.external_api_conf[STR_GATEWAY] ):
                                    print "the same external_api network is existed"
                                    return

        logger.info("going to validate external_api")
        print "going to validate external_api"

        # 如果网络已经存在，要先删除
        if self.cur_external_api_info.has_key("subnet_id"):
            subnet_id = self.cur_external_api_info["subnet_id"]
            flag = deleteSubnet(subnet_id, self.token, self.neutron_url)
            msg = "delete subnet result=%s id=%s" % (str(flag), str(subnet_id))
            logger.info(msg)
            print msg

        if self.cur_external_api_info.has_key("net_id"):
            net_id = self.cur_external_api_info["net_id"]
            flag = deleteNet(net_id, self.token, self.neutron_url)
            msg = "delete net result=%s id=%s" % (str(flag), str(net_id))
            logger.info(msg)
            print msg

        # 创建网络
        name = "external_api"
        net_id = createNet(name, "vlan", vlan, provider, "true", self.token, self.neutron_url)
        if net_id is None:
            msg = "add net fail, name=%s vlan=%s" % (name, str(vlan))
            logger.error(msg)
            print msg
        else:
            print "add net success, name=%s vlan=%s" % (name, str(vlan))

        # 创建子网
        subnet_name = name + "_subnet"

        dnsserver_ip_offset = self._get_dns_server_ip()
        dnsserver_ip_base = socket.ntohl(struct.unpack('I',socket.inet_aton(pool_start))[0])
        dnsserver_ip = socket.inet_ntoa(struct.pack('I',socket.htonl(dnsserver_ip_base + int(dnsserver_ip_offset))))

        subnet_res = createSubnet(name, net_id, subnet_name, subnet, pool_start, pool_end, gateway, self.token,
                                  self.neutron_url, dnsserver_ip)
        if subnet_res is None:
            msg = "add subnet fail, name=%s gateway=%s" % (subnet_name, str(gateway))
            logger.error(msg)
            print msg
        else:
            print "add subnet success, name=%s gateway=%s" % (subnet_name, str(gateway))

    def validate_om(self):
        state = self.external_om_conf["state"]
        if state == ST_ORIG:
            return
        logger.info("going to validate external_om")
        print "going to validate external_om"
        name_external_om = "external_om"
        orig_external_om_sysintf = None

        # 获取到所有的hostcfg信息
        network_group_list = []
        cps_server_url = cps_server.get_cpsserver_url()
        group_list = cps_server.get_network_group_list()
        for one_group in group_list:
            group_detail = cps_server.get_network_group_detail(one_group["name"])
            network_group_list.append(group_detail)

        # 获取当前的external_om的配置信息
        sysintf_list = cps_server.get_sys_interfaces_list()
        cur_vlan = self.external_om_conf[STR_VLAN]
        for ont_sysintf in sysintf_list:
            if ont_sysintf["name"] == name_external_om:
                orig_external_om_sysintf = ont_sysintf
            elif ont_sysintf["vlan"] == cur_vlan:
                logger.error("vlan id conflict, vlan id: %s" % cur_vlan)
                PrintUtil.print_msg_ex(VLAN_ID_CONFLICT, cur_vlan, error=True)
                return

        # 先删除sysintfnwmapping,才能删除sysintfnw
        for one_group in network_group_list:
            #存在这个mapping的才需要删除
            if not self.has_external_om_sysintfmapping(one_group):
                continue
            ret = fsCpsCliOpt.net_host_cfg_sysintfnw_delete(one_group["name"], name_external_om, cps_server_url)
            msg = "delete sysintfnwmapping for external_om of %s, ret=%s" % (one_group["name"], str(ret))
            logger.info(msg)
            print msg

        # 删除sysintfnw
        ret = cps_server.delete_sys_interfaces(name_external_om)
        msg = "delete sysintfnw external_om, ret=%s" % (str(ret))
        logger.info(msg)
        print msg

        # 添加sysintfnw
        if orig_external_om_sysintf is None:
            orig_external_om_sysintf = {}
            orig_external_om_sysintf["ip"] = "neutron_dhcp"
            orig_external_om_sysintf["description"] = "System external om network."
            orig_external_om_sysintf["qos"] = {"tx_limit": None, "tx_burst_limit": None, "tx_peak_limit": None}

        orig_external_om_sysintf["name"] = name_external_om
        orig_external_om_sysintf[STR_SUBNET] = self.external_om_conf[STR_SUBNET]
        orig_external_om_sysintf[STR_VLAN] = self.external_om_conf[STR_VLAN]
        orig_external_om_sysintf[STR_GATEWAY] = self.external_om_conf[STR_GATEWAY]
        orig_external_om_sysintf["ippool"] = {"start": self.external_om_conf[STR_POOL_START],
                                              "end": self.external_om_conf[STR_POOL_END]}
        orig_external_om_sysintf[STR_PROVIDER] = self.external_om_conf[STR_PROVIDER]
        ret = cps_server.create_sys_interfaces(orig_external_om_sysintf)
        msg = "add sysintfnw external_om, ret=%s" % (str(ret))
        logger.info(msg)
        print msg

        # 添加sysintfnwmapping
        for one_group in network_group_list:
            if not self.has_provider_mapping(one_group, self.external_om_conf[STR_PROVIDER]):
                continue
            sysintfmapping_om = {"name": name_external_om}
            ret = fsCpsCliOpt.net_hostcfg_sysintfnw_add(one_group["name"], sysintfmapping_om, cps_server_url)
            msg = "add sysintfnwmapping for external_om of %s, ret=%s" % (one_group["name"], str(ret))
            logger.info(msg)
            print msg

    def _get_dns_server_ip(self):
        """
        获取dnsserver_ip
        """
        netpolicyFile = "/etc/huawei/fusionsphere/cfg/netpolicy.json"
        with open(netpolicyFile) as fdNetpolicy:
            content = json.loads(fdNetpolicy.read())
        return str(content["ippolicy"]["servicesippolicy"]["dns-server"]["floatingip"])

    def _vaildate_internal_base_api(self, provider):
        """
        创建inter_base网络
        """
        #查询是否有创建的网络，名字为network_name = "internal_base"。若不存在，则创建；若存在，则继续。

        if self.internal_base_conf[NET_EXIST].upper() == "FALSE":
            net_id = createNet("internal_base", 'flat', '0', provider, 'false', self.token, self.neutron_url)
            if net_id is None:
                logger.error("fail to create net")
                return False
            else:
                self.internal_base_conf["net_id"] = net_id
                self.internal_base_conf[STR_VLAN] = '0'
                self.internal_base_conf[NET_EXIST] = "true"

        #查询是否存在子网,名字为”internal_base“。若不存在，则创建，若存在，则继续。
        if self.internal_base_conf["exist"].upper() == "FALSE":
            #从sys.ini中获取
            sysFile = "/etc/huawei/fusionsphere/cfg/sys.ini"
            sysconfig = ConfigParser.RawConfigParser()
            sysconfig.read(sysFile)
            iprange = sysconfig.get("internal_base", "managevm_ip_pool")

            pool_start = iprange.split("-")[0]
            pool_end = iprange.split("-")[1]
            #255给广播地址，删除
            if pool_end.endswith("255"):
                pool_end = pool_end[0:len(pool_end) - 1]
                pool_end += "4"

            gateway_ip = ''
            netmask = sysconfig.get("internal_base", "netmask")
            netmasks = netmask.split(".")

            #统计网络id数
            bit_size = 0
            for net in netmasks:
                str_bin = str(bin(int(net)))
                if str_bin.endswith("1"):
                    bit_size += 8
                else:
                    bit_size += 10 - len(str_bin.replace("1", ""))
                    break

            cidr = pool_start + "/" + str(bit_size)
            cidr_split = cidr.split(".")
            cidr = cidr_split[0] + "." + cidr_split[1] + ".0." + cidr_split[3]
            net_name = "internal_base"
            net_id = self.internal_base_conf["net_id"]
            sub_name = "sub_internal_base"

            #netpolicy.json中获取dnsserver_ip
            dnsserver_ip_offset = self._get_dns_server_ip()
            mng_ippool = sysconfig.get("internal_base", "known_ip_pool")
            mng_ippool_start = mng_ippool.split("-")[0]
            dnsserver_ip_base = socket.ntohl(struct.unpack('I',socket.inet_aton(mng_ippool_start))[0])
            dnsserver_ip = socket.inet_ntoa(struct.pack('I',socket.htonl(dnsserver_ip_base + int(dnsserver_ip_offset))))

            subnet_info = createSubnet(net_name, net_id, sub_name, cidr, pool_start, pool_end,
                                       gateway_ip,
                                       self.token,
                                       self.neutron_url,
                                       dnsserver_ip)
            if subnet_info is None:
                logger.error("fail to create subnet")
                return False
            else:
                self.internal_base_conf["subnet_id"] = subnet_info["subnet"]["id"]
                self.internal_base_conf[STR_SUBNET] = cidr
                self.internal_base_conf[STR_GATEWAY] = gateway_ip
                self.internal_base_conf[STR_POOL_START] = pool_start
                self.internal_base_conf[STR_POOL_END] = pool_end
                self.internal_base_conf["exist"] = "true"
                self.internal_base_conf["dnsserver_ip_mng"] = dnsserver_ip
                return True


    def validate_internal_base_api(self):
        config = ConfigParser.RawConfigParser()
        config.read(fs_network_constant.NetworkConstant.NETWORK_INI_PATH)
        if not config.has_option(fs_network_constant.NetworkConstant.NETWORK_SECTION,
                                 fs_network_constant.NetworkConstant.NETWORK_OPTION_INTERNAL_BASE_FLAG):
            return
        flag = config.get(fs_network_constant.NetworkConstant.NETWORK_SECTION,
                          fs_network_constant.NetworkConstant.NETWORK_OPTION_INTERNAL_BASE_FLAG)
        network_list = fs_network_util.get_sysintfnw_list()
        for item in network_list:
            if item["name"] == NetworkConstant.STR_NET_TYPE_BASE:
                provider = item.get(STR_PROVIDER, 'physnet1')
        if str(flag) == "y":
            try:
                print "start build internal base"
                if self.init_flag is False:
                    self.nw_init()
                if self._vaildate_internal_base_api(provider) is False:
                    logger.error("fail to vaildate internal base")
                    print "Fail to vaildate internal base."
                else:
                    print "Build internal base successfully"
            except Exception:
                logger.error("fail to vaildate internal base,exception is %s." % traceback.format_exc())


    def validate_api(self):
        if self.external_api_conf is None:
            return

        # 修改cps那边的api网络平面信息
        vlan = self.external_api_conf[STR_VLAN]
        self.validate_cps_api(vlan)

        # 生效到neutron那边去,移动到其他地方了

    def config(self, config_type, choice):
        logger.debug("config type = %s" %config_type)
        if choice == "4":
            if self.init_flag is False:
                self.nw_init()
        config_func = self.part_map[choice]
        if config_func is not None:
            config_func()

    def validate(self, validate_type, phase):
        if validate_type == utils.TYPE_DEPLOY_CONFIG:
            if phase != utils.PHASE_POST:
                return True
            self.validate_api()
        else:
            self.validate_api()

        return True

    def create_def_config(self, configger):
        pass


def test():
    mgr = OpenStackNetwokCfgProc()
    choise = sys.argv[1]
    print "choise=" + str(choise)
    if choise == "4":
        mgr.config_external_api()

    mgr.validate(utils.TYPE_ONLY_CONFIG, 0)


if __name__ == "__main__":
    test()

