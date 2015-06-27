#!/usr/bin/env python
#-*-coding:utf-8-*-

import sys
import copy
import ConfigParser
import re
import fs_log_util
import cps_server
from os.path import join
import os
import fsCpsCliOpt
from fs_network_constant import NetworkConstant
import fsutils as utils
from print_msg import PrintMessage as PrintUtil

ST_ORIG = "orig"
ST_ADD = "add"
ST_DEL = "del"
ST_DIRTY = "dirty"
ST_UPDATE = "update"
ST_ONLY_VLAN = "only vlan"

STR_NET_TYPE_API = "external_api"
STR_NET_TYPE_OM = "external_om"

STR_NAME = "name"
STR_STATE = "state"
STR_SUBNET = "subnet"
STR_GATEWAY = "gateway"
STR_VLAN = "vlan"
STR_POOL = "ippool"
STR_START = "start"
STR_END = "end"
STR_PROVIDER = "provider_name"
NET_EXIST = "net_exist"
SUB_EXIST = "sub_exist"

PROTECTED_SYSINTFNW = ["internal_base", "storage_data0", "storage_data1", "tunnel_bearing"]
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
Logger = fs_log_util.localLog.get_logger(LOG_FILE)
cps_server_url = cps_server.get_cpsserver_url()


def parse_config(file_name, section, option):
    cps_config = ConfigParser.RawConfigParser()
    cps_config.read(file_name)
    return cps_config.get(section, option)

def save_config(file_name, section, option, value):
    Logger.info("write to config file: %s, section: %s" % (NetworkConstant.NETWORK_INI_PATH, section))
    cps_config = ConfigParser.RawConfigParser()
    cps_config.read(file_name)
    sectionList = cps_config.sections()
    if section not in sectionList:
        cps_config.add_section(section)
    cps_config.set(section, option, value)
    with open(file_name, 'w') as fp:
        cps_config.write(fp)

def get_provider_list():
    provider_list = cps_server.get_provider_list()
    return provider_list


def get_sysintfnw_list():
    sysintfnw_list = cps_server.get_sys_interfaces_list()
    return sysintfnw_list


def get_network_hostcfg_list():
    group_list = cps_server.get_network_group_list()
    return group_list


def get_network_hostcfg_detail(group_name):
    group_detail = cps_server.get_network_group_detail(group_name)
    return group_detail


def is_host_in_group(hostid, network_group_list):
    for one_detail in network_group_list:
        if one_detail["name"] == "default":
            continue

        if not one_detail.has_key("hosts"):
            continue

        host_sum = one_detail["hosts"]
        if not host_sum.has_key("hostid"):
            continue

        if hostid in one_detail["hosts"]["hostid"]:
            return True

    return False

def is_host_in_group_details(hostid, network_group_list):
    for one_detail in network_group_list:
        if one_detail["name"] == "default":
            continue

        if hostid in one_detail["hosts"]["hostid"]:
            return True,one_detail

    return False,None

def get_hostcfg_summany():
    network_group_list = []
    isolate_host_list = []
    lst_allhostid, allhostsip = cps_server.get_all_hosts()
    Logger.info("get_hostcfg_summany allhostsip=%s" % allhostsip)
    group_list = get_network_hostcfg_list()
    for one_group in group_list:
        group_detail = get_network_hostcfg_detail(one_group["name"])
        network_group_list.append(group_detail)

    # 找出还没有配置到group的hostid
    for one_host_id in lst_allhostid:
        if is_host_in_group(one_host_id, network_group_list) is False:
            isolate_host_list.append(one_host_id)

    return (network_group_list, isolate_host_list, lst_allhostid)

def find_host_in_exist_hostcfg(lst_host):
    Logger.info("Enter in find_host_in_exist_hostcfg. lst_host:%s" % lst_host)
    network_group_list = []
    isolate_host_list = []
    dct_host_network_info = {}
    group_list = get_network_hostcfg_list()
    for one_group in group_list:
        group_detail = get_network_hostcfg_detail(one_group["name"])
        network_group_list.append(group_detail)

    for hostid in lst_host:
        bFlag,dct_network = is_host_in_group_details(hostid, network_group_list)
        if not bFlag:
            isolate_host_list.append(hostid)
        else:
            dct_host_network_info[hostid] = dct_network

    return dct_host_network_info, isolate_host_list

class NetworkHostcfgMgr():
    def __init__(self):
        self.cps_server_url = cps_server_url
        self.cur_provider_list = get_provider_list()
        self.cur_sysintfnw_list = get_sysintfnw_list()
        (hostcfg_list, isolate_host_list, all_hostid) = get_hostcfg_summany()
        self.cur_hostcfg_list = hostcfg_list
        self.all_hosts_id = all_hostid
        self.isolate_host_list = isolate_host_list
        # 填充一些额外的信息,group的pci信息
        self.get_hostcfg_extra_info()
        self.hostcfg_add = []

        # 配置网络的信息缓存

    def hostcfg_has_host(self, one_hostcfg):
        if not one_hostcfg.has_key("hosts"):
            return False

        host_sum = one_hostcfg["hosts"]
        if not host_sum.has_key("hostid"):
            return False

        return True

    def check_is_our_group(self, group_name):
        if group_name.startswith("group"):
            group_index = group_name.lstrip("group")
            if self.check_is_digit(group_index):
                return True
        return False
    def get_hostcfg_extra_info(self):
        # 填充hostcfg的pci信息
        for one_hostcfg in self.cur_hostcfg_list:
            if one_hostcfg["name"] == "default":
                continue

            if not self.hostcfg_has_host(one_hostcfg):
                continue

            one_host_id = one_hostcfg["hosts"]["hostid"][0]
            #存在hostid的单板还没有在host_list中
            if one_host_id not in self.all_hosts_id:
                print '%s does not exsit currently' % one_host_id
                raise Exception,'add such host or delete the hostcfg item first'
            pci_info = self.get_host_pci_info(one_host_id)
            one_hostcfg["group_pci"] = pci_info

    def get_max_bond(self, one_hostcfg):
        i_max_bond_index = 0
        if not one_hostcfg.has_key("bond"):
            return i_max_bond_index
        bond_list = one_hostcfg["bond"]
        if (bond_list is None) or (len(bond_list) == 0):
            return i_max_bond_index
        name_list =  [item['name'] for item in bond_list]
        bond_number_list = []
        for bond_name in name_list:
            bond_number = bond_name.lstrip("trunk")
            if bond_number.isdigit():
                bond_number_list.append(int(bond_number))
        i_max = max(bond_number_list) + 1
        return i_max

    def get_max_provider_num(self, lst_provider):
        lst_name = []
        for item in lst_provider:
            name = item["name"]
            if name.find("physnet") is not -1 :
                provider_no = name.strip("physnet")
                if provider_no.isdigit():
                    lst_name.append(provider_no)

        str_max_provider = max(lst_name)
        return int(str_max_provider)

    def get_available_bond_list(self, one_hostcfg):
        bond_list = []
        bond_list = bond_list + one_hostcfg.get(NetworkConstant.NETWORK_HOSTCFG_BOND, [])
        available_bond_name = [item["name"] for item in bond_list]
        if one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD):
            for bond_add in one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD]:
                bond_name = bond_add.keys()[0]
                bond_content = bond_add[bond_name]
                new_bond = {"name": bond_name,
                            "slaves": bond_content["slaves"],
                            "bond_mode": bond_content["bond_mode"]}
                available_bond_name.append(bond_name)
                bond_list.append(new_bond)

        available_bond_name = list(set(available_bond_name))
        temp_providermapping_list = one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_PROVIDERMAPPING] + \
                                    one_hostcfg.get(NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD, [])
        for providermapping in temp_providermapping_list:
            if providermapping["interface"] in available_bond_name:
                available_bond_name.remove(providermapping["interface"])
        available_bond_list = []
        for bond in bond_list:
            if bond["name"] in available_bond_name:
                available_bond_list.append(bond)

        return available_bond_list, available_bond_name

    def get_host_pci_info(self, host_id):
        host_detail = cps_server.get_host_detail_info(host_id)
        if host_detail is None:
            return None

        host_ethinfo = host_detail['ethinfo']
        pci_list = []
        for dct_eth in host_ethinfo:
            str_mac = dct_eth.keys()[0]
            str_port_info = "%s=%s" % (dct_eth[str_mac]["pci"], dct_eth[str_mac]["speed"])
            pci_list.append(str_port_info)
        return pci_list

    def count_pci_num(self, pci, pci_list):
        i = 0
        for each in pci_list:
            if pci == each:
                i = i + 1
        return i

    def port_compare(self, port1, port2):
        item_list = port1["pci"].split("=")
        port1_ind = item_list[0] + item_list[2]

        item_list = port2["pci"].split("=")
        port2_ind = item_list[0] + item_list[2]

        if port1_ind > port2_ind:
            return 1
        if port1_ind == port2_ind:
            return 0
        return -1

    def is_port_in_nic_list(self, port, nic_list):
        pci_info = port["pci"]
        pci = pci_info.split("=")[0]
        dev_id = pci_info.split("=")[2]

        for item in nic_list:
            option = item["option"]
            if not isinstance(option, dict):
                continue
            if not option.has_key("PCISLOT"):
                continue
            item_pci = option["PCISLOT"]
            item_dev_id = "0x0"
            if option.has_key("dev_id"):
                item_dev_id = option["dev_id"]
            if (item_pci == pci) and (item_dev_id == dev_id):
                return True
        return False

    def get_hostcfg_portlist(self, one_hostcfg):
        lst_port = []
        total_port_list = []
        exist_ethname_list = []

        # hostcfg中存在的
        nic_list = one_hostcfg["nic"]
        Logger.info("nic_list=%s" % str(nic_list))
        for one_nic in nic_list:
            exist_ethname_list.append(one_nic["name"])

        # 先把本hostcfg的信息收集起来
        one_host_id = one_hostcfg["hosts"]["hostid"][0]
        Logger.info("get port list from host=%s" % str(one_host_id))
        host_ethinfo = cps_server.get_host_detail_info(one_host_id)["ethinfo"]
        Logger.info("ethinfo =%s" % str(host_ethinfo))
        for one_eth_info in host_ethinfo:
            str_mac = one_eth_info.keys()[0]
            eth_detail = one_eth_info[str_mac]
            pci_detail = "%s=%s=%s" % (eth_detail["pci"], eth_detail["speed"], eth_detail["dev_id"])
            eth_name = eth_detail["name"]
            if eth_name is None or (len(eth_name) == 0):
                temp_eth = {"ref":"false", "pci":pci_detail}
                total_port_list.append(temp_eth)
            else:
                exist_ethname_list.append(eth_name)

        # 防止host-show中的信息有延迟，再次进行过滤
        for item in total_port_list:
            if self.is_port_in_nic_list(item, nic_list):
                total_port_list.remove(item)

        # 按pci和devid进行排序,需要排序，保证每次都是一样的
        total_port_list.sort(cmp=self.port_compare)
        Logger.info("after sort, port_list=%s" % str(total_port_list))

        # 在提取已经使用的，并计算出最大名字
        if len(exist_ethname_list) == 0:
            max_eth = 0
        else:
            max_num = 0
            for one_name in exist_ethname_list:
                num = int(one_name.strip("eth"))
                if num > max_num:
                    max_num = num
            max_eth = max_num + 1

        for item in total_port_list:
            eth_name = "eth%s" % max_eth
            item["name"] = eth_name
            lst_port.append(item)
            max_eth = max_eth + 1

        return lst_port

    def get_port_dev_id_by_name(self, port, lst_port):
        dev_id = ""
        for dctPort in lst_port:
            if dctPort["name"] == port:
                networkPci = dctPort["pci"]
                networkList =  networkPci.split("=")
                if len(networkList) == 3:
                    dev_id = networkList[2]
                break

        return dev_id

    def get_port_pci_by_name(self, str_name, lst_port):
        for dctPort in lst_port:
            if dctPort["name"] == str_name:
                return dctPort["pci"].split("=")[0]
        else:
            return None

    def create_nic(self, port_info, lst_port):
        nic_instance = None
        if port_info.find(":") >= 0:
            vf_num = port_info.split(":")[1]
            port = port_info.split(":")[0]
            dev_id = self.get_port_dev_id_by_name(port, lst_port)
            if dev_id != "":
                nic_instance = {"name":port,
                                "option":{"PCISLOT":self.get_port_pci_by_name(port, lst_port), "dev_id" : dev_id},
                                "vf_num":vf_num}
            else:
                nic_instance = {"name":port,
                                "option":{"PCISLOT":self.get_port_pci_by_name(port, lst_port)},
                                "vf_num":vf_num}
        else:
            port = port_info
            dev_id = self.get_port_dev_id_by_name(port, lst_port)
            if dev_id != "":
                nic_instance = {"name":port,
                                 "option":{"PCISLOT":self.get_port_pci_by_name(port, lst_port),
                                            "dev_id": dev_id}}
            else:
                nic_instance = {"name":port,
                                "option":{"PCISLOT":self.get_port_pci_by_name(port, lst_port)}}
        return nic_instance


    def check_provider(self, result, exist):
        if len(result.split(",")) != 2:
            return False

        str_provider = result.split(",")[0]
        str_maptype = result.split(",")[1]
        if str_provider not in [item["name"] for item in self.cur_provider_list]:
            PrintUtil.print_msg(["provider not exist, please input again", "provider不存在，请重新输入"])
            return False
        if str_provider in exist:
            PrintUtil.print_msg(["provider has configed, please input again", "provider已经配置，请重新输入"])
            return False

        if str_maptype not in NetworkConstant.LST_MAPPING_TYPE_COMPATIBLE:
            print PrintUtil.get_msg(["mode not exist, please input again,support:", "mode不存在，请重新输入,支持:"]) \
                                          + str(["ovs","vhostuser", "hardware-veb", "netmap"])
            return False

        return True

    def check_eth_name(self, eth_name, port_list):
        temp_name = None
        if eth_name.find(":") != -1:
            str_list = eth_name.split(":")
            if len(str_list) != 2:
                return False
            temp_name = str_list[0]
            vf_num = str_list[1]
            if self.check_is_digit(vf_num) is False:
                return False
        else:
            temp_name = eth_name

        for one_eth in port_list:
            name = one_eth["name"]
            if temp_name == name:
                return True

        return False

    def check_bond_eth(self, input_eth, port_list):
        if input_eth.find(",") == -1:
            return False

        eth_list = input_eth.split(",")
        if len(eth_list) < 2:
            return False

        for one_eth_name in eth_list:
            if self.check_eth_name(one_eth_name, port_list) is False:
                return False

        return True

    def check_vlan_range(self, input_str):
        if input_str.find(",") == -1:
            return False

        vlan_list = input_str.split(",")
        if len(vlan_list) != 2:
            return False

        for one_vlan in vlan_list:
            if one_vlan.isdigit() is False:
                return False

        if int(vlan_list[0]) > int(vlan_list[1]):
            return False

        for one_vlan in vlan_list:
            if not ( int(one_vlan) >= 1 and int(one_vlan) <= 4094 ):
                return False

        return True

    def check_is_vf_port(self, eth_name):
        if eth_name.find(":") != -1:
            return True
        else:
            return False
    def get_port_vf_num(self, eth_name):
        if eth_name.find(":") == -1:
            return -1

        try:
            return int(eth_name.split(":")[1])
        except IndexError,e:
            return -1
        except ValueError, e:
            return -1
        except e:
            return -1

    @staticmethod
    def check_is_digit(input_str):
        return input_str.isdigit()

    def is_illegal_itf_name(self, name):
        if (name is None) or (name == ""):
            return False

        if len(name.split(" ")) != 1:
            return False

        expre = "^eth\d+$"
        expre2 = "^trunk\d+$"
        pat = re.compile(expre)
        pat2 = re.compile(expre2)

        match = pat.match(name)
        match2 = pat2.match(name)
        if (match is not None) or (match2 is not None):
            return True

        return False

    def replace_sysintfnwmapping_change(self, lst_sysintfnwmapping_change, lst_sysintfnwmapping):
        def delete_item(name, lst_sysintfnwmapping):
            for item in lst_sysintfnwmapping:
                if item["name"] == name:
                    lst_sysintfnwmapping.remove(item)
                    break

        for dct_item in lst_sysintfnwmapping_change:
            str_name = dct_item["name"]
            delete_item(str_name, lst_sysintfnwmapping)
            lst_sysintfnwmapping.append(dct_item)

    def generate_host_groups(self, index_start, host_id_list):
        dct_host_eth = {}
        for str_hostid in host_id_list:
            host_detail = cps_server.get_host_detail_info(str_hostid)
            if host_detail is None:
                continue
            lst_ethinfo = host_detail['ethinfo']
            lst_pci = []
            for dct_eth in lst_ethinfo:
                str_mac = dct_eth.keys()[0]
                str_port_info = "%s=%s" % (dct_eth[str_mac]["pci"], dct_eth[str_mac]["speed"])
                lst_pci.append(str_port_info)
            dct_host_eth[str_hostid] = lst_pci

        dct_groups = {}
        for str_hostid in dct_host_eth:
            self.add_host_to_groups(dct_groups, index_start, dct_host_eth[str_hostid], str_hostid)

        return dct_groups

    def add_host_to_groups(self, dct_groups, index_start, host_pci, hostid):
        bFlag = False
        for item in dct_groups:
            if set(dct_groups[item]["pcis"]) == set(host_pci):
                dct_groups[item]["hosts"].append(hostid)
                bFlag = True

        if not bFlag:
            if len(dct_groups.keys()) == 0:
                index = index_start
            else:
                index = max(dct_groups.keys()) + 1
            dct_groups[index] = {"pcis":host_pci, "hosts":[hostid]}

    def find_hostcfg_by_pcis(self, pcis):
        one_hostcfg = None
        for one_hostcfg in self.cur_hostcfg_list:
            if one_hostcfg["name"] == "default":
                continue
            if not self.check_is_our_group(one_hostcfg["name"]):
                continue

        tmp_pcis = one_hostcfg.get("group_pci", None)
        if tmp_pcis is not None:
            if set(tmp_pcis) == set(pcis):
                return one_hostcfg
        return None

    def create_new_hostcfg(self):
        default_hostcfg = None
        for one_hostcfg in self.cur_hostcfg_list:
            if one_hostcfg["name"] == "default":
                default_hostcfg = one_hostcfg
                break

        new_hostcfg = copy.deepcopy(default_hostcfg)
        del new_hostcfg["hosts"]["default"]
        return new_hostcfg

    def isolate_group_proc(self, group_index, one_new_group):
        if group_index == 0:
            str_group = 'default'
        else:
            str_group = "group%s" % group_index
        group_pcis = one_new_group["pcis"]
        dest_hostcfg = self.find_hostcfg_by_pcis(group_pcis)
        if dest_hostcfg is not None:
            promt_english = "do you want to add hosts %s to hostcfg:%s" % (one_new_group["hosts"], dest_hostcfg["name"])\
                            + (" [y|n][n]:")
            result = utils.get_use_input_check_2(promt_english, 'n', ['y','n'])
            if result == 'n':
                return
            else:
                dest_hostcfg["host_add"] = one_new_group["hosts"]
                #更新孤立的节点列表
                for one_host_id in one_new_group["hosts"]:
                    self.isolate_host_list.remove(one_host_id)
                Logger.info("add host. dest_hostcfg:%s, cur_hostcfg_list:%s" % (dest_hostcfg, self.cur_hostcfg_list))
                return

        # hostcfg增加情况的处理
        tmp_str = ""
        for onet_host_id in one_new_group["hosts"]:
            tmp_str = tmp_str + onet_host_id + ","
        tmp_str.strip(",")

        promt_english = "do you want to add network hostcfg:%s for hosts:%s" % (str_group, \
                          tmp_str) + (" [y|n][n]:")
        result = utils.get_use_input_check_2(promt_english, 'n', ['y','n'])
        if result == 'n':
            return

        # 创建一个新的hostcfg
        new_hostcfg = self.create_new_hostcfg()
        new_hostcfg["name"] = str_group
        new_hostcfg["hosts"]["hostid"] = one_new_group["hosts"]
        #更新孤立的节点列表
        for one_host_id in one_new_group["hosts"]:
            self.isolate_host_list.remove(one_host_id)

        # 填充本hostcfg的pci信息
        one_host_id = new_hostcfg["hosts"]["hostid"][0]
        pci_info = self.get_host_pci_info(one_host_id)
        new_hostcfg["group_pci"] = pci_info

        # 进行修改
        self.hostcfg_add.append(new_hostcfg)
        self.modify_one_hostcfg(new_hostcfg)

    def validate_hostcfg_comm(self, one_hostcfg):
        one_group_name = one_hostcfg["name"]
        # 处理增加的nic
        if one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD):
            nic_add_list = one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD]
            if (nic_add_list is not None) and (len(nic_add_list) != 0):
                flag = fsCpsCliOpt.net_host_cfg_nics_add(one_group_name, nic_add_list, self.cps_server_url)
                msg = "add nic result=%s, nic_list=%s" % (str(flag), str(nic_add_list))
                Logger.info(msg)
                print msg

        # 处理增加的bond
        if one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD):
            bond_add_list = one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD]
            if (nic_add_list is not None) and (len(bond_add_list) != 0):
                for one_bond in bond_add_list:
                    flag = fsCpsCliOpt.net_host_cfg_bond_add(one_group_name, one_bond, self.cps_server_url)
                    msg = "add bond result=%s, bond=%s" % (str(flag), str(one_bond))
                    Logger.info(msg)
                    print msg

        # 处理增加的providermapping
        if one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD):
            providermapping_add_list = one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD]
            if (providermapping_add_list is not None) and (len(providermapping_add_list) != 0):
                for one_providermapping in providermapping_add_list:
                    Logger.info("going to add providermapping=" + str(one_providermapping))
                    flag = fsCpsCliOpt.net_host_cfg_provider_mapping_add(one_group_name, one_providermapping,
                                                                    self.cps_server_url)
                    msg = "add providermapping result=%s, content=%s" % (str(flag), str(one_providermapping))
                    Logger.info(msg)
                    print msg

        # 处理增加的sysintfnwmapping
        if one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE):
            sysintfnwmapping_chg_list = one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE]
            if (sysintfnwmapping_chg_list is not None) and (len(sysintfnwmapping_chg_list) != 0):
                for one_sysintfnwmapping in sysintfnwmapping_chg_list:
                    flag = fsCpsCliOpt.netHostcfgSysintfnwMappingChange(one_group_name, one_sysintfnwmapping,\
                                                                        self.cps_server_url)
                    msg = "change sysintfmapping result=%s, content=%s" % (str(flag), str(one_sysintfnwmapping))
                    Logger.info(msg)
                    print msg

    def change_provider(self):
        prompt = PrintUtil.get_msg(["do you want to change provider", "是否要修改已有的provider"]) + (" [y|n][n]:")
        result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
        if result == 'n':
            return

        for one_provider in self.cur_provider_list:
            def_vlan_range = one_provider["vlanpool"]["start"] + ","+ one_provider["vlanpool"]["end"]
            prompt = "do you want to change config for provider:%s[y|n][n]:" % one_provider["name"]
            result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
            if result == 'n':
                continue

            vlan_range = ""
            inputstr = "new config for provider:%s, vlan range:[start,end][%s]" % (one_provider['name'], def_vlan_range)
            def_flag = False
            while 1:
                try:
                    vlan_range = raw_input(inputstr)
                    if vlan_range == "":
                        def_flag = True
                        break
                    elif len(vlan_range.split(",")) != 2:
                        print PrintUtil.print_msg(["please input again", "请重新输入"])
                        continue
                    else:
                        break
                except KeyboardInterrupt:
                    sys.exit(1)
                except Exception:
                    print PrintUtil.print_msg(["please input again", "请重新输入"])
                    continue
            # vlan没有修改的话，就不需要设置
            if def_flag == True or vlan_range == def_vlan_range:
                continue

            one_provider["vlanpool"] = {"start":vlan_range.split(",")[0], "end":vlan_range.split(",")[1]}
            one_provider["state"] = ST_DIRTY

    def add_provider(self):
        Logger.debug("start to add provider")
        self.get_max_provider_num(self.cur_provider_list)
        def_vlan_range = "1,4000"
        while 1:
            prompt = PrintUtil.get_msg(["do you want to add provider", "是否要增加provider"]) + (" [y|n][n]:")
            result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
            if result == 'n':
                break

            prompt = PrintUtil.get_msg(["please input provider name:[provider_name]", "输入新provider的名称"])
            default_name = ""
            use_name = ""
            # provider的名称
            while 1:
                use_name = utils.get_use_input_default(prompt, default_name)
                if use_name == default_name:
                    print "Illegal input, please input again."
                    continue
                if not self.provider_name_is_legal(use_name):
                    print "Illegal input, please input again."
                    continue
                if len(use_name) > 12:
                    print "provider_name is too long, please input again."
                    continue
                if use_name in [item["name"] for item in self.cur_provider_list]:
                    print "provider:" + use_name + PrintUtil.get_msg([" is already exists","已经存在了"])
                    continue
                else:
                    break

            # 设置vlan范围
            vlan_range = ""
            inputstr = "set vlan range[start,end][%s]" % (def_vlan_range)
            vlan_range = utils.get_user_input_default_check(inputstr, def_vlan_range, self.check_vlan_range)
            new_provider = {"name":use_name,
                            "vlanpool":{"start":vlan_range.split(",")[0], "end":vlan_range.split(",")[1]},\
                            "state": ST_ADD}

            self.cur_provider_list.append(new_provider)

    def check_if_modify(self, key_info, input_info, cur_info, state, sysintfnw_info):
        if input_info != cur_info:
            if key_info in [STR_START, STR_END]:
                sysintfnw_info[STR_POOL][key_info] = input_info
            else:
                sysintfnw_info[key_info] = input_info
            sysintfnw_info[STR_STATE] = state


    def modify_provider(self):
        self.add_provider()

    def modify_sysintfnw(self):
        # 询问是否需要修改
        prompt = PrintUtil.get_msg(["do you want to change sysintfnw info", "是否想要修改sysintfnw info"]) + (" [y|n][n]:")
        result = utils.get_use_input_check_2(prompt, 'n', ['y', 'n'])
        if result == 'n':
            return

        # 获取所有的sysintfnw的名称
        sysintfnw_name_list = []
        assigned_vlan = {}
        for item in self.cur_sysintfnw_list:
            nw_name = item[STR_NAME]
            vlan_id = item[STR_VLAN].lstrip('0')
            assigned_vlan[nw_name] = vlan_id
            if nw_name == "internal_base":
                continue
            sysintfnw_name_list.append(nw_name)

        # 遍历每一条sysintfnw 进行修改, 只允许修改vlan和provider_name
        expect_value_list = []
        expect_value_list.append("s")
        tmp_sysintfnw_info = {}
        while 1:
            # 先把当前的sysintfnw显示一下
            i = 1
            for each in sysintfnw_name_list:
                print "[%s] %s" % (i, each)
                index = "%s" % (i)
                expect_value_list.append(index)
                tmp_sysintfnw_info[index] = each
                i = i + 1

            # 输入要修改的sysintfnw
            prompt = PrintUtil.get_msg(["please input sysintfnw index, \'s\' to exit:", "中文:"])
            result = utils.get_use_input_check_expect(prompt, expect_value_list)
            if result == "s":
                break

            input_name = tmp_sysintfnw_info[result]
            print "going to change sysintfnw: %s" % input_name
            for item in self.cur_sysintfnw_list:
                if item[STR_NAME] == input_name:
                    one_sysintfnw = item
                    # 冲突判断时，排除自身
                    assigned_vlan.pop(input_name)


            # 修改vlan，所有interface都支持
            cur_vlan = one_sysintfnw[STR_VLAN]
            prompt = PrintUtil.get_msg(["please set vlan id for %s" % input_name,
                                        "请输入网络的vlan号"]) + (" [%s]:" % cur_vlan)
            vlan_info = utils.get_user_input_default_vlan_check(prompt, cur_vlan, assigned_vlan)
            vlan_info = vlan_info.lstrip('0')
            self.check_if_modify(STR_VLAN, vlan_info, cur_vlan, ST_ONLY_VLAN, one_sysintfnw)
            # 虽未生效，但也要更新vlan冲突判断列表，场景：net1的vlan配4000，net2的vlan也配4000,生效时会冲突
            assigned_vlan[input_name] = vlan_info

            # 只有om网络支持修改以下配置项
            if input_name == STR_NET_TYPE_OM:

                # 获取当前值
                cur_subnet = one_sysintfnw[STR_SUBNET]
                cur_gateway = one_sysintfnw[STR_GATEWAY]
                cur_pool_start = one_sysintfnw[STR_POOL][STR_START]
                cur_pool_end = one_sysintfnw[STR_POOL][STR_END]

                # 子网网络地址
                prompt = PrintUtil.get_msg(["please set subnet for %s" % input_name,
                                            "请输入网络的网络地址"]) + (" [%s]:" % cur_subnet)
                subnet_info = utils.get_user_input_default_check(prompt, cur_subnet, utils.is_subnet)
                self.check_if_modify(STR_SUBNET, subnet_info, cur_subnet, ST_UPDATE, one_sysintfnw)


                # 起始ip地址
                prompt = "please set subnet ip pool start address that created in neutron for %s network [%s]:" % (input_name,cur_pool_start)
                
                while 1:
                    try:
                        pool_start_info = raw_input(prompt).strip()
                        if pool_start_info == "":
                            pool_start_info = str(cur_pool_start)
                        if utils.is_ip(pool_start_info):
                            if utils.is_ip_in_subnet(pool_start_info,subnet_info):
                                break
                
                        print "input illegal, input again"
                        continue
                
                    except KeyboardInterrupt:
                        sys.exit(1)
                    except Exception:
                        print "please input again"
                        continue

                self.check_if_modify(STR_START, pool_start_info, cur_pool_start, ST_UPDATE, one_sysintfnw)


                # 终止ip地址
                prompt = "please set subnet ip pool end address that created in neutron for %s network [%s]:" % (input_name,cur_pool_end)
                
                while 1:
                    try:
                        pool_end_info = raw_input(prompt).strip()
                        if pool_end_info == "":
                            pool_end_info = str(cur_pool_end)
                        if utils.is_ip(pool_end_info):
                            if utils.is_ip_in_subnet(pool_end_info,subnet_info):
                                if utils.is_secondip_larger(pool_start_info,pool_end_info):
                                    break
                
                        print "input illegal, input again"
                        continue
                
                    except KeyboardInterrupt:
                        sys.exit(1)
                    except Exception:
                        print "please input again"
                        continue
                self.check_if_modify(STR_END, pool_end_info, cur_pool_end, ST_UPDATE, one_sysintfnw)

                # 网关
                prompt = "please set gateway for %s network such as %s or empty:" % (input_name,cur_gateway)
                while 1:
                    try:
                        gateway_info = raw_input(prompt).strip()
                        if gateway_info == "":
                            break
                        if utils.is_ip(gateway_info):
                            if utils.is_gateway_legal(gateway_info,subnet_info,pool_start_info,pool_end_info):
                                break
                
                        print "input illegal, input again"
                        continue
                
                    except KeyboardInterrupt:
                        sys.exit(1)
                    except Exception:
                        print "please input again"
                        continue
                self.check_if_modify(STR_GATEWAY, gateway_info, cur_gateway, ST_UPDATE, one_sysintfnw)

            # 修改provider,部分interface不支持
            if input_name not in PROTECTED_SYSINTFNW:
                cur_provider = one_sysintfnw.get("provider_name", "")
                cur_provider_list = copy.deepcopy(self.cur_provider_list)
                utils.print_list(cur_provider_list, ["name", "vlanpool", "description"])
                name_list = []
                for one_provider in cur_provider_list:
                    name_list.append(str(one_provider["name"]))

                no_provider_mapping = True
                network_group_list = self.get_network_detail_list()
                while no_provider_mapping:
                    prompt = PrintUtil.get_msg(["please set provider for %s " % input_name,
                                                "请设置网络的provider "]) + ("[%s]:" % cur_provider)
                    provider_info = utils.get_use_input_check_2(prompt, cur_provider, name_list)

                    for one_group in network_group_list:
                        if self.has_provider_mapping(one_group, provider_info):
                            no_provider_mapping = False
                            break
                    if cur_provider == "":
                        no_provider_mapping = False

                    if no_provider_mapping:
                        print "No hostcfg maps to provider: %s, input again." % provider_info
                    else:
                        self.check_if_modify(STR_PROVIDER, provider_info, cur_provider, ST_UPDATE, one_sysintfnw)

    def modify_hostcfg_bond(self, one_hostcfg):
        i_max_bond = self.get_max_bond(one_hostcfg)
        used_ports = []
        while True:
            lst_nic_add = []
            lst_bond_add = []
            lst_port_real = []
            prompt = PrintUtil.get_msg(["do you want to add bond for ", "是否要增加bond给"]) \
                                       + str(one_hostcfg["name"]) + (" [y|n][n]:")
            result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
            if result == 'n':
                break

            # 生成当前hostcfg的网口列表
            lst_port = self.get_hostcfg_portlist(one_hostcfg)
            for item in lst_port:
                if item['name'] not in used_ports:
                    lst_port_real.append(item)
            Logger.info("port_list=%s" % str(lst_port))
            utils.print_list(lst_port_real, ["name", "pci"])

            def_bond_mode = "nobond"
            str_bond_name = "trunk%s" % i_max_bond
            inputstr = "input bondmode for %s, as [nobond|lacp][%s]" % (str_bond_name, def_bond_mode)
            str_bond_mode = utils.get_use_input_check_2(inputstr, "nobond", ["nobond","lacp"])

            # 输入组成bond的网口
            inputstr = "input port for %s, as [ethxx,ethxx,...]:" % str_bond_name
            port_info = utils.get_user_input_check_param(inputstr, self.check_bond_eth, lst_port_real)

            # 添加网口
            lst_port_add = []
            lst_port_input = port_info.split(",")
            used_ports.extend(lst_port_input)
            for port in lst_port_input:
                nic_instance = self.create_nic(port, lst_port)
                lst_nic_add.append(nic_instance)
                if port.find(":") >= 0:
                    lst_port_add.append( port.split(":")[0])
                else:
                    lst_port_add.append(port)
            # 后处理
            lst_bond_add.append({str_bond_name: {"bond_mode": str_bond_mode,
                                                 "slaves": lst_port_add}})
            i_max_bond = i_max_bond + 1

            # 将添加的bond和nic更新到缓存中
            if not one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD):
                one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD] = []
            one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD] += lst_nic_add
            if not one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD):
                one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD] = []
            one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD] += lst_bond_add

    def modify_hostcfg_providermapping(self, one_hostcfg):

        while True:
            # 通过新增key来保存
            lst_providermapping_add = []
            prompt = PrintUtil.get_msg(["do you want to add provider mapping for ", "是否要增加provider-mapping for "]) \
                                       + str(one_hostcfg["name"]) + (" [y|n][n]:")
            result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
            if result == 'n':
                break


            providermapping_list = one_hostcfg['providermapping']
            exist_provider = []
            for item in providermapping_list:
                exist_provider.append(item['name'])


            # 输入provider和mode
            prompt = "input provider and mappingtype, type support[ovs|vhostuser|hardware-veb|netmap]," \
                     "such as \"physnet2,kernel-ovs\":"
            result = utils.get_user_input_check_param(prompt, self.check_provider, exist_provider)
            str_provider = result.split(",")[0]
            str_maptype = result.split(",")[1]

            # 输入bond or port
            if str_maptype in NetworkConstant.LST_OVS_MAPPING_COMPATIBLE:
                inputstr = "do you want to add bond or port to provider:%s. [bond|port][bond]:" % str_provider
                bond_or_port = utils.get_use_input_check_2(inputstr, "bond", ["bond", "port"])
            else:
                bond_or_port = "port"

            if bond_or_port == "bond":
                # bond的模式
                available_bond_list, available_bond_name = self.get_available_bond_list(one_hostcfg)
                if len(available_bond_list) == 0:
                    info_msg = "No bond can be added, pleas add a new bond first"
                    Logger.info(info_msg)
                    print info_msg
                    break

                default_bond = available_bond_name[0]
                utils.print_list(available_bond_list, ["name", "bond_mode", "slaves"])
                prompt = PrintUtil.get_msg(["input bond name", "请输入bond名称"]) + \
                         (" [%s]:" % default_bond)
                bond_name = utils.get_use_input_check_2(prompt, default_bond, available_bond_name)
                lst_providermapping_add.append({"name":str_provider,
                                                "interface":bond_name,
                                                "mappingtype":str_maptype})

            else:
                lst_nic_add = []
                # provider不使用bond,如果是硬直通,一定要带vf_num
                lst_port = self.get_hostcfg_portlist(one_hostcfg)
                # 扣除新增的eth口，因为将要组bond或添加到provider上了
                lst_port_remove = []
                nic_add_list = one_hostcfg.get(NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD, [])
                lst_nic_name = [item["name"] for item in nic_add_list]
                for port in lst_port:
                    if port["name"] in lst_nic_name:
                        lst_port_remove.append(port)
                for port_remove in lst_port_remove:
                    lst_port.remove(port_remove)

                Logger.info("port_list=%s" % str(lst_port))
                if len(lst_port) == 0:
                    info_msg = "No port can be added"
                    Logger.info(info_msg)
                    print info_msg
                    break
                utils.print_list(lst_port, ["name", "pci"])

                inputstr = "input port for provider:%s, as [ethxx] or [ethxx:vf-num]:" % (str_provider)
                while 1:
                    port_name = utils.get_user_input_check_param(inputstr, self.check_eth_name, lst_port)
                    if str_maptype in NetworkConstant.LST_OVS_MAPPING_COMPATIBLE:
                        if not self.check_is_vf_port(port_name):
                            break
                        else:
                            print "you choose ovs, should not have vf-num"
                            continue
                    if str_maptype in NetworkConstant.LST_NETMAP_COMPATIBLE:
                        if self.check_is_vf_port(port_name):
                            break
                        else:
                            print "you choose netmap, should have vf-num"
                            continue

                    if str_maptype in NetworkConstant.LST_SRIOV_COMPATIBLE:
                        if str_maptype in ["sriov-nic", "hardware-veb"] :
                            if self.check_is_vf_port(port_name) :
                                break
                            else:
                                print "you choose hardware-veb, should have vf-num"
                                continue
                        if str_maptype == "passthrough" and self.check_is_vf_port(port_name) and 0 < self.get_port_vf_num(port_name):
                            break

                    if str_maptype in NetworkConstant.LST_EVS_MAPPING_COMPATIBLE:
                        if str_maptype in ["user-evs", "vhostuser"] :
                            if not self.check_is_vf_port(port_name) :
                                break
                            else:
                                print "you choose vhostuser, should not have vf-num"
                                continue
                        if str_maptype == "passthrough" and self.check_is_vf_port(port_name) and 0 == self.get_port_vf_num(port_name):
                            break

                    if str_maptype == "passthrough" and not self.check_is_vf_port(port_name):
                        print "you choose passthrough, should have vf-num"
                        continue



                nic_instance = self.create_nic(port_name, lst_port)
                lst_nic_add.append(nic_instance)
                Logger.info("lst_nic_add=%s" % str(lst_nic_add))
                nictmp = port_name
                if nictmp.find(":") >= 0:
                    nictmp = port_name.split(":")[0]

                lst_providermapping_add.append({"name":str_provider,
                                                "interface":nictmp,
                                                "mappingtype":str_maptype})
                # 将添加的nic更新到缓存中
                if not one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD):
                    one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD] = []
                one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD] += lst_nic_add

            # 将添加的providermapping更新到缓存中
            if not one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD):
                one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD] = []
            one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD] += lst_providermapping_add

    def modify_hostcfg_sysintfnwmapping(self, one_hostcfg):
        lst_sysintfnwmapping_change = []
        lst_sysintfnwmapping = one_hostcfg["sysintfnwmapping"]

        # 获取可配置的interface
        bond_add_list = []
        for bond_add in one_hostcfg.get(NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD, []):
            bond_name = bond_add.keys()[0]
            bond_content = bond_add[bond_name]
            new_bond = {"name": bond_name,
                        "slaves": bond_content["slaves"],
                        "bond_mode": bond_content["bond_mode"]}
            bond_add_list.append(new_bond)
        lst_bond = one_hostcfg["bond"] + bond_add_list
        lst_nic = one_hostcfg["nic"] + one_hostcfg.get(NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD,[])
        available_interface_lst = [str(item["name"]) for item in lst_nic]
        for bond in lst_bond:
            available_interface_lst.append(str(bond["name"]))
            lst_slave = bond["slaves"]
            for slave in lst_slave:
                available_interface_lst.remove(slave)


        # 如果没有mapping，就不需要处理
        if len(lst_sysintfnwmapping) == 0:
            return

        # 询问是否要修改
        prompt = PrintUtil.get_msg(["do you want to change sysintfnwmapping", "是否要修改sysintfnwmapping"]) \
                                     + (" [y|n][n]:")
        result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
        if result == 'n':
            return

        # 获取所有的sysintfnw的名称
        sysintfnw_name_list = []
        for item in lst_sysintfnwmapping:
            name = item["name"]
            if name == "internal_base":
                continue
            if name == NetworkConstant.STR_NET_TYPE_OM:
                continue
            if name == NetworkConstant.STR_NET_TYPE_API:
                continue
            sysintfnw_name_list.append(name)

        expect_value = []
        expect_value.append("s")
        tmp_item_info = {}
        while 1:
            # 先打印一下
            i = 1
            for each in sysintfnw_name_list:
                index = "%s" % i
                expect_value.append(index)
                tmp_item_info[index] = each
                print "[%s] %s" % (i, each)
                i = i + 1

            # 输入要修改的sysintfnwmapping
            prompt = PrintUtil.get_msg(["please input sysintfnwmapping index, \'s\' to save&exit:", "中文:"])
            result = utils.get_use_input_check_expect(prompt, expect_value)
            if result == "s":
                break

            # 修改
            input_name = tmp_item_info[result]
            for item in lst_sysintfnwmapping:
                if item["name"] == input_name:
                    one_sysintfnwmapping = item
            if one_sysintfnwmapping["name"] == "internal_base":
                print "internal_base can not be changed!"
                continue

            print "-------------------sysintfnwmapping for %s----------------" % (one_sysintfnwmapping["name"])
            utils.print_dict(one_sysintfnwmapping)
            if one_sysintfnwmapping.has_key("interface"):
                prompt = PrintUtil.get_msg(["do you want to change interface config for", "是否要修改接口"]) \
                                             + (" %s" % one_sysintfnwmapping["name"]) + (" [y|n][n]:")
            else:
                prompt = PrintUtil.get_msg(["do you want to add interface for", "是否要增加接口"]) \
                                             + (" %s" % one_sysintfnwmapping["name"]) + (" [y|n][n]:")
            result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
            if result == 'n':
                continue


            default_interface = one_sysintfnwmapping.get("interface", "")
            prompt = PrintUtil.get_msg(["input interface name", "请输入接口名称"]) + \
                     (" [%s]:" % default_interface)
            interface_name = utils.get_use_input_check_2(prompt, default_interface, available_interface_lst)
            if interface_name != default_interface:
                lst_sysintfnwmapping_change.append({"interface":interface_name,
                                                    "name": one_sysintfnwmapping["name"]})

        if not one_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE):
            one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE] = []
        if len(lst_sysintfnwmapping_change) > 0:
            self.replace_sysintfnwmapping_change(lst_sysintfnwmapping_change, lst_sysintfnwmapping)
            one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE] += lst_sysintfnwmapping_change


    def modify_one_hostcfg(self, one_hostcfg):
        self.modify_hostcfg_bond(one_hostcfg)
        self.modify_hostcfg_providermapping(one_hostcfg)
        self.modify_hostcfg_sysintfnwmapping(one_hostcfg)

    def modify_exist_hostcfg(self):
        # 进行修改
        for one_hostcfg in self.cur_hostcfg_list:
            # default是不支持修改的
            if one_hostcfg["name"] == "default":
                continue
            if not self.check_is_our_group(one_hostcfg["name"]):
                continue

            # 将hostcfg打印一下
            print "hostcfg:%s   " % (one_hostcfg["name"])
            utils.print_dict_ext(one_hostcfg, NetworkConstant.HOST_CFG_TYPE_FIELDS)

            prompt = PrintUtil.get_msg(["do you want to change hostcfg:", "是否要修改hostcfg:"]) \
                                     + str(one_hostcfg["name"]) + (" [y|n][n]:")
            result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
            if result == 'n':
                continue

            self.modify_one_hostcfg(one_hostcfg)

        # 改完之后再显示一下
        Logger.error("after hostcfg modify=" + str(self.cur_hostcfg_list))

    def modify_new_hostcfg(self):
        if len(self.hostcfg_add) == 0:
            return

        for one_new_hostcfg in self.hostcfg_add:
            # 将hostcfg打印一下
            print "hostcfg:%s   " % (one_new_hostcfg["name"])
            utils.print_dict_ext(one_new_hostcfg, NetworkConstant.HOST_CFG_TYPE_FIELDS)

            prompt = PrintUtil.get_msg(["do you want to change hostcfg:", "是否要修改hostcfg:"]) \
                                     + str(one_new_hostcfg["name"]) + (" [y|n][n]:")
            result = utils.get_use_input_check_2(prompt, 'n', ['y','n'])
            if result == 'n':
                continue

            self.modify_one_hostcfg(one_new_hostcfg)


    def isolate_fix_hosts_proc(self, host_list):
        Logger.info("[isolate_fix_hosts_proc] enter host_list:%s" % host_list)
        group_name_all_list = [item["name"] for item in self.cur_hostcfg_list]
        group_name_fs_list = []
        for group in group_name_all_list:
            str_group = group.encode("utf-8")
            if self.check_is_our_group(str_group):
                group_name_fs_list.append(group)
        try:
            index_start = int(max(group_name_fs_list).strip("group")) + 1
        except:
            index_start = 0
        new_group_list = self.generate_host_groups(index_start, host_list)
        print "new group info=" + str(new_group_list)

        # 遍历每个分组
        for group_index in new_group_list:
            one_group_detail = new_group_list[group_index]
            self.isolate_group_proc(group_index, one_group_detail)

    def isolate_hosts_proc(self):
        PrintUtil.print_msg(["add hostcfg proc start", "中文"])
        if len(self.isolate_host_list) == 0:
            PrintUtil.print_msg(["but all hosts have configed!", "但是所有主机都已经配置完成"])
            return

        # 把孤立的host进行分组
        group_name_all_list = [item["name"] for item in self.cur_hostcfg_list]
        group_name_fs_list = []
        for group in group_name_all_list:
            str_group = group.encode("utf-8")
            if self.check_is_our_group(str_group):
                group_name_fs_list.append(group)

        if len(group_name_fs_list) == 0:
            index_start = 1
        else:
            index_start = int(max(group_name_fs_list).strip("group")) + 1
        new_group_list = self.generate_host_groups(index_start, self.isolate_host_list)

        # 遍历每个分组
        for group_index in new_group_list:
            one_group_detail = new_group_list[group_index]

            # 打印本分组信息
            print "+ group%s +" % group_index
            utils.print_dict(one_group_detail)

            self.isolate_group_proc(group_index, one_group_detail)

        # 显示新增hostcfg的信息
        Logger.info("new_hostcfg=" + str(self.hostcfg_add))

    def modify_hostcfg(self):
        Logger.debug("start to modify hostcfg.")
        self.modify_exist_hostcfg()
        self.modify_new_hostcfg()
        self.isolate_hosts_proc()

    def provider_validate(self):
        Logger.debug("going to validate provide")
        for pure_provider in self.cur_provider_list:
            if not pure_provider.has_key("state"):
                continue

            state = pure_provider["state"]
            if (state is None) or (state == ST_ORIG):
                continue

            del pure_provider["state"]
            if state == ST_ADD:
                print "going to add provider"
                flag = cps_server.create_provider(pure_provider)
                msg = "create provider[%s] result=%s" % (pure_provider["name"], str(flag))
                Logger.info(msg)
                print msg
                continue

            if state == ST_DIRTY:
                print "going to delete&add provider"
                flag = cps_server.delete_provider(pure_provider["name"])
                msg = "delete provider[%s] result=%s" % (pure_provider["name"], str(flag))
                Logger.info(msg)
                print msg
                flag = cps_server.create_provider(pure_provider)
                msg = "create provider[%s] result=%s" % (pure_provider["name"], str(flag))
                Logger.info(msg)
                print msg
                continue

            if state == ST_DEL:
                print "going to delete provider"
                flag = cps_server.delete_provider(pure_provider)
                msg = "delete provider[%s] result=%s" % (pure_provider["name"], str(flag))
                Logger.info(msg)
                print msg
                continue

    @staticmethod
    def get_network_detail_list():
        network_group_list = []
        group_list = cps_server.get_network_group_list()
        for one_group in group_list:
            group_detail = cps_server.get_network_group_detail(one_group["name"])
            network_group_list.append(group_detail)
        return network_group_list

    def has_sysintfmapping(self, one_hostcfg, network_name):
        sysintfmapping_list = one_hostcfg["sysintfnwmapping"]
        for item in sysintfmapping_list:
            if item["name"] == network_name:
                return True
        return False

    def has_provider_mapping(self, one_hostcfg, provider_name):
        providermapping_list = one_hostcfg[NetworkConstant.NETWORK_HOSTCFG_PROVIDERMAPPING] \
                               + one_hostcfg.get(NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD, [])
        for item in providermapping_list:
            if item["name"] == provider_name:
                return True
        return False

    def update_by_delete_and_add(self, one_sysintfnw):
        network_name = one_sysintfnw["name"]
        network_group_list = self.get_network_detail_list()

        # 先删除sysintfnwmapping,才能删除sysintfnw
        for one_group in network_group_list:
            #存在这个mapping的才需要删除
            if not self.has_sysintfmapping(one_group, network_name):
                continue
            ret = fsCpsCliOpt.net_host_cfg_sysintfnw_delete(one_group["name"], network_name, self.cps_server_url)
            msg = "delete sysintfnwmapping for %s of %s, ret=%s" % (network_name, one_group["name"], ret)
            Logger.info(msg)
            print msg

        # 删除sysintfnw
        ret = cps_server.delete_sys_interfaces(network_name)
        msg = "delete sysintfnw %s, ret=%s" % (network_name, ret)
        Logger.info(msg)
        print msg

        # 添加sysintfnw
        ret = cps_server.create_sys_interfaces(one_sysintfnw)
        msg = "add sysintfnw %s, ret=%s" % (network_name, ret)
        Logger.info(msg)
        print msg

        # 添加sysintfnwmapping
        for one_group in network_group_list:
            if not self.has_provider_mapping(one_group, one_sysintfnw["provider_name"]):
                continue
            sysintfmapping_nw = {"name": network_name}
            ret = fsCpsCliOpt.net_hostcfg_sysintfnw_add(one_group["name"], sysintfmapping_nw, self.cps_server_url)
            msg = "add sysintfnwmapping for %s, ret=%s" % (one_group["name"], ret)
            Logger.info(msg)
            print msg

    def update_by_cps_cli(self, content):
        flag = cps_server.update_sys_interfaces(content)
        msg = "update sysintfnw[%s] result=%s" % (content["name"], flag)
        Logger.info(msg)
        print msg

    def sysintfnw_validate(self):
        Logger.debug("going to validate sysinfnw")
        for one_sysintfnw in self.cur_sysintfnw_list:
            if not one_sysintfnw.has_key("state"):
                continue

            state = one_sysintfnw["state"]
            if state == ST_ORIG:
                continue
            del one_sysintfnw["state"]

            network_name = one_sysintfnw["name"]
            # 部分网络(storage_data0/storage_data1/tunnel_bearing)，只支持修改vlan，并不允许删增操作
            if state == ST_ONLY_VLAN:
                content = {"name": network_name, "vlan": one_sysintfnw["vlan"]}
                self.update_by_cps_cli(content)
            elif state == ST_UPDATE:
                self.update_by_delete_and_add(one_sysintfnw)

    def hostcfg_validate(self):
        # 先处理修改的hostcfg
        Logger.info("Enter in hostcfg_validate. cur_hostcfg_list:%s" % self.cur_hostcfg_list)
        for one_hostcfg in self.cur_hostcfg_list:
            one_group_name = one_hostcfg["name"]
            Logger.info("going to validate hostcfg=" + one_group_name)
            self.validate_hostcfg_comm(one_hostcfg)

            # 增加节点的处理
            if one_hostcfg.has_key("host_add"):
                lst_host = one_hostcfg["host_add"]
                if (lst_host is not None) and (len(lst_host) != 0):
                    flag = fsCpsCliOpt.hostcfg_host_add(lst_host, "network", one_group_name, self.cps_server_url)
                    msg = "add hosts result=%s, host_list=%s" % (str(flag), str(lst_host))
                    Logger.info(msg)
                    print msg

        # 增加的hostcfg的处理
        for new_hostcfg in self.hostcfg_add:
            # 创建这个group
            one_group_name = new_hostcfg["name"]
            Logger.info("going to validate new hostcfg=" + one_group_name)
            print "going to add hostcfg:" + one_group_name
            flag = cps_server.net_host_cfg_add(one_group_name)
            msg = "add hostcfg result=%s, hostcfg=%s" % (str(flag), str(one_group_name))
            Logger.info(msg)
            print msg

            self.validate_hostcfg_comm(new_hostcfg)

            lst_host = new_hostcfg["hosts"]["hostid"]
            flag = fsCpsCliOpt.hostcfg_host_add(lst_host, "network", one_group_name, self.cps_server_url)
            msg = "add hosts result=%s, host_list=%s" % (str(flag), str(lst_host))
            Logger.info(msg)
            print msg

    def provider_name_is_legal(self,provider_name):
        provider_name_pattern = "^[a-zA-Z0-9_-]+$"
        p = re.compile(provider_name_pattern)
        if p.match(provider_name):
            return True
        else:
            return False

if __name__ == "__main__":
    pass