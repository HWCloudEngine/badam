#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import os
import sys
import json
import traceback
import commands

import fs_log_util
import cps_server
from fs_network_constant import NetworkConstant
import fs_network_openstack_util
import fsutils as utils
from print_msg import PrintMessage as PrintUtil
import fs_network_util
from os.path import join
import fsutils


ST_ORIG = "orig"
ST_ADD = "add"
ST_DEL = "del"
ST_DIRTY = "dirty"

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
Logger = fs_log_util.localLog.get_logger(LOG_FILE)


class NetwokCfgProc():
    def __init__(self):
        # 注意这两个值是处理过的
        self.cps_server_url = cps_server.get_cpsserver_url()
        self.network_cfg_mgr = fs_network_util.NetworkHostcfgMgr()
        self.openstack_network_mgr = fs_network_openstack_util.OpenStackNetwokCfgProc()


    def init(self):
        self.part_map = {"1": self.network_cfg_part1,
                         "2": self.network_cfg_part2,
                         "3": self.network_cfg_part3}
        self.cps_server_url = cps_server.get_cpsserver_url()
        self.network_cfg_mgr = fs_network_util.NetworkHostcfgMgr()
        self.openstack_network_mgr = fs_network_openstack_util.OpenStackNetwokCfgProc()

    def get_section_list(self):
        return [NetworkConstant.NETWORK_SECTION]

    def get_file_path(self):
        return NetworkConstant.NETWORK_INI_PATH

    def check_providermapping(self, provider_mapping_info):
        if not provider_mapping_info.has_key("name"):
            return False
        if not provider_mapping_info.has_key("mappingtype"):
            return False
        if not provider_mapping_info.has_key("interface"):
            return False

        str_provider = provider_mapping_info["name"]
        str_maptype = provider_mapping_info["mappingtype"]
        if str_provider not in [item["name"] for item in self.network_cfg_mgr.cur_provider_list]:
            err_msg = "provider not exist, please input again"
            Logger.error(err_msg)
            print err_msg
            return False

        if str_maptype not in ["kernel-ovs", "user-evs", "sriov-nic", "netmap-nic"]:
            err_msg = "mode not exist, please input again,support:"
            Logger.error(err_msg)
            print err_msg
            return False

        return True

    def run_command(self, cmd):
        try:
            (status, output) = commands.getstatusoutput(cmd)
            Logger.info("run cmd :%s,status %s output %s" % (cmd, status, output))
            return status, output
        except Exception, e:
            Logger.error(e)
        return 1, output

    def get_host_name(self):
        cmd = "hostname"
        (status, output) = self.run_command(cmd)
        if status != 0:
            Logger.error("hostname failed! curl:" + cmd + ' output=' + output)
            sys.exit(1)
        return output

    def check_eth_name(self, eth_name, port_list):
        temp_name = None
        if eth_name.find(":") != -1:
            str_list = eth_name.split(":")
            if len(str_list) != 2:
                return False
            temp_name = str_list[0]
            vf_num = str_list[1]
        else:
            temp_name = eth_name

        for one_eth in port_list:
            name = one_eth["name"]
            if temp_name == name:
                return True

        return False

    def check_bond_pci(self, slave_list, port_list):
        pci_list = [item["pci"].split("=")[0] for item in port_list]
        Logger.info("pci_list: %s" % pci_list)
        Logger.info("slave_list: %s" % slave_list)
        for one_pci in slave_list:
            if one_pci not in pci_list:
                err_msg = "%s is not existed." % one_pci
                Logger.error(err_msg)
                print err_msg
                return False

        return True

    def check_vlanpool(self, value):
        if "start" in value:
            if not value["start"].isdigit():
                return False
        else:
            return False

        if "end" in value:
            if not value["end"].isdigit():
                return False
        else:
            return False

        return True

    def check_ippool(self, value):
        if "start" not in value:
            return False
        if "end" not in value:
            return False

        return True

    def get_hostcfg_nic_list(self, one_hostcfg):
        exist_ethname_list = []
        exist_pci_list = []
        nic_list = one_hostcfg.get("nic", [])
        Logger.info("In hostcfg: %s, nic list is: %s" % (one_hostcfg["name"], nic_list))
        for one_nic in nic_list:
            exist_ethname_list.append(one_nic["name"])
            nic_option = one_nic["option"]
            if isinstance(nic_option, dict) and nic_option.has_key("PCISLOT"):
                exist_pci_list.append(nic_option["PCISLOT"])
        return exist_ethname_list,exist_pci_list

    def choose_sub_section(self):
        print PrintUtil.get_msg(["Please choose a sub-section from list:", "请从列表中选择一个子分类:"])
        while 1:
            print "[1] Provider"
            print "[2] Sysintfnw"
            print "[3] Network hostcfg"
            print "[s] Save&quit"

            inputstr = PrintUtil.get_msg(["Please choose", "请选择"]) + " [1-3|s][s]"
            choise = raw_input(inputstr)
            if choise == "":
                return "s"
            elif choise in ["1", "2", "3", "s"]:
                return choise
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [1-3|s]!"

    def network_cfg_part1(self):
        # 输出一下当前的provider
        print "--------------Provider info--------------"
        provider_list = self.network_cfg_mgr.cur_provider_list
        utils.print_list(provider_list, ["name", "vlanpool", "description"])

        # 进行修改
        self.network_cfg_mgr.modify_provider()

        # 打印修改后的provider信息
        utils.print_list(provider_list, ["name", "vlanpool", "description", "state"])

    def network_cfg_part2(self):
        # 先显示一下
        sysintfnw_list = self.network_cfg_mgr.cur_sysintfnw_list
        print "--------------------Sysintfnw info---------------"
        utils.print_list(sysintfnw_list, ["name", "ip", "vlan", "provider_name",
                                          "ippool", "gateway", "description", "subnet"])

        # 进行修改
        self.network_cfg_mgr.modify_sysintfnw()

        # 再次显示一下
        utils.print_list(sysintfnw_list, ["name", "ip", "vlan", "provider_name",
                                          "ippool", "gateway", "description", "subnet", "state"])

    def network_cfg_part3(self):
        self.network_cfg_mgr.modify_hostcfg()

    def config(self, config_type):
        #配置前先进行初始化，获取当前的环境信息。
        self.init()
        # 根据类型进行不同的处理
        if config_type == utils.TYPE_DEPLOY_CONFIG:
            self.network_cfg_part1()
            self.network_cfg_part2()
            self.network_cfg_part3()
            return True

        # TYPE_ONLY_CONFIG类型，可以自由选择二级分类
        while 1:
            choise = self.choose_sub_section()
            if choise == "s":
                return True
                # 如果是openstack的网络配置

            config_func = self.part_map[choise]
            if config_func is not None:
                config_func()

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
            continue
        config = ConfigParser.RawConfigParser()
        config.read(NetworkConstant.NETWORK_INI_PATH)
        if not config.has_section(NetworkConstant.NETWORK_SECTION):
            config.add_section(NetworkConstant.NETWORK_SECTION)
        config.set(NetworkConstant.NETWORK_SECTION,
                   NetworkConstant.NETWORK_OPTION_INTERNAL_BASE_FLAG, is_build)
        with open(NetworkConstant.NETWORK_INI_PATH, 'w') as fd:
            config.write(fd)

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
        config = ConfigParser.RawConfigParser()
        config.read(NetworkConstant.NETWORK_INI_PATH)
        if not config.has_section(NetworkConstant.NETWORK_SECTION):
            config.add_section(NetworkConstant.NETWORK_SECTION)
        config.set(NetworkConstant.NETWORK_SECTION,
                   NetworkConstant.NETWORK_ROUTE_OPTION, gateway_input)
        with open(NetworkConstant.NETWORK_INI_PATH, 'w') as fd:
            config.write(fd)

    def __saveToConfigInfoToFile(self, fileName):
        fs_network_util.save_config(fileName,
                                    NetworkConstant.NETWORK_SECTION,
                                    NetworkConstant.NETWORK_PROVIDER_OPTION,
                                    json.dumps(self.network_cfg_mgr.cur_provider_list))

        fs_network_util.save_config(fileName,
                                    NetworkConstant.NETWORK_SECTION,
                                    NetworkConstant.NETWORK_SYSINTFNW_OPTION,
                                    json.dumps(self.network_cfg_mgr.cur_sysintfnw_list))

        fs_network_util.save_config(fileName,
                                    NetworkConstant.NETWORK_SECTION,
                                    NetworkConstant.NETWORK_HOSTCFG_OPTION,
                                    json.dumps({}))

    def parse_provider_config(self, cps_config):
        if cps_config.has_option(NetworkConstant.NETWORK_SECTION, NetworkConstant.NETWORK_PROVIDER_OPTION):
            existed_provider_name = [item["name"] for item in self.network_cfg_mgr.cur_provider_list]
            config_provider_list = json.loads(cps_config.get(NetworkConstant.NETWORK_SECTION,
                                                             NetworkConstant.NETWORK_PROVIDER_OPTION))
            for config_provider in config_provider_list:
                # 只支持新增provider
                if not config_provider.get("name", None):
                    msg = "Need to give a name for the provider."
                    Logger.error(msg)
                    print msg
                if config_provider["name"] in existed_provider_name:
                    continue

                if config_provider.has_key(NetworkConstant.NETWORK_PROVIDER_VLANPOOL):
                    if self.check_vlanpool(config_provider[NetworkConstant.NETWORK_PROVIDER_VLANPOOL]):
                        config_provider["state"] = NetworkConstant.ST_ADD
                        self.network_cfg_mgr.cur_provider_list.append(config_provider)
                    else:
                        err_msg = "error vlanpool setting"
                        print err_msg
                        Logger.error(err_msg)
                        continue

    def parse_sysintfnw_config(self, cps_config):
        if cps_config.has_option(NetworkConstant.NETWORK_SECTION, NetworkConstant.NETWORK_SYSINTFNW_OPTION):
            existed_sysintfnw = dict()
            assigned_vlan = {}
            for one_sysintfnw in self.network_cfg_mgr.cur_sysintfnw_list:
                sysintfnw_name = one_sysintfnw["name"]
                vlan_id = one_sysintfnw["vlan"].lstrip('0')
                assigned_vlan[sysintfnw_name] = vlan_id
                if sysintfnw_name == NetworkConstant.STR_NET_TYPE_BASE:
                    continue
                existed_sysintfnw[sysintfnw_name] = one_sysintfnw

            config_sysintfnw_list = json.loads(cps_config.get(NetworkConstant.NETWORK_SECTION,
                                                              NetworkConstant.NETWORK_SYSINTFNW_OPTION))
            for config_sysintfnw in config_sysintfnw_list:
                sysintfnw_name = config_sysintfnw["name"]
                if sysintfnw_name not in existed_sysintfnw:
                    continue
                one_sysintfnw = existed_sysintfnw[sysintfnw_name]
                if one_sysintfnw.has_key("state"):
                    continue
                # 只能配置vlan的物理网络
                one_sysintfnw["state"] = NetworkConstant.ST_ORIG
                # vlan配置
                if config_sysintfnw.has_key(NetworkConstant.NETWORK_SYSINTFNW_VLAN):
                    cur_vlan = one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_VLAN]
                    config_vlan = str(config_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_VLAN])
                    if not config_vlan.isdigit():
                        del one_sysintfnw["state"]
                        err_msg = "vlan id should be digit."
                        Logger.info(err_msg)
                        print err_msg
                        continue
                    if cur_vlan != config_vlan:
                        assigned_vlan.pop(sysintfnw_name)
                        if fsutils.check_conflict_vlan(config_vlan, assigned_vlan):
                            one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_VLAN] = config_vlan
                            one_sysintfnw["state"] = NetworkConstant.ST_ONLY_VLAN
                            assigned_vlan[sysintfnw_name] = config_vlan
                        else:
                            del one_sysintfnw["state"]
                            assigned_vlan[sysintfnw_name] = cur_vlan
                            err_msg = "vlan id conflict."
                            Logger.info(err_msg)
                            print err_msg
                            continue

                # 只有om网络支持修改以下配置项
                if sysintfnw_name == NetworkConstant.STR_NET_TYPE_OM:
                    # 子网ip
                    if config_sysintfnw.has_key(NetworkConstant.NETWORK_SYSINTFNW_SUBNET):
                        cur_subnet = one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_SUBNET]
                        config_subnet = str(config_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_SUBNET])
                        if cur_subnet != config_subnet:
                            if fsutils.is_subnet(config_subnet):
                                one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_SUBNET] = config_subnet
                                one_sysintfnw["state"] = NetworkConstant.ST_UPDATE
                            else:
                                del one_sysintfnw["state"]
                                err_msg = "error subnet setting"
                                Logger.info(err_msg)
                                print err_msg
                                continue



                    # 配置ippool
                    if config_sysintfnw.has_key(NetworkConstant.NETWORK_SYSINTFNW_IPPOOL):
                        cur_ippool = one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_IPPOOL]
                        config_ippool = config_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_IPPOOL]
                        if not self.check_ippool(config_ippool):
                            del one_sysintfnw["state"]
                            err_msg = "error ippool setting; %s" % config_ippool
                            Logger.info(err_msg)
                            print err_msg
                        # 起始ip地址
                        cur_ip_start = cur_ippool["start"]
                        config_ip_start = str(config_ippool["start"])
                        if cur_ip_start != config_ip_start:
                            is_legal = "False"
                            if fsutils.is_ip(config_ip_start):
                                if fsutils.is_ip_in_subnet(config_ip_start,config_subnet):
                                    one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_IPPOOL]["start"] = \
                                    config_ip_start
                                    one_sysintfnw["state"] = NetworkConstant.ST_UPDATE
                                    is_legal = "True"
                            if "False" == is_legal:
                                del one_sysintfnw["state"]
                                err_msg = "error ippool start setting"
                                Logger.info(err_msg)
                                print err_msg
                                continue

                        # 终止ip地址
                        cur_ip_end = cur_ippool["end"]
                        config_ip_end = str(config_ippool["end"])
                        if cur_ip_end != config_ip_end:
                            is_legal = "False"
                            if fsutils.is_ip(config_ip_end):
                                if fsutils.is_ip_in_subnet(config_ip_end,config_subnet):
                                    if fsutils.is_secondip_larger(config_ip_start,config_ip_end):
                                        one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_IPPOOL]["end"] = \
                                        config_ip_end
                                        one_sysintfnw["state"] = NetworkConstant.ST_UPDATE
                                        is_legal = "True"
                            if "False" == is_legal:
                                del one_sysintfnw["state"]
                                err_msg = "error ippool end setting"
                                Logger.info(err_msg)
                                print err_msg
                                continue

                    # 网关
                    if config_sysintfnw.has_key(NetworkConstant.NETWORK_SYSINTFNW_GATEWAY):
                        cur_gateway = one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_GATEWAY]
                        config_gateway = str(config_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_GATEWAY])
                        if cur_gateway != config_gateway:
                            if "" == config_gateway:
                                one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_GATEWAY] = config_gateway
                                one_sysintfnw["state"] = NetworkConstant.ST_UPDATE
                            else:
                                is_legal = "False"
                                if fsutils.is_ip(config_gateway):
                                    if fsutils.is_gateway_legal(config_gateway,config_subnet,config_ip_start,config_ip_end):
                                        one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_GATEWAY] = config_gateway
                                        one_sysintfnw["state"] = NetworkConstant.ST_UPDATE
                                        is_legal = "True"
                                if "False" == is_legal:
                                    del one_sysintfnw["state"]
                                    err_msg = "error gateway setting"
                                    Logger.info(err_msg)
                                    print err_msg
                                    continue

                # 配置provider
                if config_sysintfnw.has_key(NetworkConstant.NETWORK_SYSINTFNW_PROVIDER):
                    cur_provider = one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_PROVIDER]
                    config_provider = str(config_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_PROVIDER])
                    name_list = []
                    for one_provider in self.network_cfg_mgr.cur_provider_list:
                        name_list.append(str(one_provider["name"]))

                    if config_provider not in name_list:
                        del one_sysintfnw["state"]
                        err_msg = "provider is not existed."
                        Logger.info(err_msg)
                        print err_msg
                        continue
                    if cur_provider != config_provider:
                        hostcfg_group_list = fs_network_util.NetworkHostcfgMgr.get_network_detail_list()
                        no_provider_mapping = True
                        for one_group in hostcfg_group_list:
                            if self.network_cfg_mgr.has_provider_mapping(one_group, config_provider):
                                no_provider_mapping = False
                                break
                        if no_provider_mapping:
                            del one_sysintfnw["state"]
                            err_msg = "No hostcfg maps to provider: %s, input again." % config_provider
                            Logger.info(err_msg)
                            print err_msg
                            continue
                        else:
                            one_sysintfnw[NetworkConstant.NETWORK_SYSINTFNW_PROVIDER] = config_provider
                            one_sysintfnw["state"] = NetworkConstant.ST_UPDATE

    def get_group_default_hostcfg(self, hostcfg_list, isolate_host_list):
        group_default_hostcfg = {}
        for one_hostcfg in hostcfg_list:
            if one_hostcfg["name"] == NetworkConstant.NETWORK_GROUP_DEFAULT_HOSTCFG:
                group_default_hostcfg = one_hostcfg
                break

        if len(group_default_hostcfg) == 0:
            group_default_hostcfg = self.network_cfg_mgr.create_new_hostcfg()
            group_default_hostcfg["name"] = NetworkConstant.NETWORK_GROUP_DEFAULT_HOSTCFG
            group_default_hostcfg["hosts"] = {"hostid": isolate_host_list}
            self.network_cfg_mgr.hostcfg_add.append(group_default_hostcfg)
        else:
            group_default_hostcfg["host_add"] = isolate_host_list
            
        return group_default_hostcfg

    def add_nic_by_group_config(self, cps_config, group_default_hostcfg):
        if not cps_config.has_option(NetworkConstant.NETWORK_SECTION, NetworkConstant.NETWORK_HOSTCFG_NIC):
            return

        nic_add_list = json.loads(cps_config.get(NetworkConstant.NETWORK_SECTION,
                                                 NetworkConstant.NETWORK_HOSTCFG_NIC))
        if (nic_add_list is None) or (len(nic_add_list) == 0):
            return

        nic_existed_list = []
        exist_ethname_list, exist_pci_list = self.get_hostcfg_nic_list(group_default_hostcfg)
        # 找出group_default中已经有的nic，不做添加操作
        for nic in nic_add_list:
            nic_name = nic["name"]
            if nic_name in exist_ethname_list:
                nic_existed_list.append(nic)
                info_msg = "nic %s is existed." % nic_name
                Logger.info(info_msg)
                print info_msg
                continue

            nic_option = nic["option"]
            if isinstance(nic_option, dict) and nic_option.has_key("PCISLOT"):
                nic_pci = nic_option["PCISLOT"]
                if nic_pci in exist_pci_list:
                    nic_existed_list.append(nic)
                    info_msg = "nic %s is existed." % nic_name
                    Logger.info(info_msg)
                    print info_msg
                    continue

        for nic_existed in nic_existed_list:
            nic_add_list.remove(nic_existed)

        # 获取增加的nic
        if not group_default_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD):
            group_default_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD] = []
        group_default_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_NIC_ADD] += nic_add_list

    def add_bond_by_group_config(self, cps_config, group_default_hostcfg):
        if not cps_config.has_option(NetworkConstant.NETWORK_SECTION, NetworkConstant.NETWORK_HOSTCFG_BOND):
            return
        bond_list = json.loads(cps_config.get(NetworkConstant.NETWORK_SECTION,
                                                  NetworkConstant.NETWORK_HOSTCFG_BOND))

        if (bond_list is None) or (len(bond_list) == 0):
            return

        bond_add_list = []
        for one_bond in bond_list:
            bond_detail ={one_bond["name"]:{"bond_mode":one_bond["bond_mode"],
                                             "slaves":one_bond["slaves"]}}
            bond_add_list.append(bond_detail)

        # 获取增加的bond
        if not group_default_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD):
            group_default_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD] = []
        group_default_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_BOND_ADD] += bond_add_list

    def add_providermappping_by_group_config(self, cps_config, group_default_hostcfg):
        if not cps_config.has_option(NetworkConstant.NETWORK_SECTION, NetworkConstant.NETWORK_HOSTCFG_PROVIDERMAPPING):
            return
        providermapping_add_list = json.loads(cps_config.get(NetworkConstant.NETWORK_SECTION,
                                                             NetworkConstant.NETWORK_HOSTCFG_PROVIDERMAPPING))
        if (providermapping_add_list is None) or (len(providermapping_add_list) == 0):
            return

        # 获取增加的providermapping
        if not group_default_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD):
            group_default_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD] = []
        group_default_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_MAPPING_ADD] += providermapping_add_list

    def change_sysintfnwmapping_by_group_config(self, cps_config, group_default_hostcfg):
        if not cps_config.has_option(NetworkConstant.NETWORK_SECTION, NetworkConstant.NETWORK_HOSTCFG_SYSINTFNWMAPPING):
            return
        sysintfnwmapping_chg_list = json.loads(cps_config.get(NetworkConstant.NETWORK_SECTION,
                                                             NetworkConstant.NETWORK_HOSTCFG_SYSINTFNWMAPPING))
        if (sysintfnwmapping_chg_list is None) or (len(sysintfnwmapping_chg_list) == 0):
            return

        # 获取增加的sysintfnwmapping
        if not group_default_hostcfg.has_key(NetworkConstant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE):
            group_default_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE] = []
        group_default_hostcfg[NetworkConstant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE] += sysintfnwmapping_chg_list

    def parse_hostcfg_config(self, cps_config):
        # 如果没有配置的option，不需要解析
        value = None
        user_option_set = set([key for key, value in cps_config.items(NetworkConstant.NETWORK_SECTION)])
        group_option_set = set(NetworkConstant.NETWORK_HOSTCFG_MCCP_FIELDS)
        Logger.info("start to parse hostcfg part: %s, value = %s" % (user_option_set, value))
        if len(user_option_set & group_option_set) == 0:
            return

        # 获取group_default规则的信息，没有此规则则新建
        (hostcfg_list, isolate_host_list, all_hostid) = fs_network_util.get_hostcfg_summany()
        if len(isolate_host_list) == 0:
            msg = "all hosted have been configged, all_hostid = %s"%all_hostid
            Logger.info(msg)
            return

        # 获取group默认的网络规则
        group_default_hostcfg = self.get_group_default_hostcfg(hostcfg_list, isolate_host_list)

        # 增加nic
        self.add_nic_by_group_config(cps_config, group_default_hostcfg)

        # 增加bond
        self.add_bond_by_group_config(cps_config, group_default_hostcfg)

        # 增加providermapping
        self.add_providermappping_by_group_config(cps_config, group_default_hostcfg)

        # 更改sysintfnwmapping
        self.change_sysintfnwmapping_by_group_config(cps_config, group_default_hostcfg)

    def parseConfigInfoFromFile(self, fileName):
        # 向cps发送请求，初始化网络信息
        self.init()
        Logger.info('begin to parse. %s ' % fileName)
        try:
            cps_config = ConfigParser.RawConfigParser()
            cps_config.read(fileName)
            section_list = cps_config.sections()
            # 自己生效的文件中是没有相关的配置信息的
            if NetworkConstant.NETWORK_SECTION not in section_list:
                Logger.error('section: %s is not found.' % NetworkConstant.NETWORK_SECTION)
                return

            Logger.info('begin to parse section: %s.' % NetworkConstant.NETWORK_SECTION)
            # provider配置读取
            self.parse_provider_config(cps_config)

            # sysintfnw配置读取
            self.parse_sysintfnw_config(cps_config)

            # hostcfg配置读取
            self.parse_hostcfg_config(cps_config)

        except:
            Logger.error("fail to parse exception: %s" % (traceback.format_exc()))
            Logger.error(traceback.format_exc())
            sys.exit(1)

    def validate(self, validate_type, phase):
        if validate_type == utils.TYPE_DEPLOY_CONFIG:
            if phase != utils.PHASE_PRE:
                return True
            self.parseConfigInfoFromFile(NetworkConstant.NETWORK_INI_PATH)
            self.network_cfg_mgr.provider_validate()
            self.network_cfg_mgr.hostcfg_validate()
            self.network_cfg_mgr.sysintfnw_validate()
            # openstack网络配置的生效
            self.openstack_network_mgr.validate(validate_type, phase)
            # 提交
            cps_server.cps_commit()
        else:
            if phase == utils.PHASE_USER_CONFIG:
                self.parseConfigInfoFromFile(NetworkConstant.NETWORK_INI_PATH)
            self.network_cfg_mgr.provider_validate()
            self.network_cfg_mgr.sysintfnw_validate()
            self.network_cfg_mgr.hostcfg_validate()
            self.openstack_network_mgr.validate(validate_type, phase)
            cps_server.cps_commit()

    def create_def_config(self, config):
        Logger.info("create_def_config :%s."%config)
        if not os.path.exists(NetworkConstant.NETWORK_INI_PATH):
            #如果文件不存在，则创建
            ini_file = open(NetworkConstant.NETWORK_INI_PATH, 'w')
            ini_file.close()
            Logger.debug("write_data.default.ini doesn't exist,file is %s." % NetworkConstant.NETWORK_INI_PATH)
        cps_config = ConfigParser.RawConfigParser()
        cps_config.read(NetworkConstant.NETWORK_INI_PATH)
        sectionList = cps_config.sections()
        if NetworkConstant.NETWORK_SECTION not in sectionList:
            cps_config.add_section(NetworkConstant.NETWORK_SECTION)
        network_config = config.items(NetworkConstant.NETWORK_SECTION)
        for key, value in network_config:
            cps_config.set(NetworkConstant.NETWORK_SECTION, key, value)
        cps_config.write(open(NetworkConstant.NETWORK_INI_PATH, 'w'))
