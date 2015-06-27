#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join


class NetworkConstant(object):
    NETWORK_INI_PATH = join(os.path.dirname(os.path.abspath(__file__)), 'fs_network.ini')
    NETWORK_SECTION = "network"
    NETWORK_NAME_KEY = "name"
    
    NETWORK_PROVIDER_OPTION = "provider"
    NETWORK_PROVIDER_VLANPOOL = "vlanpool"
    NETWORK_PROVIDER_FIELDS = [NETWORK_NAME_KEY,
                               NETWORK_PROVIDER_VLANPOOL]
    
    NETWORK_SYSINTFNW_OPTION = "sysintfnw"
    NETWORK_SYSINTFNW_VLAN = "vlan"
    NETWORK_SYSINTFNW_PROVIDER = "provider_name"
    NETWORK_SYSINTFNW_SUBNET = "subnet"
    NETWORK_SYSINTFNW_IPPOOL = "ippool"
    NETWORK_SYSINTFNW_GATEWAY = "gateway"
    NETWORK_SYSINTFNW_ONLY_VLAN = ["internal_base", "storage_data0", "storage_data1", "tunnel_bearing"]
    NETWORK_SYSINTFNW_OM_FIELDS = [NETWORK_NAME_KEY,
                                   NETWORK_SYSINTFNW_VLAN,
                                   NETWORK_SYSINTFNW_SUBNET,
                                   NETWORK_SYSINTFNW_IPPOOL,
                                   NETWORK_SYSINTFNW_GATEWAY,
                                   NETWORK_SYSINTFNW_PROVIDER]

    NETWORK_GROUP_DEFAULT_HOSTCFG = "group1"
    NETWORK_HOSTCFG_OPTION = "hostcfg"
    NETWORK_HOSTCFG_NIC = "nic"
    NETWORK_HOSTCFG_BOND = "bond"
    NETWORK_HOSTCFG_PROVIDERMAPPING = "providermapping"
    NETWORK_HOSTCFG_SYSINTFNWMAPPING = "sysintfnwmapping"
    NETWORK_HOSTCFG_INFO_NIC_ADD = "nic_add"
    NETWORK_HOSTCFG_INFO_BOND_ADD = "bond_add"
    NETWORK_HOSTCFG_INFO_MAPPING_ADD = "providermapping_add"
    NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE = "sysintfnwmapping_change"
    NETWORK_OPTION_INTERNAL_BASE_FLAG = "create_internal_base_flag"
    NETWORK_HOSTCFG_MCCP_FIELDS = [NETWORK_HOSTCFG_NIC,
                                   NETWORK_HOSTCFG_BOND,
                                   NETWORK_HOSTCFG_PROVIDERMAPPING,
                                   NETWORK_HOSTCFG_SYSINTFNWMAPPING]
    NETWORK_HOSTCFG_FIELDS = [NETWORK_NAME_KEY,
                              NETWORK_HOSTCFG_INFO_NIC_ADD,
                              NETWORK_HOSTCFG_INFO_BOND_ADD,
                              NETWORK_HOSTCFG_INFO_MAPPING_ADD,
                              NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE]

    NETWORK_ROUTE_OPTION = "default_route"

    ST_ORIG = "orig"
    ST_ADD = "add"
    ST_DEL = "del"
    ST_DIRTY = "dirty"
    ST_UPDATE = "update"
    ST_ONLY_VLAN = "only vlan"
    STR_NET_TYPE_API = "external_api"
    STR_NET_TYPE_OM = "external_om"
    STR_NET_TYPE_BASE = "internal_base"

    HOST_CFG_TYPE_FIELDS = ['name', 'type', 'hosts', 'nic', 'bond', 'providermapping', 'sysintfnwmapping']
    EXTERNAL_API_VLAN = "external_api_vlan"
    EXTERNAL_API_SUBNET = "external_api_subnet"
    EXTERNAL_API_GATEWAY = "external_api_gateway"
    EXTERNAL_API_POOL_START = "external_api_pool_start"
    EXTERNAL_API_POOL_END = "external_api_pool_end"
    EXTERNAL_API_PROVIDER = "external_api_provider"

    LST_MAPPING_TYPE_COMPATIBLE = ["kernel-ovs","user-evs", "sriov-nic", "netmap-nic", "ovs", "vhostuser", "hardware-veb", "netmap", "share", "passthrough"]
    LST_OVS_MAPPING_COMPATIBLE = ["kernel-ovs", "ovs", "share"]
    LST_EVS_MAPPING_COMPATIBLE = ["user-evs", "vhostuser", "passthrough"]
    LST_SRIOV_COMPATIBLE = ["sriov-nic", "hardware-veb", "passthrough"]
    LST_NETMAP_COMPATIBLE = ["netmap-nic", "netmap"]

    physical_mapping_dict_compatible = {
                        #FSP 5.1 B032: 4 mapping types
                        'ovs': 'ovs',
                        'vhostuser': 'evs',
                        'hardware-veb': 'sriov',
                        'netmap': 'netmap',

                        #FSP 5.1 B031: 4 mapping types
                        'kernel-ovs': 'ovs',
                        'user-evs': 'evs',
                        'sriov-nic': 'sriov',
                        'netmap-nic': 'netmap',

                        # FSP 5.0: 3 mapping types, SRIOV and EVS all use passthrough, must be determined by vf_num yet
                        'share': 'ovs',
                        'passthrough': 'evs-or-sriov'}



