#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join
import fs_log_util

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)

class Constant(object):
    #host_cfg config
    HOST_CFG = "host_cfg"

    COMPUTE_HOST_TYPE = "compute"

    CONTROL_HOST_TYPE = "control"

    COMPUTE_HOST_HWTYPE = "computehost_hwtype"

    CTRl_HOST_HWTYPE = "ctrlhost_hwtype"

    CTRL_HOST_HWTYPE_PCI_PRE = "ctrl_extend_disk_pci_"

    COMPUTE_HOST_HWTYPE_PCI_PRE = "compute_extend_disk_pci_"

    PCI_KEY = "pci"

    CTRL_HOST = "ctrl_hosts"

    COMPUTE_HOST = "compute_hosts"

    HOST_LIST_KEY = "host_list"

    NETWORK_GROUPS = "network_group"

    NETWORK_GROUPS_HOST_PRE = "network_group_"

    NETWORK_GROUPS_NIC_PRE = "network_group_nic_add_"

    NETWORK_GROUPS_BOND_PRE = "network_group_bond_add_"

    NETWORK_GROUPS_MAPPING_PRE = "network_group_providermapping_add_"

    NETWORK_GROUPS_SYSINTFNWMAP_PRE = "network_group_sysintfnwmapping_change_"

    NETWORK_HOSTCFG_INFO_NIC_ADD = "nic_add"
    NETWORK_HOSTCFG_INFO_BOND_ADD = "bond_add"
    NETWORK_HOSTCFG_INFO_MAPPING_ADD = "providermapping_add"
    NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE = "sysintfnwmapping_change"

    HOST_CFG_TYPE_FIELDS = ['name','type','hosts','nic','bond','providermapping', 'sysintfnwmapping']


    STORAGE_DATA0 = "storage_data0"
    STORAGE_DATA1 = "storage_data1"
    TUNNEL_BEARING = "tunnel_bearing"
    INTERNAL_BASE = "internal_base"
    EXTERNAL_API = "external_api"
    EXTERNAL_OM = "external_om"
    LST_SYSINTFNW_NAME = [STORAGE_DATA0,
                          STORAGE_DATA1,
                          TUNNEL_BEARING,
                          INTERNAL_BASE,
                          EXTERNAL_API,
                          EXTERNAL_OM]

    LST_BOND_MODE = ["nobond","lacp"]

    LST_MAPPINT_TYPE = ["kernel-ovs","user-evs", "sriov-nic", "netmap-nic"]

    LST_SYSINTFNW_CHANGE_KEY = ["vlan","provider_name"]

