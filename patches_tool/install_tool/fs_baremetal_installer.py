#!/usr/bin/python
#coding:utf-8

import json

import fsutils
import fs_role_installer_base
import fs_system_server
import cps_server
from fs_common_constant import DefaultConst
from fs_common_constant import ParamsConst

BAREMETAL_ROLE = "baremetal"

class BaremetalDeploy(fs_role_installer_base.RoleInstallerBase):
    """
    需要部署baremetal角色的host的选择和相关组件的参数刷新
    """
    def __init__(self):
        super(BaremetalDeploy, self).__init__()

    def is_need_deploy(self, cfg):
        """
        根据配置判断是否部署baremetal角色
        """
        is_deploy = "false"
        if cfg.has_option(DefaultConst.SEC_DEPLOY_POLICY,
                          DefaultConst.OPT_DEPLOY_BAREMETAL):
            is_deploy = cfg.get(DefaultConst.SEC_DEPLOY_POLICY,
                                DefaultConst.OPT_DEPLOY_BAREMETAL)
        if is_deploy.lower() == "true":
            return True
        else:
            return False

    def choose_role_hosts(self, config,  host_mode, ctrl_host_lst):
        """
        将需要部署baremetal角色，添加到待部署role-host字典中
        """
        if host_mode == fsutils.FS_DEPLOY_MODE_TWO:
            baremetal_hosts = ctrl_host_lst[0:2]
        else:
            baremetal_hosts = ctrl_host_lst
        return BAREMETAL_ROLE, baremetal_hosts



