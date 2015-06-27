#!/usr/bin/python
#coding:utf-8

import os
import sys
import ConfigParser
import json

from install_tool import log
import cps_server
import fs_role_installer_base


NEW_INSTALLER_ENV_INI = "new_installer_env.ini"
SEC_INSTALLER = "deployer"
OPT_INSTALLERS = "deployers"


def get_installer_instances():
    """
    功能： 根据配置文件new_installer_env.ini中的配置，实例化新组件部署类
    返回值： 返回实例对象列表
    """
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    installer_env_file = os.path.join(cur_dir, NEW_INSTALLER_ENV_INI)
    cfg = ConfigParser.RawConfigParser()
    cfg.read(installer_env_file)

    new_role_installers = cfg.get(SEC_INSTALLER, OPT_INSTALLERS)
    new_role_installers = json.loads(new_role_installers)

    installer_insts_lst = []
    for i in range(len(new_role_installers)):
        installer_dct = new_role_installers[i]
        module_path = installer_dct["path"]
        module_name = installer_dct["import"]
        class_name = installer_dct["class"]

        sys.path.append(module_path)
        im_module = __import__(module_name)
        instance = getattr(im_module, class_name)()
        installer_insts_lst.append(instance)

    return installer_insts_lst


class NewRoleInstaller(object):
    """
    针对新组件接入的组件部署框架类
    """
    installer_insts_lst = get_installer_instances()
    role_host_dct = {}

    @staticmethod
    def add_role_host_2_queue(config, host_mode, ctrl_hosts):
        """
        功能：调用各个新组件的部署实例对象，将role-host信息添加到队列
        返回值： 成功-True, 失败-False
        """
        for inst in NewRoleInstaller.installer_insts_lst:
            if not inst.is_need_deploy(config):
                continue
            try:
                role, deploy_lst = inst.choose_role_hosts(config, host_mode,
                                                          ctrl_hosts)
                NewRoleInstaller.role_host_dct[role] = deploy_lst
            except fs_role_installer_base.RoleInstallError as err_str:
                log.error("config_and_choose_role_hosts Exception:%s" % err_str)
                return False
        return True

    @staticmethod
    def deploy_role_2_host():
        """
        功能：根据队列中的role-host信息，将角色部署到对应host上
        返回值： 成功-True，失败-False
        """
        for role, deploy_lst in NewRoleInstaller.role_host_dct.iteritems():
            for host in deploy_lst:
                if not cps_server.role_host_add(role, [host]):
                    log.error("add %s role failed" % str(role))
                    return False
        return True




