#!/usr/bin/python
#coding:utf-8


class RoleInstallerBase(object):
    """
    针对新组件接入一键式部署角色，定义的基类
    """
    def __init__(self):
        pass

    def is_need_deploy(self, cfg):
        """
        功能：根据各个角色的配置，确定是否需要部署该角色
        返回值：部署-True， 不部署-False
        """
        return False

    def choose_role_hosts(self, config,  host_mode, ctrl_host):
        """
        功能：配置角色涉及组件的参数，选择需要部署该角色的host
        返回值： 角色名称和需要部署该角色的hostname列表
        """
        return "", []


class RoleInstallError(Exception):
    """
    自定义新组件部署异常类
    """
    def __init__(self, msg):
        super(RoleInstallError, self).__init__()
        self.msg = msg

    def __str__(self):
        return str(self.msg)
