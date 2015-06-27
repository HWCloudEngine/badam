#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import os
import traceback
from os.path import join
import cps_server
import fs_log_util
import fs_neutron_constant


#与openstack相关的配置文件信息
SERVICE_NAME = "service_name"
TEMPLATE_NAME = "template_name"
PARAM = "param"
CLOSE_SECURITY_LIST = [{SERVICE_NAME: "nova", TEMPLATE_NAME: "nova-compute", PARAM: {"security_group_api": "nova",
                                                                                     "firewall_driver": "nova.virt.firewall.NoopFirewallDriver",
                                                                                     "libvirt_vif_driver": "nova.virt.libvirt.vif.LibvirtGenericVIFDriver"}},
                       {SERVICE_NAME: "nova", TEMPLATE_NAME: "nova-api", PARAM: {"security_group_api": "nova"}},
                       {SERVICE_NAME: "nova", TEMPLATE_NAME: "nova-conductor", PARAM: {"security_group_api": "nova"}},
                       {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-server", PARAM: {"firewall_driver": "neutron"
                                                                                                             ".agent.firewall.NoopFirewallDriver"}},
                       {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-server", PARAM: {"enable_security_group": "False"}},
                       {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-openvswitch-agent", PARAM: {"enable_ipset": "False"}},
                       {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-openvswitch-agent", PARAM: {"enable_security_group": "False"}},
                       {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-openvswitch-agent",
                        PARAM: {"firewall_driver": "neutron.agent.firewall.NoopFirewallDriver"}}]
OPEN_SECURITY_LIST = [{SERVICE_NAME: "nova", TEMPLATE_NAME: "nova-compute", PARAM: {"security_group_api": "neutron",
                                                                                     "firewall_driver": "nova.virt"
                                                                                                       ".firewall"
                                                                                                       ".NoopFirewallDriver"}},
                      {SERVICE_NAME: "nova", TEMPLATE_NAME: "nova-api", PARAM: {"security_group_api": "neutron"}},
                      {SERVICE_NAME: "nova", TEMPLATE_NAME: "nova-conductor", PARAM: {"security_group_api": "neutron"}},
                      {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-server",
                       PARAM: {"firewall_driver": "neutron.agent.linux.iptables_firewall"
                                                  ".OVSHybridIptablesFirewallDriver"}},
                      {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-server", PARAM: {"enable_security_group": "True"}},
                      {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-openvswitch-agent", PARAM: {"enable_ipset": "True"}},
                      {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-openvswitch-agent", PARAM: {"enable_security_group": "True"}},
                      {SERVICE_NAME: "neutron", TEMPLATE_NAME: "neutron-openvswitch-agent", PARAM: {
                          "firewall_driver": "neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver"}}]

CLOSE_VXLAN_LIST = [{SERVICE_NAME: "neutron",
                     TEMPLATE_NAME: "neutron-server",
                     PARAM: {"tenant_network_types": "flat,vlan"}},
                    {SERVICE_NAME: "neutron",
                     TEMPLATE_NAME: "neutron-openvswitch-agent",
                     PARAM: {"enable_tunneling": "False",
                             "l2_population": "False",
                             "tenant_network_type": "flat,vlan"}}]
OPEN_VXLAN_LIST = [{SERVICE_NAME: "neutron",
                    TEMPLATE_NAME: "neutron-server",
                    PARAM: {"tenant_network_types": "vxlan,flat,vlan"}},
                   {SERVICE_NAME: "neutron",
                    TEMPLATE_NAME: "neutron-openvswitch-agent",
                    PARAM: {"enable_tunneling": "True",
                            "l2_population": "True",
                            "tenant_network_type": "vxlan,flat,vlan"}}]




#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class NeutronUtil():
    def __init__(self):
        pass

    def close_security_group(self, cf):
        LOG.info("begin to close security group cf = %s."%cf)
        for item_list in CLOSE_SECURITY_LIST:
            flag = cps_server.update_template_params(item_list[SERVICE_NAME], item_list[TEMPLATE_NAME],
                                                     item_list[PARAM])
            if not flag:
                LOG.error("fail to close security group")
                return False
        LOG.info("succeed to close security group")
        return True

    def open_security_group(self, cf):
        LOG.info("begin to open security groupcf = %s."%cf)
        for item_list in OPEN_SECURITY_LIST:
            flag = cps_server.update_template_params(item_list[SERVICE_NAME], item_list[TEMPLATE_NAME], item_list[PARAM])
            if not flag:
                LOG.error("fail to open security group")
                return False
        LOG.info("succeed to open security group")
        return True

    def close_vxlan_flag(self, cf):
        LOG.info("begin to close_vxlan_flag cf = %s."%cf)
        for item_list in CLOSE_VXLAN_LIST:
            flag = cps_server.update_template_params(item_list[SERVICE_NAME], item_list[TEMPLATE_NAME],
                                                     item_list[PARAM])
            if not flag:
                LOG.error("fail to close_vxlan_flag.")
                return False
        LOG.info("succeed to close_vxlan_flag.")
        return True

    def open_vxlan_flag(self, cf):
        LOG.info("begin to open_vxlan_flag cf = %s."%cf)
        for item_list in OPEN_VXLAN_LIST:
            flag = cps_server.update_template_params(item_list[SERVICE_NAME], item_list[TEMPLATE_NAME],item_list[PARAM])
            if not flag:
                LOG.error("fail to open_vxlan_flag.")
                return False
        LOG.info("succeed to open_vxlan_flag.")
        return True

    def neutron_get_data(self, section, keys):
        """
        获取配置文件中的数据
        """
        cf = ConfigParser.ConfigParser()
        if not os.path.exists(fs_neutron_constant.NEUTRON_INI_PATH):
            LOG.info("get_data.default.ini doesn't exist,file is %s." % fs_neutron_constant.NEUTRON_INI_PATH)
            return None
        else:
            try:
                cf.read(fs_neutron_constant.NEUTRON_INI_PATH)
                values = []
                for key in keys:
                    value = cf.get(section, key)
                    values.append(value)
                return values
            except Exception, err:
                LOG.error("get data file. Exception, e:%s,err:%s" % (traceback.format_exc(), err))
                return None

    def neutron_write_data(self, section, keys_and_values):
        """
        修改配置文件中的值,将传入参数的值持久化到配置文件当中。
        """
        cf = ConfigParser.ConfigParser()
        if not os.path.exists(fs_neutron_constant.NEUTRON_INI_PATH):
            ini_file = open(fs_neutron_constant.NEUTRON_INI_PATH, 'w')
            ini_file.close()
            LOG.debug("write_data.default.ini doesn't exist,file is %s." % fs_neutron_constant.NEUTRON_INI_PATH)

        try:
            cf.read(fs_neutron_constant.NEUTRON_INI_PATH)
            if not cf.has_section(section):
                cf.add_section(section)
            for k, v in keys_and_values.iteritems():
                cf.set(section, k, v)
            cf.write(open(fs_neutron_constant.NEUTRON_INI_PATH, "w"))
            return True
        except Exception, err:
            LOG.error("write data file. Exception, e:%s, err:%s" % (traceback.format_exc(),err))
            return False
