#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import copy
import os

import json
import fs_log_util
import cps_server
import fsutils as utils
from os.path import join

#日志定义
import fs_system_constant

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class Dynamic_role():
    def __init__(self):
        self.lst_all_host, allhostsip = cps_server.get_all_hosts()


    def get_section_list(self):
        return [fs_system_constant.SECTION_DYNAMIC_ROLE]


    def get_file_path(self):
        return fs_system_constant.SECTION_DYNAMIC_ROLE


    def save_role_list(self, role, temp_list):
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        if not config.has_section(fs_system_constant.SECTION_DYNAMIC_ROLE):
            config.add_section(fs_system_constant.SECTION_DYNAMIC_ROLE)
        config.set(fs_system_constant.SECTION_DYNAMIC_ROLE,
                   "%s_%s" % (str(role), fs_system_constant.SECTION_DYNAMIC_ROLE_LIST), json.dumps(temp_list))
        with open(fs_system_constant.SYSTEM_INI_PATH, 'w') as fd:
            config.write(fd)


    def get_role_list(self, role):
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        if config.has_option(fs_system_constant.SECTION_DYNAMIC_ROLE, "%s_%s" % (role, fs_system_constant.SECTION_DYNAMIC_ROLE_LIST)):
            role_list = config.get(fs_system_constant.SECTION_DYNAMIC_ROLE, "%s_%s" % (role, fs_system_constant.SECTION_DYNAMIC_ROLE_LIST))
            if role_list is None or role_list == '':
                return None
            return json.loads(role_list)
        return None


    def config_role(self, role):
        role_host = cps_server.get_all_role_hosts(role)
        temp_list = copy.deepcopy(role_host)

        while 1:
            temp_no = 0
            temp_dict = {}
            for host in self.lst_all_host:
                temp_no += 1
                temp_dict[str(temp_no)] = host
                if host in temp_list:
                    print "[%s] Delete %s role @%s" % (str(temp_no), role, host)
                else:
                    print "[%s] Add %s role @%s" % (str(temp_no), role, host)
            print "[s] Save&quit"
            if temp_no == 1:
                input_str = raw_input("Please choose [1|s][s]")
            else:
                input_str = raw_input("Please choose [1-%s|s][s]" % str(temp_no))
            if input_str == '' or input_str == 's':
                self.save_role_list(role, temp_list)
                return
            if temp_dict.has_key(input_str):
                host = temp_dict[input_str]
                if host in temp_list:
                    temp_list.remove(host)
                else:
                    temp_list.append(host)
                continue
            print "Input error"

    def config(self, type):
        while 1:
            print '[1] Router : Router provides router, VPN, firewall,and DHCP (which dynamically assigns IP addresses) services for VMs in different projects.'
            print '[2] Loadbalancer : Provides LoadBalancer to openstack services.'
            print '[3] Blockstorage : Blockstorage manages block storage resources.'
            print '[4] Blockstorage-driver : Blockstorage-driver serves as the volume driver of the Cinder service and alloc release volumes from Fusionstorage agent.'
            print '[s] Save&quit'
            input_str = raw_input('Please choose [1-4|s][s]')
            if input_str == '' or input_str == 's':
                print 'Dynamic Role take some time to take effect. '
                print 'Proposal over three minutes later a similar operation.'
                break
            if input_str == '1':
                self.config_role(utils.ROLE_NAME_NETWORK)
                continue
            if input_str == '2':
                self.config_role(utils.ROLE_NAME_LOADBALANCER)
                continue
            if input_str == '3':
                self.config_role(utils.ROLE_NAME_BLOCKSTORAGE)
                continue
            if input_str == '4':
                self.config_role(utils.ROLE_NAME_BLOCKSTORAGE_DRIVER)
                continue
            print 'Please input [1-4|s]'
            continue

    def validate_role_blockstorage_driver(self, role):
        temp_list = self.get_role_list(role)
        if temp_list is not None:
            role_host = cps_server.get_all_role_hosts(role)
            for this_host in self.lst_all_host:
                if this_host in role_host and not this_host in temp_list:
                    cps_server.role_host_delete(role, [this_host])
                if not this_host in role_host and this_host in temp_list:
                    cps_server.role_host_add(role, [this_host])
            self.clear(role)
            cps_server.cps_commit()
        
        role_host = cps_server.get_all_role_hosts(role)
        volume_params = cps_server.get_template_params("cinder","cinder-volume")
        volume_hosts_str = volume_params['cfg']['volume_hosts']
        if volume_hosts_str is not None and volume_hosts_str != '':
            volume_hosts = volume_hosts_str.split(',')
            for i in range(len(volume_hosts))[::-1]:
                if volume_hosts[i] not in role_host:
                    volume_hosts[i] = ''
            for host in role_host:
                if host not in volume_hosts:
                    found = False
                    for i in range(len(volume_hosts)):
                        if volume_hosts[i] == '':
                            volume_hosts[i] = host
                            found = True
                            break
                    if found is False:
                        volume_hosts.append(host)
        else:
            volume_hosts = role_host
            
        finally_volume = ','.join(volume_hosts)
        if volume_hosts_str != finally_volume:
            params = {"volume_hosts": finally_volume}
            cps_server.update_template_params("cinder", "cinder-volume", params)
            cps_server.update_template_params("cinder", "cinder-backup", params)
            cps_server.cps_commit()
        return

    def validate_role(self, role):
        temp_list = self.get_role_list(role)
        if temp_list is None:
            return
        role_host = cps_server.get_all_role_hosts(role)
        for this_host in self.lst_all_host:
            if this_host in role_host and not this_host in temp_list:
                cps_server.role_host_delete(role, [this_host])
            if not this_host in role_host and this_host in temp_list:
                cps_server.role_host_add(role, [this_host])
        self.clear(role)
        return

    def validate(self, type, phase):
        if type == utils.TYPE_ONLY_DEPLOY and phase == utils.PHASE_PRE:
            pass

        if type == utils.TYPE_ONLY_CONFIG:
            self.validate_role(utils.ROLE_NAME_NETWORK)
            self.validate_role(utils.ROLE_NAME_LOADBALANCER)
            self.validate_role(utils.ROLE_NAME_BLOCKSTORAGE)
            self.validate_role_blockstorage_driver(utils.ROLE_NAME_BLOCKSTORAGE_DRIVER)
            cps_server.cps_commit()

    def clear(self, role):
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        if config.has_option(fs_system_constant.SECTION_DYNAMIC_ROLE, "%s_%s" % (role, fs_system_constant.SECTION_DYNAMIC_ROLE_LIST)):
            config.remove_option(fs_system_constant.SECTION_DYNAMIC_ROLE, "%s_%s" % (role, fs_system_constant.SECTION_DYNAMIC_ROLE_LIST))
        with open(fs_system_constant.SYSTEM_INI_PATH, 'w') as fd:
            config.write(fd)

    def create_def_config(self, config):
        self.clear(utils.ROLE_NAME_NETWORK)
        self.clear(utils.ROLE_NAME_BLOCKSTORAGE)
        self.clear(utils.ROLE_NAME_BLOCKSTORAGE_DRIVER)
