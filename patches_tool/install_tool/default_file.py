#!/usr/bin/env python
#-*-coding:utf-8-*-

#日志定义
import ConfigParser
import copy
import json
import os
import sys
import traceback
import time
import commands
import fs_change_util
import fs_log_util
import fs_system_constant
import fs_system_util
import fsinstall
import fsutils as utils
from os.path import join
import fs_modes
import cps_server

import fs_common_installer


CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')

logger = fs_log_util.localLog.get_logger(LOG_FILE)

DEFAULT_INI_SECTION_DEPLOY_POLICY = 'deploy_policy'
DEFAULT_INI_OPTION_DEPLOY_POLICY_HOST_MODE = 'host_mode'
DEFAULT_INI_OPTION_DEPLOY_POLICY_CTRL_HOSTS = 'ctrl_hosts'
DEFAULT_INI_OPTION_DEPLOY_POLICY_LB_HOSTS = 'lb_hosts'
DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_HOSTS = 'router_hosts'
DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_MODE = 'router_mode'
DEFAULT_INI_OPTION_DEPLOY_CINDER_DEFAULT_STORE = 'cinder_default_store'
DEFAULT_INI_OPTION_DEPLOY_BS_DRIVER_HOSTS = 'blockstorage_driver_hosts'

DEFAULT_INI_SECTION_DOMAIN = 'domain'
DEFAULT_INI_OPTION_DOMAIN_KEYSTONE_DOMAIN = 'keystone_domain'
DEFAULT_INI_OPTION_DOMAIN_GLANCE_DOMAIN = 'glance_domain'
DEFAULT_INI_OPTION_DOMAIN_LOCAL_AZ = 'local_az'
DEFAULT_INI_OPTION_DOMAIN_LOCAL_DC = 'local_dc'
DEFAULT_INI_OPTION_DOMAIN_POSTFIX = 'domainpostfix'


class DefaultFile():
    def __init__(self):
        self.config_bk = None
        self.is_config_exist_bk = None
        self.password_section_name = 'password'
        self.cloud_password_option_name = 'cloud_password'
        self.dc_password_option_name = 'dc_password'
        self.storage_passwords_option_name = 'storage_passwords'


    def load_default(self, filename):
        default_file_name = "/etc/huawei/fusionsphere/cfg/default.ini"
        default_file_new_name = "/etc/huawei/fusionsphere/cfg/default_new.ini"
        if not os.path.exists(filename):
            print "file not exist.file is %s" % filename
            logger.error("file not exist.file is %s" % filename)
            return
        dos2unixCmd = "dos2unix %s "%filename
        dos2unixCmd2 = "dos2unix %s "%default_file_name
        commands.getstatusoutput(dos2unixCmd)
        commands.getstatusoutput(dos2unixCmd2)

        if not os.path.exists(default_file_name):
            self.load(filename)
            logger.warning("%s not exist load only by input" % default_file_name)
            return
        try:
            config = ConfigParser.RawConfigParser()
            config.read(filename)

            default_cf = ConfigParser.RawConfigParser()
            default_cf.read(default_file_name)
            for section in config.sections():
                if not default_cf.has_section(section):
                    default_cf.add_section(section)
                for key, value in config.items(section):
                    default_cf.set(section, key, value)
            with open(default_file_new_name, 'w') as fd:
                default_cf.write(fd)
        except:
            logger.error("failed %s" % traceback.format_exc())
            return
        logger.info("start load")

        self.load(default_file_new_name)


    def load(self, filename):
        """
        导入配置文件数据
        """
        dos2unixCmd = "dos2unix %s "%filename
        commands.getstatusoutput(dos2unixCmd)
        try:
            fs_system_util.change_all_flag_list("true")
            fs_change_util.change_all_flag_list(fs_change_util.CHANGE_TYPE)
            fs_change_util.set_disk_check_time(60)
            self.load_pre()
            if not os.path.exists(filename):
                print "File:%s not exist" % filename
                logger.error("File:%s not exist" % filename)
                return
            config = ConfigParser.RawConfigParser()
            config.read(filename)

            #1.根据配置文件部署，已经完成部署的场景提示用户是否只进行配置，当前不支持重复部署
            (this_mode, ctrl_hosts) = fs_modes.check_modes()
            if not this_mode is None:
                print "This az has been deployed with mode %s." % this_mode.get_name()
            else:
                print "Start deploy. %s" % time.strftime('%Y-%m-%d %H:%M:%S')
                if not load_deploy(config):
                    self.load_back()
                    logger.error("deploy fail")
                    return
                else:
                    print "Deploy successfully. %s" % time.strftime('%Y-%m-%d %H:%M:%S')
            print ""
            print "Start config. %s" % time.strftime('%Y-%m-%d %H:%M:%S')
            #2.根据配置文件配置
            if not all_section_file_config(config):
                logger.error("config error")
                return
            print ""
            print "Config successfully. %s" % time.strftime('%Y-%m-%d %H:%M:%S')
            print "All install has been success. %s" % time.strftime('%Y-%m-%d %H:%M:%S')
        except KeyboardInterrupt:
            logger.error("occur KeyboardInterrupt exception. ")
            print 'Terminating client!'
            sys.exit(1)
        except:
            logger.error("load failed %s" % traceback.format_exc())
            print "HELP! I am in  trouble.please rerun me or connect HUAWEI FSP support staff!"


    def load_pre(self):
        self.is_config_exist_bk = os.path.exists(utils.DEFAULT_FILE_NAME)
        if os.path.exists(utils.DEFAULT_FILE_NAME):
            self.config_bk = ConfigParser.RawConfigParser()
            self.config_bk.read(utils.DEFAULT_FILE_NAME)

    def load_back(self):
        if self.config_bk is None:
            if os.path.exists(utils.DEFAULT_FILE_NAME):
                cmd = "rm " + utils.DEFAULT_FILE_NAME
                fsinstall.run_command(cmd)
        else:
            with open(utils.DEFAULT_FILE_NAME, 'w') as fd:
                self.config_bk.write(fd)


def save():
    try:
        filename = input_file_name()
        config = ConfigParser.RawConfigParser()
        config.read(utils.DEFAULT_FILE_NAME)

        with open(filename, 'w') as fd:
            config.write(fd)
        print "Save successfully at %s" % filename
    except:
        logger.error("save failed with traceback : %s" % traceback.format_exc())


def file_config_base(config, section_list, file_name, process, show_name):
    config_sys = ConfigParser.RawConfigParser()
    if not os.path.exists(file_name):
        with open(file_name, 'w') as fd:
            config_sys.write(fd)
    else:
        config_sys.read(file_name)
    config_bk = copy.deepcopy(config_sys)
    is_change_flag = False
    for section_name in section_list:
        if config.has_section(section_name):
            if not config_sys.has_section(section_name):
                config_sys.add_section(section_name)
            items_sys = config.items(section_name)
            for key, value in items_sys:
                config_sys.set(section_name, key, value)
            is_change_flag = True

    if not is_change_flag:
        return

    try:
        with open(file_name, 'w') as fd:
            config_sys.write(fd)
        process.validate(utils.TYPE_ONLY_CONFIG, utils.PHASE_USER_CONFIG)
        print "%s config success" % show_name
    except KeyboardInterrupt:
        logger.error("occur KeyboardInterrupt exception. ")
        raise KeyboardInterrupt()
    except:
        print "%s  config failed" % show_name
        logger.error("file_config failed %s config is %s ,traceback is %s" % (
            show_name, utils.get_safe_message(str(config)), traceback.format_exc()))
        with open(file_name, 'w') as fd:
            config_bk.write(fd)
        sys.exit(1)


def get_config(file_name, section_name):
    config_sys = ConfigParser.RawConfigParser()
    if not os.path.exists(file_name):
        with open(file_name, 'w') as fd:
            config_sys.write(fd)
    else:
        config_sys.read(file_name)
    if not config_sys.has_section(section_name):
        config_sys.add_section(section_name)
    return config_sys


def all_section_file_config(config):
    section_map = utils.build_map()
    for k in sorted(section_map.iterkeys()):
        v = section_map[k]
        vname = str(v[utils.SECTION_NAME])
        process = v[utils.SECTION_INSTANCE]
        if process is not None:
            tryTime = 0
            while  tryTime < 2:
                logger.info("SYS:into validate Http Mode, time = %s" %tryTime)
                failed = False
                try:
                    print ""
                    print "Start config %s. %s" % (str(v[utils.SECTION_NAME]), time.strftime('%Y-%m-%d %H:%M:%S'))
                    file_config_base(config, process.get_section_list(), process.get_file_path(), process, v[utils.SECTION_NAME])
                    print "Config %s success. %s " % (str(v[utils.SECTION_NAME]), time.strftime('%Y-%m-%d %H:%M:%S'))
                    print ""
                except KeyboardInterrupt:
                    logger.error("occur KeyboardInterrupt exception. ")
                    raise KeyboardInterrupt()
                except:
                    logger.error("all_section_file_config failed. name is %s.traceback is %s" % (vname, traceback.format_exc()))
                    failed = True

                if failed:
                    print "Save %s failed, try again, please wait about 10 seconds." %vname
                    time.sleep(10)
                    tryTime = tryTime + 1
                else:
                    break
            if tryTime == 2 :
                print "Save %s failed, please check by yourself!" %vname
                logger.error("SYS:Save %s failed, times is out, please check by yourself!" %vname)
                sys.exit(1)
    return True


def load_deploy(config):
    try:
        if not cover_deploy_check(config):
            print "Input File is not available"
            logger.error("check deploy file fail")
            return False

        fsinstall.validate()
    except KeyboardInterrupt:
        print 'Terminating client!'
        return False
    except:
        logger.error("deploy by config failed %s" % traceback.format_exc())
        return False
    return True


def ask_is_continue():
    print "This environment has been deployed"
    while 1:
        input_str = raw_input("Do you want to continue load without deploy [y|n][n]")
        if input_str == 'n' or input_str == '':
            return False
        if input_str == 'y':
            return True


def cover_deploy_check(config):
    try:
        #对配置文件进行合法性检查
        #1检查host_mode合法性
        if not config.has_option(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_HOST_MODE):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_HOST_MODE)
            print msg
            logger.error(msg)
            return False
        host_mode = config.get(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_HOST_MODE)

        #2检查host_list的合法性
        if not config.has_option(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_CTRL_HOSTS):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_CTRL_HOSTS)
            print msg
            logger.error(msg)
            return False
        pre_host_list = json.loads(
            config.get(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_CTRL_HOSTS))
        host_list = get_host_ids_by_macs(pre_host_list)
        if host_list is False:
            print "Error in file %s:%s" % (DEFAULT_INI_OPTION_DEPLOY_POLICY_CTRL_HOSTS, str(pre_host_list))
            logger.error("Error in file %s:%s" % (DEFAULT_INI_OPTION_DEPLOY_POLICY_CTRL_HOSTS, str(pre_host_list)))
            return False

        #3检查host_list和host_mode是否冲突
        if not check_host_deploy(host_mode, host_list):
            logger.error("check_host_deploy failed")
            return False

        #4检查keyston domain合法性
        if not config.has_option(DEFAULT_INI_SECTION_DOMAIN, DEFAULT_INI_OPTION_DOMAIN_KEYSTONE_DOMAIN):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DOMAIN, DEFAULT_INI_OPTION_DOMAIN_KEYSTONE_DOMAIN)
            print msg
            logger.error(msg)
            return False
        keystone_domain = config.get(DEFAULT_INI_SECTION_DOMAIN, DEFAULT_INI_OPTION_DOMAIN_KEYSTONE_DOMAIN)
        if not fs_system_util.check_domain(keystone_domain):
            print "Error in file %s:%s" % (DEFAULT_INI_OPTION_DOMAIN_KEYSTONE_DOMAIN, keystone_domain)
            logger.error("Error in file %s:%s" % (DEFAULT_INI_OPTION_DOMAIN_KEYSTONE_DOMAIN, keystone_domain))
            return False

        #5检查glance domain合法性
        if not config.has_option(DEFAULT_INI_SECTION_DOMAIN, DEFAULT_INI_OPTION_DOMAIN_GLANCE_DOMAIN):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DOMAIN, DEFAULT_INI_OPTION_DOMAIN_GLANCE_DOMAIN)
            print msg
            logger.error(msg)
            return False
        glance_domain = config.get(DEFAULT_INI_SECTION_DOMAIN, DEFAULT_INI_OPTION_DOMAIN_GLANCE_DOMAIN)
        if not fs_system_util.check_domain(glance_domain):
            print "Error in file %s:%s" % (DEFAULT_INI_OPTION_DOMAIN_GLANCE_DOMAIN, glance_domain)
            logger.error("Error in file %s:%s" % (DEFAULT_INI_OPTION_DOMAIN_GLANCE_DOMAIN, glance_domain))
            return False

        #6检查本地域名合法性
        if not config.has_option(DEFAULT_INI_SECTION_DOMAIN, 'local_az'):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DOMAIN, 'local_az')
            print msg
            logger.error(msg)
            return False
        if not config.has_option(DEFAULT_INI_SECTION_DOMAIN, 'local_dc'):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DOMAIN, 'local_dc')
            print msg
            logger.error(msg)
            return False
        if not config.has_option(DEFAULT_INI_SECTION_DOMAIN, 'domainpostfix'):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DOMAIN, 'domainpostfix')
            print msg
            logger.error(msg)
            return False
        local_az = config.get(DEFAULT_INI_SECTION_DOMAIN, 'local_az')
        local_dc = config.get(DEFAULT_INI_SECTION_DOMAIN, 'local_dc')
        domain_postfix = config.get(DEFAULT_INI_SECTION_DOMAIN, 'domainpostfix')
        cps_server.set_local_domain(local_dc, local_az, domain_postfix)

        #9检查动态角色列表合法性
        if not config.has_option(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_LB_HOSTS):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_LB_HOSTS)
            print msg
            logger.error(msg)
            return False
        if not config.has_option(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_HOSTS):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_HOSTS)
            print msg
            logger.error(msg)
            return False
        if not config.has_option(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_CINDER_DEFAULT_STORE):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_CINDER_DEFAULT_STORE)
            print msg
            logger.error(msg)
            return False
        if not config.has_option(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_BS_DRIVER_HOSTS):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_BS_DRIVER_HOSTS)
            print msg
            logger.error(msg)
            return False
        pre_lb_list = json.loads(
            config.get(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_LB_HOSTS))
        lb_list = get_host_ids_by_macs(pre_lb_list)
        if lb_list is False:
            print "Error in file %s:%s" % (DEFAULT_INI_OPTION_DEPLOY_POLICY_LB_HOSTS, str(lb_list))
            logger.error("Error in file %s:%s" % (DEFAULT_INI_OPTION_DEPLOY_POLICY_LB_HOSTS, str(lb_list)))
            return False
        pre_router_list = json.loads(
            config.get(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_HOSTS))
        router_list = get_host_ids_by_macs(pre_router_list)
        if router_list is False:
            print "Error in file %s:%s" % (DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_HOSTS, str(router_list))
            logger.error("Error in file %s:%s" % (DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_HOSTS, str(router_list)))
            return False
        if len(router_list) == 0:
            if host_mode == utils.FS_DEPLOY_MODE_ONE:
                router_list.append(host_list[0])
            elif host_mode == utils.FS_DEPLOY_MODE_TWO or host_mode == utils.FS_DEPLOY_MODE_THREE:
                router_list.append(host_list[0])
                router_list.append(host_list[1])
        if not config.has_option(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_MODE):
            msg = "please set section:%s, option:%s" % (DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_MODE)
            print msg
            logger.error(msg)
            return False
        router_mode = config.get(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_POLICY_ROUTER_MODE)
        cinder_type = config.get(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_CINDER_DEFAULT_STORE)
        pre_bs_driver_list = json.loads(
            config.get(DEFAULT_INI_SECTION_DEPLOY_POLICY, DEFAULT_INI_OPTION_DEPLOY_BS_DRIVER_HOSTS))
        bs_driver_list = get_host_ids_by_macs(pre_bs_driver_list)
        if len(bs_driver_list) == 0:
            if host_mode == utils.FS_DEPLOY_MODE_TWO:
                bs_driver_list = host_list[0:2]
            else:
                bs_driver_list = host_list
        if bs_driver_list is False:
            print "Error in file %s:%s" % (DEFAULT_INI_OPTION_DEPLOY_BS_DRIVER_HOSTS, str(bs_driver_list))
            logger.error("Error in file %s:%s" % (DEFAULT_INI_OPTION_DEPLOY_BS_DRIVER_HOSTS, str(bs_driver_list)))
            return False
        if cinder_type == fs_system_constant.CINDER_TYPE_FUSION_STORAGE:
            if host_mode == utils.FS_DEPLOY_MODE_TWO:
                bs_list = host_list[0:2]
            else:
                bs_list = host_list
        else:
            bs_list = []

        #10持久化一些关键信息
        fsinstall.set_deploy_role_host(router_list, lb_list, bs_list, bs_driver_list)
        fsinstall.save_deploy_msg(host_mode, host_list, keystone_domain, glance_domain)
        fsinstall.set_router_mode(router_mode)

        #添加role-host到部署队列
        if not fs_common_installer.NewRoleInstaller.add_role_host_2_queue(
                                              config, host_mode, host_list):
            return False

        return True
    except:
        logger.error("cover_deploy_check failed %s" % traceback.format_exc())
        return False


def get_host_ids_by_macs(input_list):
    host_id_list = []
    all_hosts, all_hosts_ip = cps_server.get_all_hosts()
    if "hostid" in input_list:
        for host_id in input_list["hostid"]:
            if host_id in all_hosts:
                if not host_id in host_id_list:
                    host_id_list.append(host_id)
            else:
                print "There is host id not exist :%s" % host_id
                logger.error("There is host id not exist :%s" % host_id)
                return False
    all_host_detail = cps_server.get_all_hosts_detail(all_hosts)
    if "mac" in input_list:
        mac_list = input_list["mac"]
        for mac in mac_list:
            host = get_host_id_by_mac(mac, all_host_detail)
            if host is None:
                print "There is mac not exist :%s" % mac
                logger.error("There is host id not exist :%s" % host_id)
                logger.error("all_host_detail: %s" % str(all_host_detail))
                return False
            if not host in host_id_list:
                host_id_list.append(host)
    return host_id_list


def get_host_id_by_mac(mac, all_host_detail):
    for host, host_detail in all_host_detail.iteritems():
        eth_list = host_detail['ethinfo']
        for eth_info in eth_list:
            for this_mac in eth_info.keys():
                if this_mac == mac:
                    return host
    return None


def check_host_deploy(host_mode, host_list):
    hostname = fsinstall.get_host_name()
    if host_mode == utils.FS_DEPLOY_MODE_ONE:
        if len(host_list) == 0:
            host_list.append(hostname)
        if len(host_list) != 1:
            logger.error("host_list size is not 1")
            return False
    elif host_mode == utils.FS_DEPLOY_MODE_THREE:
        all_hosts = utils.get_all_hosts()
        if len(host_list) == 0:
            host_list.append(hostname)
            for host in all_hosts:
                if len(host_list) == 3:
                    break
                if host == hostname:
                    continue
                host_list.append(host)
        if len(host_list) != 3:
            logger.error("host_list size is not 3")
            return False
        for host in host_list:
            if not host in all_hosts:
                logger.error("host is not in allhosts %s %s" % (str(host), str(all_hosts)))
                return False
    elif host_mode == utils.FS_DEPLOY_MODE_TWO:
        all_hosts = utils.get_all_hosts()
        if len(host_list) < 3:
            if hostname not in host_list:
                host_list.append(hostname)
            for host in all_hosts:
                if len(host_list) == 3:
                    break
                if host == hostname:
                    continue
                if host not in host_list:
                    host_list.append(host)
        if len(host_list) != 3:
            logger.error("host_list size is not enough.")
            return False
        for host in host_list:
            if not host in all_hosts:
                logger.error("host is not in allhosts %s %s" % (str(host), str(all_hosts)))
                return False
    else:
        logger.error("mode is not right %s" % host_mode)
        return False
    return True


def input_config():
    while 1:
        filename_full = raw_input("Please input file full name :")

        if filename_full is None:
            continue
        if os.path.exists(filename_full):
            config = ConfigParser.RawConfigParser()
            config.read(filename_full)
            return config
        else:
            print "File:%s not exist." % filename_full
            logger.warning("File not exist.")
            continue


def input_file_name():
    while 1:
        filename = raw_input("Please input name")

        if filename is None or '/' in filename:
            continue
        filename_full = join(CURRENT_PATH, filename)
        if os.path.exists(filename_full):
            print "File name exist"
            while 1:
                input_str = raw_input("Do you want to overwrite it [y|n][n]")
                if input_str == '' or input_str == 'y' or input_str == 'n':
                    break
            if input_str == '' or input_str == 'n':
                continue
            if input_str == 'y':
                break
        else:
            break
    return filename

