#!/usr/bin/python
# coding:utf-8
"""
Command-line interface to deploy FusionSphere.
"""
import ConfigParser
import commands
import json
import os
import sys
import traceback
import fs_log_util
import cps_server
import fs_system_server
import fs_system_constant
import print_msg
from print_msg import PrintMessage as PrintUtil
import time
import fsutils as utils
from os.path import join
import fs_modes

import fs_component_update
import fs_common_installer

#***************section_map******************
SECTION_NAME = "name"
SECTION_INSTANCE = "instance"
SECTION_WORK_ITEMS = "work items"
deploy_role_host_dict = {}
deploy_router_mode = 'legacy'

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
#日志定义
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)


class FsConfigParser(ConfigParser.RawConfigParser):
    def write(self, fp):
        """Write an .ini-format representation of the configuration state."""
        if self._defaults:
            fp.write("[%s]\n" % "")
            for (key, value) in self._defaults.items():
                fp.write("%s = %s\n" % (key, str(value).replace('\n', '\n\t')))
            fp.write("\n")
        sections = sorted(self._sections)
        for section in sections:
            fp.write("[%s]\n" % section)
            for (key, value) in self._sections[section].items():
                if key == "__name__":
                    continue
                if (value is not None) or (self._optcre == self.OPTCRE):
                    key = " = ".join((key, str(value).replace('\n', '\n\t')))
                fp.write("%s\n" % (key))
            fp.write("\n")


def print_line():
    print "=============================================================================================================="


def print_welcome():
    print "=============================================welcome=========================================================="


def print_choose_notice():
    print "[y|n][n] :the input should be y or n, the default is n(just press Enter)."


def input_language():
    while 1:
        print_line()
        print "0) Engligh"
        print "1) Chinese"
        input_str = "please choose lanuage:[0|1][1]"
        lan = raw_input(input_str)
        if lan == "0":
            PrintUtil.set_language_mode(print_msg.LANGUAGE_EN)
        elif lan == "" or lan == "1":
            print "you should set code format to UTF-8 for Chinese"
            PrintUtil.set_language_mode(print_msg.LANGUAGE_CN)

        if lan == "0" or lan == "1" or lan == "":
            flag = 1
            while 1:
                print_line()
                PrintUtil.print_msg(["0)Continue", "0)继续"])
                PrintUtil.print_msg(["1)Cancle", "1)取消"])
                input_str = PrintUtil.get_msg(["You choose Engligh![0|1][1]", "您选择了中文！[0|1][1]"])
                flag = raw_input(input_str)
                if flag == "":
                    flag = "1"
                if flag == "1" or flag == "0":
                    break
                else:
                    PrintUtil.print_msg(
                        ["please choose correct character, support \"0\" or \"1\"", "输入非法，请输入\"0\"或者\"1\""])

            if flag == "0":
                break
        else:
            print "please choose correct character, support \"0\" or \"1\""

    if lan == "0":
        lan_mod = print_msg.LANGUAGE_EN
    else:
        lan_mod = print_msg.LANGUAGE_CN
    print_msg.PrintMessage.set_language_mode(lan_mod)


def run_command(cmd):
    try:
        (status, output) = commands.getstatusoutput(cmd)
        logger.info("run cmd :%s,status %s output %s" % (cmd, status, output))
        return status, output
    except Exception, e:
        logger.error(e)
    return 1, output


def show_all_hosts():
    print ""
    PrintUtil.print_msg_by_index('1000311')
    time.sleep(1)
    # host discovery ...
    try:
        # get all host name
        all_host_id = utils.get_all_hosts()
        if all_host_id is None:
            logger.error("get all hosts failed")
            sys.exit(1)

        lst_print = []
        for host in all_host_id:
            host_info = cps_server.get_host_detail_info(host)
            if host_info is None:
                PrintUtil.print_msg_by_index_ex('1000312', (host))
                sys.exit(1)

            board_type = host_info['boardtype']
            status = host_info['status']
            manage_ip = host_info['manageip']
            cpu_type = host_info['cputype']
            memory_size = host_info['memorysize']
            disk_info = host_info['diskinfo']
            eth_info = host_info['ethinfo']
            role_info = host_info['roleinfo']

            disk_num = len(disk_info)
            eth_num = len(eth_info)
            role_num = len(role_info)

            line = max(disk_num, eth_num, role_num)

            blank = ' '

            for current_line in range(line):
                if current_line < disk_num:
                    disk = disk_info[current_line]['dev'] + ',' + disk_info[current_line]['size']
                else:
                    disk = blank

                if current_line < eth_num:
                    mac = eth_info[current_line].keys()[0]
                    eth = mac + ',' + eth_info[current_line][mac]['speed']
                else:
                    eth = blank

                if current_line != 0:
                    current_host = blank
                    current_board_type = blank
                    current_status = blank
                    current_manage_ip = blank
                    current_cpu_type = blank
                    current_memory_size = blank
                else:
                    current_host = host
                    current_board_type = board_type
                    current_status = status
                    current_manage_ip = manage_ip
                    current_cpu_type = cpu_type
                    current_memory_size = memory_size

                dct_line = {"host": current_host,
                            "boardtype": current_board_type,
                            "status": current_status,
                            "manageip": current_manage_ip,
                            "cpu": current_cpu_type,
                            "memory": current_memory_size,
                            "disk": disk,
                            "nic": eth}
                lst_print.append(dct_line)
        utils.print_list(lst_print, ["host", "boardtype", "status", "manageip", "cpu", "memory", "disk", "nic"])
        return all_host_id
    except Exception as e:
        logger.debug(e, exc_info=1)
        logger.error("host discovery failed: %s" % str(traceback.format_exc()))
        sys.exit(1)


def get_host_name():
    cmd = "hostname"
    (status, output) = run_command(cmd)
    if status != 0:
        logger.error("hostname failed! curl:" + cmd + ' output=' + output)
        sys.exit(1)
    return output

def input_router_mode(message_id_str,default_router_mode):
    while 1:
        input_str = PrintUtil.get_msg_by_index_ex(message_id_str, default_router_mode)
        agent_mode_str = raw_input(input_str)
        agent_mode_str = agent_mode_str.strip()
        if agent_mode_str == '':
            agent_mode_str = default_router_mode
        agent_mode_flag = True
        if agent_mode_str not in ['legacy','dvr']:
            agent_mode_flag = False
        if agent_mode_flag:
            break
        PrintUtil.print_msg_by_index_ex('1000335',(agent_mode_str))
        continue
    return agent_mode_str

def update_neutron_router_agent_mode(router_agent_mode ,is_msg_print = True):
    params = {'agent_mode': router_agent_mode}
    if not cps_server.update_template_params('neutron', 'neutron-l3-agent', params):
        return False
    if is_msg_print:
        print "------------update_neutron_router_agent_mode success .%s" % time.strftime('%Y-%m-%d %H:%M:%S')
    return True

def update_neutron_enable_distributed_routing(enable_distributed_routing_value ,is_msg_print = True):
    params = {'enable_distributed_routing': enable_distributed_routing_value}
    if not cps_server.update_template_params('neutron', 'neutron-openvswitch-agent', params):
        return False
    if is_msg_print:
        print "------------update_neutron_enable_distributed_routing_value success .%s" % time.strftime('%Y-%m-%d %H:%M:%S')
    return True


def input_host_mode(hostname):
    flag = True
    def_host_mode = utils.FS_DEPLOY_MODE_THREE
    host_mode_tmp = def_host_mode
    while flag:
        flag = False
        keystone_domain = fs_system_server.input_keystone_domain()
        glance_domain = fs_system_server.input_glance_domain()
        while 1:
            try:
                all_host_id = show_all_hosts()
                host_num = len(all_host_id)
                number = int(fs_modes.get_mode_by_name(utils.FS_DEPLOY_MODE_THREE).get_control_number())
                if host_num > number:
                    def_deploy_mode = '2'
                else:
                    def_deploy_mode = '1'
                print "[1] %s" % utils.FS_DEPLOY_MODE_ONE
                print "[2] %s" % utils.FS_DEPLOY_MODE_THREE
                input_str = PrintUtil.get_msg_by_index_ex('1000313', def_deploy_mode)
                host_mode_tmp = raw_input(input_str)
                if host_mode_tmp == "":
                    host_mode_tmp = def_deploy_mode
                if host_mode_tmp == '1':
                    host_mode_tmp = utils.FS_DEPLOY_MODE_ONE
                    break
                elif host_mode_tmp == "2":
                    host_mode_tmp = utils.FS_DEPLOY_MODE_THREE
                    if host_num >= 3:
                        break
                    else:
                        print "There is only %s host(s) you can't choose %s."%(str(host_num), utils.FS_DEPLOY_MODE_THREE)
                        continue
                else:
                    PrintUtil.print_msg_by_index('1000315')
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                PrintUtil.print_msg_by_index('1000315')
                continue

        def_ctrl_hosts = ''
        host_list = [hostname]
        if host_mode_tmp == utils.FS_DEPLOY_MODE_ONE:
            ctrl_hosts = host_mode_tmp
            PrintUtil.print_msg_by_index_ex('1000316', (host_mode_tmp))
        elif host_mode_tmp == utils.FS_DEPLOY_MODE_THREE:
            PrintUtil.print_msg_by_index_ex('1000317', (host_mode_tmp))
            while 1:
                host_list = [hostname]
                try:
                    input_str = PrintUtil.get_msg_by_index_ex('1000318', def_ctrl_hosts)
                    ctrl_hosts = raw_input(input_str)
                    if ctrl_hosts == 'b' or ctrl_hosts == 'back':
                        flag = True
                        break
                    if ctrl_hosts == '':
                        ctrl_hosts = hostname
                        for host in all_host_id:
                            if len(host_list) == 3:
                                break
                            if host == hostname:
                                continue
                            else:
                                host_list.append(host)
                                ctrl_hosts = ctrl_hosts + ',' + host

                        break

                    host_list = split_str_to_list(ctrl_hosts)
                    if len(host_list) != 3:
                        PrintUtil.print_msg_by_index('1000319')
                        continue

                    error_host_list = []
                    host_flag = True
                    for host in host_list:
                        if host in all_host_id:
                            pass
                        else:
                            error_host_list.append(host)
                            host_flag = False

                    if not host_flag:
                        PrintUtil.print_msg_by_index_ex('1000320', (str(error_host_list)))
                        continue

                    if host_list[0] == host_list[1] or host_list[0] == host_list[2] or host_list[2] == host_list[1]:
                        PrintUtil.print_msg_by_index('1000321')
                        continue
                    if hostname in host_list:
                        break
                    else:
                        assert isinstance(hostname, object)
                        PrintUtil.print_msg_by_index_ex('1000322', hostname)
                        continue
                except KeyboardInterrupt:
                    sys.exit(1)
                except:
                    PrintUtil.print_msg_by_index('1000323')
                    continue
        default_router = ""
        if host_mode_tmp == utils.FS_DEPLOY_MODE_ONE:
            default_router = host_list[0]
        elif host_mode_tmp == utils.FS_DEPLOY_MODE_THREE:
            default_router = host_list[0] + "," + host_list[1]
        #提示客户输入router角色的部署列表
        router_list = input_host_list_by_message(all_host_id, '1000326', default_router)
        #提示客户输入router需要的agent_mode
        default_router_mode = 'legacy'
        router_mode = input_router_mode('1000334',default_router_mode)

        #提示客户输入lb角色的部署列表
        lb_list = input_host_list_by_message(all_host_id, '1000327', '')
        #提示客户输入cinder使用的方式

        while 1:
            default_cinder_type = 'file'
            right_list = [fs_system_constant.CINDER_TYPE_FILE, fs_system_constant.CINDER_TYPE_FUSION_STORAGE, fs_system_constant.CINDER_TYPE_IPSAN]
            input_str = PrintUtil.get_msg_by_index_ex('1000329', default_cinder_type)
            cinder_type = raw_input(input_str)
            cinder_type = cinder_type.strip()
            if cinder_type == '':
                cinder_type = default_cinder_type
            if cinder_type in right_list:
                break
        if cinder_type == fs_system_constant.CINDER_TYPE_FUSION_STORAGE:
            bs_list = all_host_id
        else:
            bs_list = []

        if host_mode_tmp == utils.FS_DEPLOY_MODE_ONE:
            #提示客户输入blockstorage-driver角色的部署列表
            bs_driver_list = input_host_list_by_message(all_host_id, '1000328', hostname)
        else:
            #提示客户输入blockstorage-driver角色的部署列表
            bs_driver_list = input_host_list_by_message(all_host_id, '1000328', ctrl_hosts)


        print_line()
        PrintUtil.print_msg_by_index('1000324')
        PrintUtil.print_msg_by_index_ex('1000325', host_mode_tmp)
        PrintUtil.print_msg_by_index_ex('1000306', host_list)
        PrintUtil.print_msg_by_index_ex('1000330', router_list)
        PrintUtil.print_msg_by_index_ex('1000336', router_mode)
        PrintUtil.print_msg_by_index_ex('1000331', lb_list)
        PrintUtil.print_msg_by_index_ex('1000333', cinder_type)
        PrintUtil.print_msg_by_index_ex('1000332', bs_driver_list)
        PrintUtil.print_msg_by_index_ex('1000307', glance_domain)
        PrintUtil.print_msg_by_index_ex('1000308', keystone_domain)
        while 1:
            input_str = PrintUtil.get_msg(["Are you sure? [y|n][y]", "确认吗？[y|n][y]"])
            input_flag = raw_input(input_str)
            if input_flag == 'y' or input_flag == '':
                break
            elif input_flag == 'n':
                flag = True
                break
            else:
                PrintUtil.print_msg(["Please input [y|n][y]", "请输入y或者n"])
                continue

    return host_mode_tmp, ctrl_hosts, host_list, keystone_domain, glance_domain, router_list,router_mode, lb_list, bs_list, bs_driver_list


def input_host_list_by_message(all_host_id, message_id_str, default_value):
    while 1:
        input_str = PrintUtil.get_msg_by_index_ex(message_id_str, default_value)
        role_str = raw_input(input_str)
        role_str = role_str.strip()
        if role_str == '':
            role_str = default_value
        role_list = split_str_to_list(role_str)
        error_host_list = []
        host_flag = True
        for host in role_list:
            if host in all_host_id:
                pass
            else:
                error_host_list.append(host)
                host_flag = False
        if host_flag:
            break
        PrintUtil.print_msg_by_index_ex('1000320', (str(error_host_list)))
        continue
    return role_list


def input_deploy_mode():
    while 1:
        print "=============================================================================================================="
        PrintUtil.print_msg(["1)fast deploy", "1)快速部署"])
        PrintUtil.print_msg(["2)custom deploy", "2)自定义部署"])
        PrintUtil.print_msg(["3)change config", "3)修改配置"])
        PrintUtil.print_msg(["4)cancel", "4)取消"])
        input_str = PrintUtil.get_msg(["please choose mode [1|2|3|4][1]", "请选择部署模式[1|2|3|4][1]"])
        mode = raw_input(input_str)
        if mode == "":
            mode = "1"
            break
        elif mode == "1" or mode == "2":
            if is_deployed():
                PrintUtil.print_msg(
                    ["System has been deployed!you can config you system now", "您的系统已经部署,您现在可以进行修改配置操作"])
                continue
            else:
                break
        elif mode == "3":
            break
        elif mode == "4":
            input_str = PrintUtil.get_msg(["Are you sure quit?[y|n][n]", "确定退出吗？[y|n][n]"])
            flag = raw_input(input_str)
            if flag == 'y':
                sys.exit(1)
            else:
                continue
        elif mode == "config" or mode == "fastdeploy":
            break
        else:
            PrintUtil.print_msg(["Please input correct character, only support \'1\' or \'2\' or \'3\' or \'4\'! ",
                                 "非法输入，合法输入支持\'1\' or \'2\' or \'3\' or \'4\'!"])
    return mode


def split_str_to_list(input_str):
    ret_list = []
    ret_list_tmp = input_str.split(',')
    for str_tmp in ret_list_tmp:
        if str_tmp == "":
            continue
        ret_list.append(str_tmp.strip())
    return ret_list


def save_deploy_msg(host_mode_tmp, ctrl_host_list, keystone_domain, glance_domain):
    cmd = "rm " + utils.DEFAULT_FILE_NAME
    run_command(cmd)
    config = FsConfigParser()

    config.add_section(utils.SECTION_ROLE_DEPLOY)
    config.set(utils.SECTION_ROLE_DEPLOY, 'host_mode', host_mode_tmp)
    config.set(utils.SECTION_ROLE_DEPLOY, 'ctrl_hosts', json.dumps(ctrl_host_list))

    config.add_section(utils.SECTION_SYS_CONFIG)
    config.set(fs_system_constant.SECTION_SYS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_KEYSTONE_DOMAIN,
               keystone_domain)
    config.set(fs_system_constant.SECTION_SYS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_GLANCE_DOMAIN,
               glance_domain)

    with open(utils.DEFAULT_FILE_NAME, 'w') as fd:
        config.write(fd)
    time.sleep(5)
    deploy_all_sections(config)


def deploy_all_sections(config):
    for k, v in utils.get_section_map().iteritems():
        processor = v[SECTION_INSTANCE]
        if processor is not None:
            try:
                processor.create_def_config(config)
            except Exception, e:
                logger.error("Choose_section failed: k=%s, e= %s, e=%s." % (k,traceback.format_exc(),e))


def update_all_sections():
    for k, v in utils.get_section_map().iteritems():
        processor = v[SECTION_INSTANCE]
        if processor is not None:
            try:
                processor.update_params()
            except AttributeError:
                logger.error("k = %s ." %k)
                continue


def get_computer_hosts(all_host_id, host_list):
    computer_hosts = []
    for host in all_host_id:
        if host in host_list:
            pass
        else:
            computer_hosts.append(host)
    return computer_hosts


def role_deploy():
    #需要判断配置文件中是否保留有上次的配置数据，如果有则不需要用户再次输入
    logger.debug("come in role_deploy")
    hostname = get_host_name()
    while 1:
        local_dc, local_az, local_domain = input_local_domain()
        PrintUtil.print_msg_by_index('1000324')
        print "local dc : %s" % local_dc
        print "local az : %s" % local_az
        print "domain postfix : %s" % local_domain
        if input_is_sure():
            break
        else:
            continue

    cps_server.set_local_domain(local_dc, local_az, local_domain)
    cps_server.cps_commit()
    host_mode, ctrl_hosts, host_list, keystone_domain, glance_domain, router_list,router_mode, lb_list, bs_list, bs_driver_list = input_host_mode(
        hostname)
    set_deploy_role_host(router_list, lb_list, bs_list, bs_driver_list)
    set_router_mode(router_mode)
    save_deploy_msg(host_mode, host_list, keystone_domain, glance_domain)
    print 'Start deploy'
    logger.info("success role_deploy ctrl_hosts = %s" %ctrl_hosts)

def set_router_mode(router_mode):
    global deploy_router_mode
    deploy_router_mode = router_mode

def set_deploy_role_host(router_list, lb_list, bs_list, bs_driver_list):
    global deploy_role_host_dict
    deploy_role_host_dict["router"] = router_list
    deploy_role_host_dict["dhcp"] = router_list
    deploy_role_host_dict['loadbalancer'] = lb_list
    deploy_role_host_dict['blockstorage'] = bs_list
    deploy_role_host_dict['blockstorage-driver'] = bs_driver_list


def input_is_sure():
    while 1:
        input_str = raw_input(PrintUtil.get_msg(["Are you sure? [y|n][y]", "确认吗？[y|n][y]"]))
        if input_str == "" or input_str == 'y':
            return True
        if input_str == 'n':
            return False
        continue


def input_local_domain():
    while 1:
        input_str = raw_input("Please set local dc name: [dc1]")
        dc_name = input_str.strip()
        if dc_name == '':
            dc_name = 'dc1'
        if utils.is_simple_str(dc_name):
            break
        print "Dc name should be composed by numbers , letters , '-'"
    while 1:
        input_str = raw_input("Please set local az name: [az1]")
        az_name = input_str.strip()
        if az_name == '':
            az_name = 'az1'
        if utils.is_simple_str(az_name):
            break
        print "Az name should be composed by numbers , letters , '-'"
    while 1:
        input_str = raw_input("Please set local domain postfix: [domainname.com]")
        domain_postfix = input_str.strip()
        if domain_postfix == '':
            domain_postfix = 'domainname.com'
        if utils.is_domain_postfix_str(domain_postfix):
            break
        print "domain postfix should be composed by numbers , letters , '-', '.'"
    return dc_name, az_name, domain_postfix


def is_deployed():
    if os.path.exists(utils.DEFAULT_FILE_NAME):
        config = FsConfigParser()
        config.read(utils.DEFAULT_FILE_NAME)
        section_list = config.sections()
        for item in section_list:
            if item.find(utils.SECTION_ROLE_DEPLOY) is not -1:
                role_deploy_dict = dict(config.items(item))
                if role_deploy_dict.has_key('is_deployed'):
                    str_is_deployed = role_deploy_dict.get('is_deployed')
                    return str_is_deployed == 'YES'
    return False


def set_deployed():
    config = FsConfigParser()
    config.read(utils.DEFAULT_FILE_NAME)
    config.set(utils.SECTION_ROLE_DEPLOY, 'is_deployed', 'YES')
    with open(utils.DEFAULT_FILE_NAME, 'w') as fd:
        config.write(fd)


def check_config():
    if not os.path.exists(utils.DEFAULT_FILE_NAME):
        PrintUtil.print_msg(["Please deploy first,then config", "请先部署服务再配置"])
        sys.exit(1)

def create_virsh_machine_flag():
    """
    create virsh machine flag
    """
    virsh_flag = {'instance_console_log': 'true', 'nic_suspension': 'true', 'instance_memory_qos': 'true',
                  'instance_vwatchdog': 'true'}
    if not cps_server.update_template_params("nova", "nova-compute", virsh_flag):
        print "create virsh machine flag failed. flag : %s" % virsh_flag
        logger.error("create virsh machine flag failed. flag : %s" % virsh_flag)
        return False
    logger.info("create virsh machine flag success. flag : %s" % virsh_flag)
    cps_server.cps_commit()
    return True


def print_params_update_success_info():
    """
    对更新组件的keystone和glance相关参数进行整改后，
    为了保持原有的信息打印一致，特意加上
    """
    old_modules = ["expiration", "auth_host", "auth_port", "auth_protocol",
                   "auth_url", "default_availability_zone", "nova_url",
                   "cinder_url", "neutron_url", "glance_host", "glance_store",
                   "glance_port"]
    for info in old_modules:
        str_print = "------------update_%s_match_config success .%s" \
                    % (info, time.strftime('%Y-%m-%d %H:%M:%S'))
        print str_print
        time.sleep(1)

def update_templates_params_on_deploy(config):
    """
    部署阶段，更新组件的参数
    新添加函数，整改各组件的keystone和glance相关参数更新部分
    """
    if not fs_component_update.update_component_cfg(config):
        return False
    #为了适配原有的print信息，需要加入print
    print_params_update_success_info()

    update_all_sections()

    if deploy_router_mode == 'dvr':
        if not update_neutron_router_agent_mode('dvr_snat'):
            return False
        if not update_neutron_enable_distributed_routing('True'):
            return False
    return True

def update_templates_params_on_config(config):
    """
    配置阶段，根据配置更新组件的参数
    新添加函数，整改各组件的keystone和glance相关参数更新部分
    """
    if not fs_component_update.update_component_cfg(config):
        return False

    update_all_sections()
    return True

def update_all_template_params(config, is_keystone_update=True, is_glance_update=True):
    try:
        print "   "
        print "------update Templates Params .%s" % time.strftime('%Y-%m-%d %H:%M:%S')
        #更新所有组件参数信息
        if not update_templates_params_on_deploy(config):
            print "------update Templates Params failed,for detailed info,please refer fsinstall.log!%s" % time.strftime(
                '%Y-%m-%d %H:%M:%S')
            sys.exit(1)
        print "------update Templates Params successfully!%s" % time.strftime('%Y-%m-%d %H:%M:%S')
    except:
        logger.error(traceback.format_exc())


def update_component_cfg(is_keystone_update, is_glance_update):
    config = ConfigParser.RawConfigParser()
    config.read(utils.DEFAULT_FILE_NAME)
    try:
        #更新所有组件参数信息
        if not update_templates_params_on_config(config):
            logger.error("update Templates Params failed,for detailed info,please refer fsinstall.log!%s" % time.strftime(
                '%Y-%m-%d %H:%M:%S'))
            sys.exit(1)
        return True 
    except:
        logger.error(traceback.format_exc())
        return False

def _set_lite_mod_config():
        """
        _set_lite_mod_config ceilometer mongodb
        """
        params = {"deploy_mode" : "active-standby"}
        ret = cps_server.update_template_params("mongodb", "mongodb", params)
        if not ret:
            logger.error("update_template_params mongodb mongodb failed. params : %s" % params)
            return False

        for item in ["ceilometer-api", "ceilometer-collector", "ceilometer-alarm-fault"]:
            ret = cps_server.update_template_params("ceilometer", item, params)
            if not ret:
                logger.error("update_template_params ceilometer %s failed. params : %s" % (item, params))
                return False

        body = {'hamode': "active-standby"}
        url = "/cps/v1/services/%s/componenttemplates/%s" % ("mongodb", "mongodb")
        ret = cps_server.post_cps_http(url, body)
        if not ret:
            logger.error("update componenttemplates mongodb mongodb failed. body : %s" % body)
            return False
        return True


def install_all_roles(config):
    installmode = config.get(utils.SECTION_ROLE_DEPLOY, 'host_mode')
    local_dc = fs_system_server.system_get_local_dc()
    local_az = fs_system_server.system_get_local_az()
    glance_dc = fs_system_server.system_get_glance_dc()
    glance_az = fs_system_server.system_get_glance_az()
    keystone_dc = fs_system_server.system_get_keystone_dc()
    keystone_az = fs_system_server.system_get_keystone_az()
    image_flag = (local_dc == glance_dc and local_az == glance_az)
    auth_flag = (local_dc == keystone_dc and local_az == keystone_az)

    templates = cps_server.get_template_list()
    if templates is None:
        return False

    if installmode == utils.FS_DEPLOY_MODE_ONE:
        for template in templates['templates']:
            service_name = template['service']
            template_name = template['name']

            if template_name == 'glance' and not image_flag:
                continue

            if template_name == 'keystone' and not auth_flag:
                continue

            special_template_dict = fs_modes.get_mode_by_name(installmode).get_special_template()
            for key, value in special_template_dict:
                if template_name == key:
                    if not cps_server.update_temp_ins_num(service_name, template_name, value):
                        return False
                    continue

            template_info = cps_server.get_template_info(service_name, template_name)
            if template_info is None:
                return False

            #nova-util active-active mode,but default insnum is -1 !!!!
            if template_info['hamode'] != 'single' and template_info['insnum'] != '1' and template_info[
                'insnum'] != '-1':
                if not cps_server.update_temp_ins_num(service_name, template_name, '1'):
                    return False
    elif installmode == utils.FS_DEPLOY_MODE_THREE:
        logger.info("start 3")
        for template in templates['templates']:
            service_name = template['service']
            template_name = template['name']

            if template_name == 'glance' and not image_flag:
                continue

            if template_name == 'keystone' and not image_flag:
                continue

            special_template_dict = fs_modes.get_mode_by_name(installmode).get_special_template()
            logger.info("special_template_dict is :%s" % str(special_template_dict))

            if template_name in special_template_dict:
                if not cps_server.update_temp_ins_num(service_name, template_name,
                                                      special_template_dict[template_name]):
                    return False
                continue

            template_info = cps_server.get_template_info(service_name, template_name)
            if template_info is None:
                return False

            # dns-server still not support multi instances
            if template_name == 'dns-server':
                continue

            if (template_info['hamode'] == 'active-active' and template_info['insnum'] != '3' and template_info[
                'insnum'] != '-1'):
                if not cps_server.update_temp_ins_num(service_name, template_name, '3'):
                    return False
    elif installmode == utils.FS_DEPLOY_MODE_TWO:
        logger.info("start 2Controllers")

        if not _set_lite_mod_config():
            logger.error("_set_lite_mod_config failed!")
            return False

        for template in templates['templates']:
            service_name = template['service']
            template_name = template['name']

            if template_name == 'glance' and not image_flag:
                continue

            if template_name == 'keystone' and not image_flag:
                continue

            special_template_dict = fs_modes.get_mode_by_name(installmode).get_special_template()
            logger.info("special_template_dict is :%s" % str(special_template_dict))

            if template_name in special_template_dict:
                if not cps_server.update_temp_ins_num(service_name, template_name,
                                                      special_template_dict[template_name]):
                    return False
                continue

            template_info = cps_server.get_template_info(service_name, template_name)
            if template_info is None:
                return False

            # dns-server still not support multi instances
            if template_name == 'dns-server':
                continue

            if (template_info['insnum'] != '2' and template_info['insnum'] != '-1'):
                if not cps_server.update_temp_ins_num(service_name, template_name, '2'):
                    return False
    return True


def assign_host_2_role_balance(role_name, inst_num, hosts_lst, lst_index):
    """
        返回值，为下一个均衡部署角色所布的hosts_lst的index
        比如3controller的 roleA:host0,host1; roleB:host2:host0; roleC:host1,host2
        比如5controller的 roleA:host0,host1; roleB:host2:host3; roleC:host4,host0

        database 首节点already deployed on this role!
    """
    hosts_deploy_lst = []
    lst_len = len(hosts_lst)
    for i in range(inst_num):
        item = hosts_lst[(lst_index + i) % lst_len]
        if item not in hosts_deploy_lst:
            hosts_deploy_lst.append(item)

    if not cps_server.role_host_add(role_name, hosts_deploy_lst):
        logger.error("add auth role failed")
    next_index = (lst_index + inst_num) % lst_len
    return next_index


def assign_host_2_role(config):
    local_dc = fs_system_server.system_get_local_dc()
    local_az = fs_system_server.system_get_local_az()
    glance_dc = fs_system_server.system_get_glance_dc()
    glance_az = fs_system_server.system_get_glance_az()
    keystone_dc = fs_system_server.system_get_keystone_dc()
    keystone_az = fs_system_server.system_get_keystone_az()
    deploy_mode = config.get(utils.SECTION_ROLE_DEPLOY, 'host_mode')

    manage_role = fs_modes.get_mode_by_name(deploy_mode).get_manage_role()
    balance_role = fs_modes.get_mode_by_name(deploy_mode).get_balance_role()
    agent_role = fs_modes.get_mode_by_name(deploy_mode).get_agent_role()
    control_number = int(fs_modes.get_mode_by_name(deploy_mode).get_control_number())

    ctrl_hosts = json.loads(config.get(utils.SECTION_ROLE_DEPLOY, 'ctrl_hosts'))
    controller_host = ctrl_hosts[0:control_number]

    #用户选择的controller节点必须部署的角色
    necessary_role = fs_modes.get_mode_by_name(deploy_mode).get_necessary_role()
    for item in necessary_role:
        item = str(item)
        for host in ctrl_hosts:
            if not cps_server.role_host_add(item, [host]):
                logger.error("add %s role failed" % str(item))

    allhosts = utils.get_all_hosts()
    if local_dc == keystone_dc and local_az == keystone_az:
        for host in controller_host:
            if not cps_server.role_host_add('auth', [host]):
                logger.error("add auth role failed")
    if local_dc == glance_dc and local_az == glance_az:
        for host in controller_host:
            if not cps_server.role_host_add('image', [host]):
                logger.error("add image role failed")

    # assign manage role
    for item in manage_role:
        item = str(item)
        for host in controller_host:
            if not cps_server.role_host_add(item, [host]):
                logger.error("add %s role failed" % str(item))

    # assign balance role (当前database（gaussdb） mongodb rabbitmq三个都是主备部署的)
    role_host = cps_server.get_all_role_hosts("database")
    if 1 == len(role_host):
        index_lst = controller_host.index(role_host[0]) + 1
        database_inst = 1
    else:
        index_lst = 0
        database_inst = 2
    for item in balance_role:
        item = str(item)
        if "database" == item:
            index_lst = assign_host_2_role_balance(item, database_inst, controller_host, index_lst)
        else:
            index_lst = assign_host_2_role_balance(item, 2, controller_host, index_lst)

    # assign agent role
    for item in agent_role:
        item = str(item)
        for host in allhosts:
            if not cps_server.role_host_add(item, [host]):
                logger.error("add %s role failed" % str(item))

    router_deploy_list = []

    for role_name, deploy_list in deploy_role_host_dict.iteritems():
        for host in deploy_list:
            if role_name == 'router':
                router_deploy_list = deploy_list
            if not cps_server.role_host_add(role_name, [host]):
                logger.error("add %s role failed" % str(role_name))

    if deploy_router_mode == 'dvr':
        for host in list(set(allhosts) - set(router_deploy_list)):
            if not cps_server.role_host_add('dvr-compute', [host]):
                logger.error("add dvr-compute role failed")

    #新的组件部署入口
    fs_common_installer.NewRoleInstaller.deploy_role_2_host()
	
    return True


def get_host_deploy_role_info():
    #获取当前单板已经部署的角色信息
    host_deploy_role = {}

    result = cps_server.cps_host_list()
    if not result:
        logger.info("get cps host-list failed.")
        return None
    hosts_info = result.get("hosts", [])
    for host_item in hosts_info:
        host_id = host_item.get("id", "")
        roles = host_item.get("roles", [])
        host_deploy_role[host_id] = roles

    return host_deploy_role

def is_all_role_apply_to_host(host_roles, config_role):
    for role in config_role:
        if role not in host_roles:
            return False
    return True

def check_temp_install_commit():
    all_hosts = utils.get_all_hosts()
    #已配置的 哪些单板部署了 哪些角色的信息
    host_config_role = cps_server.get_host_role_dict_info()
    logger.info("host_config_role=%s."%host_config_role)

    # wait for commit ok
    time.sleep(5)
    number = 0
    while 1:
        number += 1
        all_host_ok = True
        print "   "
        print "------start to check commit result.%s--------------------------------------------" % time.strftime(
            '%Y-%m-%d %H:%M:%S')
        if number > 30:
            print "Detection timeout.Abnormal one or more components"
            return

        host_deploy_role = get_host_deploy_role_info()
        if not host_deploy_role:
            print "system is busy, waiting for next check."
            time.sleep(10)
            logger.info("system is busy, waiting for next check.")
            continue

        for host in all_hosts:
            config_role = host_config_role.get(host, [])
            deploy_role = host_deploy_role.get(host, [])

            if not is_all_role_apply_to_host(deploy_role, config_role):
                all_host_ok = False
                print "host = %s, installing roles." % (host)
                continue

            instances = cps_server.get_host_template_status(host)
            if instances is None:
                print "host = %s, system is busy, waiting for next check." % host
                all_host_ok = False
                continue

            installing_template = ''
            for instance in instances['instances']:
                if instance['status'] != 'normal':
                    temp_name = instance['template'].split('.')
                    if installing_template == '':
                        installing_template = temp_name[1]
                    else:
                        installing_template = installing_template + " , " + temp_name[1]
                    all_host_ok = False
                else:
                    pass

            if installing_template == '':
                print "host = %s, installed successfully." % host
            else:
                print "host = %s, installing : %s." % (host, installing_template)
                if number > 30:
                    print "Detection timeout.Abnormal one or more components"
                    return

        if all_host_ok:
            print "------all hosts commit for templates are ok."
            return
        else:
            time.sleep(10)
            continue

def check_softrepo_to_swift():
    sys.path.append("/usr/bin/cps_base")
    cps_const = __import__("cpsconstant")

    init_file = ConfigParser.RawConfigParser()
    init_file.read(cps_const.CPSConstant.INIT_FILE)

    if init_file.has_option(cps_const.CPSConstant.INIT_SEC_INIT,
                            cps_const.CPSConstant.INIT_KEY_INSTALLMODE):
        install_mode = init_file.get(cps_const.CPSConstant.INIT_SEC_INIT,
                                    cps_const.CPSConstant.INIT_KEY_INSTALLMODE)
    elif init_file.has_option(cps_const.CPSConstant.INIT_SEC_INIT,
                            cps_const.CPSConstant.INIT_KEY_INSTALLMODE_EXTERN):
        install_mode = init_file.get(cps_const.CPSConstant.INIT_SEC_INIT,
                            cps_const.CPSConstant.INIT_KEY_INSTALLMODE_EXTERN)
    if not install_mode:
        logger.info("this node is not firstNode, not wait softrepo "
                    "switch to swift")
        return True
    else:
        return (cps_const.CPSConstant.INSTALLMODE_VALUE_CONTROL==install_mode)

def check_clusters(config):
    install_mode = config.get(utils.SECTION_ROLE_DEPLOY, 'host_mode')
    if install_mode == utils.FS_DEPLOY_MODE_ONE:
        return
    if install_mode == utils.FS_DEPLOY_MODE_THREE \
        or install_mode == utils.FS_DEPLOY_MODE_TWO:
        print "   "
        logger.info("start to wait until softrepo switch to swift")
        wait_time_str = os.getenv(fs_system_constant.PREINSTALL_WAIT_TIME_ENV,
                                  "3000")
        wait_time = int(wait_time_str)
        retry_time = 0
        while retry_time < wait_time and not check_softrepo_to_swift():
            time.sleep(5)
            retry_time = retry_time + 5
        if retry_time >= wait_time:
            logger.info("softrepo switch to swift cluster, not OK,time is out")
        else:
            logger.info("softrepo switch to swift cluster, OK!")

        print 'In cluster switch, please wait about 3 minutes'
        time.sleep(180)
        print 'Cluster switch successfully'


def validate():
    logger.debug("come in validate")
    #1)部署前准备
    create_virsh_machine_flag()
    config = ConfigParser.RawConfigParser()
    config.read(utils.DEFAULT_FILE_NAME)
    #2)更新组件参数
    update_all_template_params(config)
    #3)开始部署
    print "   "
    print "------start deploy roles .%s" % time.strftime('%Y-%m-%d %H:%M:%S')
    logger.info("start deploy roles.")
    try:
        result_install_all_roles = install_all_roles(config)
        if not result_install_all_roles:
            logger.error("install all roles fail")
    except:
        logger.error("install roles raise exception")
        logger.error("install_all_roles : %s" % traceback.format_exc())
    assign_host_2_role(config)
    if not cps_server.cps_commit():
        print "run cps commit failed!"
        logger.error("run cps commit failed while deploy")
        sys.exit(1)
    print "------install and run cps commit successfully! now we will check the commit result! "

    print "   "
    print "------All roles has been deployed.%s" % time.strftime('%Y-%m-%d %H:%M:%S')
    logger.info("All roles has been deployed.")
    #4)检查部署情况
    check_temp_install_commit()

    check_clusters(config)

    utils.set_finish_flag()
    print ""
    print "Deploy finished!"
    logger.info("finish validate")


def start():
    logger.debug("come in fsintall")
    #1)部署完成后不允许再次部署
    (this_mode, ctrl_hosts) = fs_modes.check_modes()
    if not this_mode is None:
        PrintUtil.print_msg_by_index('1000301')
        sys.exit(1)
    logger.info("come in fsintall ctrl_hosts = %s"%ctrl_hosts)
    print_welcome()

    #2)用户交互界面，输入部署的必需参数
    role_deploy()

    #3)生效
    validate()


def main():
    try:
        start()
    except Exception as e:
        PrintUtil.get_msg(["HELP! I am in  trouble.please rerun me or connect HUAWEI FSP support staff!",
                           "哎呀，一键部署配置脚本挂掉了，请尝试重新运行或者联系华为 FSP支持人员处理"])
        logger.debug(e, exc_info=1)


if __name__ == "__main__":
    sys.exit(main())
