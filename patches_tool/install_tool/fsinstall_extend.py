#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join
import sys
import json
import time
import copy
import traceback
import fsCpsCliOpt
from fs_disk_cfg import FSdiskOptConfig
import fs_log_util
import cps_server
import fs_system_server
import fsutils as utils
import fs_config
import fsinstall_base_func
import fs_network_util
import fs_modes
from print_msg import PrintMessage as PrintUtil

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)


class ExtendExec():
    def __init__(self):
        self.cpsServerUrl = cps_server.get_cpsserver_url()
        self.serviceEndpoints = {"cps": {"internalurl": self.cpsServerUrl}}
        self.network_cfg_mgr = fs_network_util.NetworkHostcfgMgr()

    def get_lst_control_host(self):
        return json.loads(fs_system_server.system_get_ctrl_hosts())

    def get_install_mode(self):
        return fs_system_server.system_get_host_mode()

    def get_local_az(self):
        return fs_system_server.system_get_local_az()

    def get_local_dc(self):
        return fs_system_server.system_get_local_dc()

    def get_keystone_az(self):
        return fs_system_server.system_get_keystone_az()

    def get_keystone_dc(self):
        return fs_system_server.system_get_keystone_dc()

    def get_glance_az(self):
        return fs_system_server.system_get_glance_az()

    def get_glance_dc(self):
        return fs_system_server.system_get_glance_dc()

    def reduce(self):
        try:
            while 1:
                lst_all_host, allhostsip = cps_server.get_all_hosts()
                ctrl_host = self.get_lst_control_host()
                reduce_list = list(set(lst_all_host) - set(ctrl_host))
                if reduce_list is None or len(reduce_list) == 0:
                    print "There is no compute host for reduce!"
                    return
                logger.info("lst_not_config_host:%s" % reduce_list)
                lst_print_info = fsinstall_base_func.get_host_print_info(reduce_list)
                if len(lst_print_info) == 0:
                    print "all hosts have been configured! exit"
                    return
                def_hostlist = ""
                utils.print_list(lst_print_info,
                                 ["host", "boardtype", "status", "manageip", "cpu", "memory", "disk", "nic"])
                inputstr = PrintUtil.get_msg(["please input hostid to reduce", "请输入要减少的hostid"]) \
                           + " [host1,host2][%s]" % def_hostlist
                hostlist = raw_input(inputstr)
                if (hostlist == ""):
                    hostlist = def_hostlist

                if hostlist == "":
                    print PrintUtil.get_msg(["please input correct host list", "请输入正确host列表"])
                    continue
                lst_host = hostlist.split(",")
                bRet = True
                for host in lst_host:
                    if not host in reduce_list:
                        logger.error("fail to checkExtendHost. lst_host:%s" % lst_host)
                        bRet = False
                        break
                if bRet:
                    break
                else:
                    continue
            for host in lst_host:
                self.reduce_host(host)

        except:
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())


    def reduce_host(self, host):
        pass

    def configInteractive(self):
        if not utils.is_finished():
            (this_mode, ctrl_hosts) = fs_modes.check_modes()
            if this_mode is None:
                PrintUtil.print_msg(["Please deploy first,then config", "请先部署服务再配置"])
                sys.exit(1)
            else:
                fs_config.init_files(this_mode, ctrl_hosts)
                return True
        while True:
            try:
                def_hostlist = ""
                lst_all_host, allhostsip = cps_server.get_all_hosts()
                logger.info("all hosts are %s" % lst_all_host)
                lst_not_config_host = list(set(lst_all_host) - set(self.get_lst_control_host()))
                logger.info("lst_not_config_host:%s" % lst_not_config_host)

                lst_print_info = fsinstall_base_func.get_host_print_info(lst_not_config_host)
                if len(lst_print_info) == 0:
                    print "all hosts have been configured!! exit"
                    return

                utils.print_list(lst_print_info,
                                 ["host", "boardtype", "status", "manageip", "cpu", "memory", "disk", "nic"])

                def_config_flag = "y"
                inputstr = PrintUtil.get_msg(["extend all hosts or not", "是否扩展所有的hosts"]) \
                           + " [y|n][%s]" % def_config_flag
                str_config_flag = raw_input(inputstr)
                if (str_config_flag == ""):
                    str_config_flag = def_config_flag

                if str_config_flag == "":
                    print PrintUtil.get_msg(["please input correct choice", "请输入正确的选择"])
                    continue

                if str_config_flag == "y":
                    lst_host = lst_not_config_host
                else:
                    inputstr = PrintUtil.get_msg(["please input hostid to extend", "请输入要扩展的hostid"]) \
                               + " [host1,host2][%s]" % def_hostlist
                    hostlist = raw_input(inputstr)
                    if (hostlist == ""):
                        hostlist = def_hostlist

                    if hostlist == "":
                        print PrintUtil.get_msg(["please input correct host list", "请输入正确host列表"])
                        continue

                    lst_host = hostlist.split(",")

                    host_is_correct = True
                    #需要进行 host id 合法性检查
                    for extHost in lst_host:
                        if extHost not in lst_all_host:
                            host_is_correct = False
                            print PrintUtil.get_msg(["please input correct host list", "请输入正确host列表"])
                            logger.error("input host is not correct. lst_host:%s" % lst_host)
                            break
                    if not host_is_correct:
                        continue

                bRet = self.checkExtendHost(lst_host)
                if not bRet:
                    logger.error("fail to checkExtendHost. lst_host:%s" % lst_host)
                    continue
                break
            except KeyboardInterrupt:
                logger.error("fail in configInteractive. trace:%s" % traceback.format_exc())
                raise KeyboardInterrupt()
            except:
                logger.error("fail in configInteractive. trace:%s" % traceback.format_exc())
                # 这个只有host 是由其他az的数据连过来的，导致 cps host-show $(hostname) 失败，需要检测环境
                sys.exit(1)
        isSuccessed = True
        try:
            bRet = self.configForNewHosts(lst_host)
            if not bRet:
                logger.error("fail to configForNewHosts, lst_host:%s" % lst_host)
                print "fail to add new host!"
                return False
        except KeyboardInterrupt:
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())
            raise KeyboardInterrupt()
        except:
            isSuccessed = False
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())

        if isSuccessed:
            print PrintUtil.get_msg(["extend host success", "扩展host成功"]) + " host list:%s" % lst_host
        return True

    def configForNewHosts(self, lst_host):
        #add host info
        logger.info("Enter in configForNewHosts. lst_host:%s" % lst_host)

        try:
            #check storage
            objDisk = FSdiskOptConfig()
            objDisk.extendHostConfig(lst_host)
            objDisk.validate("1", None)
        except KeyboardInterrupt:
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())
            raise KeyboardInterrupt()
        except:
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())
        try:
            #check network
            dct_host_network_info, isolate_host_list = fs_network_util.find_host_in_exist_hostcfg(lst_host)
            logger.info("find_host_in_exist_hostcfg, dct_host_network_info:%s, isolate_host_list:%s" % \
                        (dct_host_network_info, isolate_host_list))
            self.network_cfg_mgr.isolate_fix_hosts_proc(isolate_host_list)
            self.network_cfg_mgr.hostcfg_validate()
        except KeyboardInterrupt:
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())
            raise KeyboardInterrupt()
        except:
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())
        try:
            for hostid in dct_host_network_info.keys():
                bRet = fsCpsCliOpt.hostcfg_host_add([hostid],
                                                    "network",
                                                    dct_host_network_info[hostid]["name"],
                                                    self.cpsServerUrl)
                if not bRet:
                    logger.error("fail to hostcfg_host_add. hostid:%s" % hostid)
                    return False
        except KeyboardInterrupt:
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())
            raise KeyboardInterrupt()
        except:
            logger.error("fail in configForNewHosts. trace:%s" % traceback.format_exc())

        #add role
        self.assignHost2Role(lst_host)

        bRet = cps_server.cps_commit()
        if not bRet:
            logger.error("fail to cpsCommit")
            return False

        self.checkAlreadyOk(lst_host)

        return True

    def checkAlreadyOk(self, lst_host):
        logger.info("enter in checkAlreadyOk. lst_host:%s" % lst_host)
        time.sleep(5)
        max_try_time = 10
        try_time = 0
        while True:
            allhostok = True
            print "   "
            print "------start to check commit result.%s--------------------------------------------" % time.strftime(
                '%Y-%m-%d %H:%M:%S')
            for host in lst_host:
                instances = cps_server.get_host_template_status(host)
                if instances is None:
                    print "host = %s, system is busy, waiting for next check." % host
                    allhostok = False
                    continue

                installing_template = ''
                for instance in instances['instances']:
                    if instance['status'] != 'normal':
                        tempname = instance['template'].split('.')
                        if installing_template == '':
                            installing_template = tempname[1]
                        else:
                            installing_template = installing_template + " , " + tempname[1]
                        allhostok = False
                    else:
                        pass

                if installing_template == '':
                    print "host = %s, installed successfully." % host
                else:
                    print "host = %s, installing : %s." % (host, installing_template)
            host_mode = fs_system_server.system_get_host_mode()
            roles = fs_modes.get_mode_by_name(host_mode).get_agent_role()
            is_role_deployed = cps_server.is_roles_deployed(roles)
            if allhostok == True and is_role_deployed:
                print "------all hosts commit for templates are ok."
                return
            else:
                if try_time == max_try_time:
                    if not is_role_deployed:
                        print "------Warning:maybe some role in %s deployed failed.please check your hardware env!!!" % str(roles)
                    print "------checking timeout,please check by yourself."
                    break
                try_time = try_time + 1
                time.sleep(60)
                continue

    def getRoleInstallFlag(self, rolename):
        opt_role = {}
        if (self.get_local_az() == self.get_keystone_az() and self.get_local_dc() == self.get_keystone_dc()):
            opt_role['auth'] = 'true'
        else:
            opt_role['auth'] = 'false'

        if (self.get_local_az() == self.get_glance_az() and self.get_local_dc() == self.get_glance_dc()):
            opt_role['image'] = 'true'
        else:
            opt_role['image'] = 'false'

        for item in opt_role.iteritems():
            if item[0] == rolename:
                if item[1] == "true":
                    return True
                else:
                    return False

        return True

    def assignHost2Role(self, lst_host):
        logger.info("Enter in assignHost2Role:%s" % lst_host)
        lst_host_copy = copy.deepcopy(lst_host)
        agent_role = fs_modes.get_mode_by_name(self.get_install_mode()).get_agent_role()
        # assign agent role
        for item in agent_role:
            for host in lst_host_copy:
                if not cps_server.role_host_add(item, [host]):
                    logger.error("add %s role failed.host is :%s" % (str(item), str(host)))

        return True

    def checkExtendHost(self, lst_host):
        lst_ctrl_host = self.get_lst_control_host()
        for hostid in lst_host:
            if hostid in lst_ctrl_host:
                print "host %s is already configed, please retry" % hostid
                logger.warning("hostid:%s is control host" % hostid)
                return False
        return True


if __name__ == "__main__":
    obj = ExtendExec()
    obj.configInteractive()