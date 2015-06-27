#!/usr/bin/env python
#-*-coding:utf-8-*-
import sys
import commands
import os
import json
import traceback
import copy
import fs_log_util
import cps_server
import fsutils as utils
from os.path import join
from fsinstall_base import Constant
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)

def split_str_to_list(input):
    ret_list = []
    ret_list_tmp = input.split(',')
    for str_tmp in  ret_list_tmp:
        ret_list.append(str_tmp.strip())
    return ret_list

def runCommand(cmd):
    try:
        (status, output) = commands.getstatusoutput(cmd)
        logger.info("run cmd :%s,status %s output %s" % (cmd, status, output))
        return status, output
    except Exception, e:
        logger.error(e)
    return 1, output

def get_host_print_info(lst_host):
    lst_print = []
    cps_url = cps_server.get_cpsserver_url()
    for host in lst_host:
        hostinfo = getHostDetailInfo(cps_url, host)
        if hostinfo == None:
            str_msg = "host discovery failed,host = %s." % host
            logger.error(str_msg)
            print str_msg
            raise Exception("fail to get_host_print_info")

        boardtype = hostinfo['boardtype']
        status = hostinfo['status']
        manageip = hostinfo['manageip']
        cputype = hostinfo['cputype']
        cpucorecount = hostinfo['cpucorecount']
        memorysize = hostinfo['memorysize']
        diskinfo = hostinfo['diskinfo']
        ethinfo = hostinfo['ethinfo']
        roleinfo = hostinfo['roleinfo']

        disknum = len(diskinfo)
        ethnum = len(ethinfo)
        rolenum = len(roleinfo)

        line = max(disknum, ethnum, rolenum)

        blank = ' '

        for current_line in range(line):
            if current_line < disknum :
                disk = diskinfo[current_line]['dev'] + ',' + diskinfo[current_line]['size']
            else:
                disk = blank

            if current_line < ethnum :
                mac = ethinfo[current_line].keys()[0]
                eth = mac + ',' + ethinfo[current_line][mac]['speed']
            else:
                eth = blank

            if current_line != 0:
                current_host = blank
                current_boardtype = blank
                current_status = blank
                current_manageip = blank
                current_cputype = blank
                current_memorysize = blank
            else:
                current_host = host
                current_boardtype = boardtype
                current_status = status
                current_manageip = manageip
                current_cputype = cputype
                current_memorysize = memorysize

            dctLine = {"host":current_host,
                       "boardtype":current_boardtype,
                       "status":current_status,
                       "manageip":current_manageip,
                       "cpu":current_cputype,
                       "memory":current_memorysize,
                       "disk":disk,
                       "nic":eth}
            lst_print.append(dctLine)
    return lst_print


def getAllHostsInfo(cpsServerUrl):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hosts" % cpsServerUrl
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None, None

        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))

        result = json.loads(res.text)
        return result
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None, None

def get_all_hwtype(dct_host_info):
    lst_hwtype = []
    if not dct_host_info.has_key('hosts'):
        logger.error("__get_all_hwtype failed. dct_host_info do not has hosts")
        return False

    for item in dct_host_info['hosts']:
        lst_hwtype.append(item['boardtype'])

    return lst_hwtype

def get_hwtypes_by_hosts(lst_hosts):
    cpsServerUrl = cps_server.get_cpsserver_url()
    dct_host_info = getAllHostsInfo(cpsServerUrl)
    lst_hwtypes = []
    for item in dct_host_info['hosts']:
        if item['id'] in lst_hosts:
            if item['boardtype'] not in lst_hwtypes:
                lst_hwtypes.append(item['boardtype'])
    return lst_hwtypes

def generate_network_groups(cpsServerUrl, lst_allhostid, start_num = 1):
    dct_host_eth = {}
    for str_hostid in lst_allhostid:
        dctHostInfo = getHostDetailInfo(cpsServerUrl, str_hostid)
        lst_ethinfo = dctHostInfo['ethinfo']
        lst_pci = []
        for dct_eth in lst_ethinfo:
            str_mac = dct_eth.keys()[0]
            str_port_info = "%s=%s" % (dct_eth[str_mac]["pci"], dct_eth[str_mac]["speed"])
            lst_pci.append(str_port_info)
        dct_host_eth[str_hostid] = lst_pci

    logger.info("[generate_network_groups] dct_host_eth:%s" % dct_host_eth)

    dct_groups = {}
    for str_hostid in dct_host_eth:
        add_host_to_groups(dct_groups, dct_host_eth[str_hostid], str_hostid, start_num)

    return dct_groups

def add_host_to_groups(dct_groups, lst_pci, host, start_num):
    bFlag = False
    for item in dct_groups:
        if set(dct_groups[item]["pcis"]) == set(lst_pci):
            dct_groups[item]["hosts"].append(host)
            bFlag = True

    if not bFlag:
        if len(dct_groups.keys()) == 0:
            index = start_num
        else:
            index = max(dct_groups.keys()) + 1
        dct_groups[index] = {"pcis":lst_pci, "hosts":[host]}

def getHostDetailInfo(cpsUrl, host):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hosts/%s" % (cpsUrl, host)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None

        return json.loads(res.text)
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None

def getRoleInstallFlag(rolename, fsconfig):
    opt_role = fsconfig.get_opt_role()

    for item in opt_role.iteritems():
        if item[0] == rolename:
            if item[1] == "true":
                return True
            else:
                return False

    return True

def role_host_list(rolename, serviceEndpoints):
    logger.info("enter in role_host_list. rolename:%s" % rolename)
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/roles/%s/hosts?commit_state=uncommit" % (serviceEndpoints['cps']['internalurl'], rolename)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None

        hosts = json.loads(res.text)['hosts']

        return hosts
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None

def role_host_add(rolename, hosts, serviceEndpoints):
    logger.info("enter in role_host_add. rolename:%s, hosts:%s" % (rolename, hosts))
    method = "POST"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    body = {'type': 'include', 'hosts': hosts}
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/roles/%s/hosts" % (serviceEndpoints['cps']['internalurl'], rolename)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        print "assign hosts to role:role=%s,hosts=%s" % (rolename, hosts)
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False

def netHostcfgAdd(name, serviceEndpoints):
    logger.info("start to netHostcfgAdd, name:%s" % name)
    bRet = hostcfgGet(name, "network", "uncommit", serviceEndpoints['cps']['internalurl'])
    if bRet:
        logger.info("hostcfg %s is already exist. need to delete." % name)
        bRet = hostcfgDelete(name, "network", serviceEndpoints['cps']['internalurl'])
        if not bRet:
            logger.error("fail to hostcfgDelete. name:%s" % name)
            return False

    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network/types/%s" % (serviceEndpoints['cps']['internalurl'], name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        print "create network hostcfg, hostcfgname=%s" % name
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False


def hostcfgGet(name, type_name, commitstate, cpsUrl):
    logger.info("enter in netHostcfgGet. name:%s, type:%s" % (name, type_name))
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network?commit_state=%s" % (cpsUrl, commitstate)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        body = json.loads(res.text)
        lst_hostcfg = body["hostcfg"]
        for dct_hostcfg in lst_hostcfg:
            if dct_hostcfg["name"] == name:
                return dct_hostcfg
        else:
            return None
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None

def hostcfgDelete(name, type_name, cpsUrl):
    logger.info("enter in hostcfgDelete. name:%s, type:%s" % (name, type_name))
    method = "DELETE"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/%s/types/%s" % (cpsUrl, type_name, name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False


def netHostcfgNicAdd(name, lst_nics, serviceEndpoints):
    logger.info("start to netHostcfgNicAdd. name:%s, lst_nics:%s" % (name, lst_nics))
    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network/types/%s/items/nic" % \
          (serviceEndpoints['cps']['internalurl'], name)
    body = {'nics': lst_nics}
    kwargs['data'] = json.dumps(body)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        print "create network hostcfg, hostcfgname=%s, lst_nics:%s" % (name, lst_nics)
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False

def netHostcfgBondAdd(name, dct_bond, serviceEndpoints):
    logger.info("enter in netHostcfgBondAdd. name:%s, dct_bond:%s" % (name, dct_bond))
    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network/types/%s/items/bond" % \
          (serviceEndpoints['cps']['internalurl'], name)
    str_name = dct_bond.keys()[0]
    body = {"name":dct_bond.keys()[0],
            "bond_mode":dct_bond[str_name]["bond_mode"],
            "slaves":dct_bond[str_name]["slaves"]}
    kwargs['data'] = json.dumps(body)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        print "create network hostcfg, hostcfgname=%s, dct_bond:%s" % (name, dct_bond)
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False

def netHostcfgMappingAdd(name, dct_mapping, serviceEndpoints):
    logger.info("enter in netHostcfgMappingAdd. name:%s, dct_mapping:%s" % (name, dct_mapping))
    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network/types/%s/items/providermapping" % \
          (serviceEndpoints['cps']['internalurl'], name)
    kwargs['data'] = json.dumps(dct_mapping)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        print "create network hostcfg, hostcfgname=%s, dct_mapping:%s" % (name, dct_mapping)

        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False

def netHostcfgSysintfnwDelete(str_hostcfgname, str_item_name, serviceEndpoints):
    method = "DELETE"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network/types/%s/items/sysintfnwmapping" % \
          (serviceEndpoints['cps']['internalurl'], str_hostcfgname)
    dct_body = {'name': str_item_name}
    kwargs['data'] = json.dumps(dct_body)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        print "netHostcfgSysintfnwDelete, str_hostcfgname=%s, str_item_name:%s" % (str_hostcfgname, str_item_name)

        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False

def netHostcfgSysintfnwAdd(str_hostcfgname, dct_sysintfnwchange, serviceEndpoints):
    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network/types/%s/items/sysintfnwmapping" % \
          (serviceEndpoints['cps']['internalurl'], str_hostcfgname)
    kwargs['data'] = json.dumps(dct_sysintfnwchange)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        print "netHostcfgSysintfnwDelete, str_hostcfgname=%s, dct_sysintfnwchange:%s" % \
              (str_hostcfgname, dct_sysintfnwchange)

        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False

def netHostcfgSysintfnwChange(str_hostcfgname, dct_sysintfnwchange, serviceEndpoints):
    logger.info("enter in netHostcfgSysintfnwChange. str_hostcfgname:%s, dct_sysintfnwchange:%s" % \
                (str_hostcfgname, dct_sysintfnwchange))
    # delete old
    bRet = netHostcfgSysintfnwDelete(str_hostcfgname, dct_sysintfnwchange["name"], serviceEndpoints)
    if not bRet:
        logger.error("fail to netHostcfgSysintfnwDelete, str_hostcfgname:%s,dct_sysintfnwchange:%s" % \
                     (str_hostcfgname, dct_sysintfnwchange))
        return False
    # create new
    bRet = netHostcfgSysintfnwAdd(str_hostcfgname, dct_sysintfnwchange, serviceEndpoints)
    if not bRet:
        logger.error("fail to netHostcfgSysintfnwAdd, str_hostcfgname:%s, dct_sysintfnwchange:%s" % \
                     (str_hostcfgname, dct_sysintfnwchange))
        return False
    return True

def hostcfg_host_add(hosts, type_name, name, serviceEndpoints):
    logger.info("enter in hostcfg_host_add. hosts:%s, type:%s, name:%s" % (hosts, type_name, name))
    # check if host is already exist
    bRet, lst_host_not_add = hostcfg_host_list(hosts, type_name, name, serviceEndpoints)
    if bRet:
        logger.info("all host is configed. lst_host:%s" % lst_host_not_add)
        return True

    logger.info("hostcfg_host_add, lst_host_not_add:%s" % lst_host_not_add)
    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    body = {'hosts': {'hostid': lst_host_not_add}}
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/%s/types/%s/hosts" % (serviceEndpoints['cps']['internalurl'], type_name, name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        print "assign host to hostcfg, hostcfgname=%s,host=%s" % (name, lst_host_not_add)
        return True
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return False


def hostcfg_host_list(lst_hosts, type_name, name, serviceEndpoints):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/%s?commit_state=uncommit" % \
          (serviceEndpoints['cps']['internalurl'], type_name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False, lst_hosts
        lst_hostcfg = json.loads(res.text)["hostcfg"]
        for dctItem in lst_hostcfg:
            if dctItem["name"] == name:
                dctHost = dctItem["hosts"]
                if dctHost.has_key("default"):
                    return True, []
                if dctHost.has_key("hostid"):
                    lst_host_config = dctHost["hostid"]
                    lst_host_not_add = list(set(lst_hosts) - set(lst_host_config))
                    if len(lst_host_not_add) != 0:
                        return False, lst_host_not_add
                    else:
                        return True, []

        return False, lst_hosts
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s, e:%s" % (url, method, traceback.format_exc(), e))
        return False, lst_hosts

def getDefaultNetworkHostcfg(cpsServerUrl):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/network/types/default?commit_state=commited" % (cpsServerUrl)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, kwargs, res.text))
            return None

        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        return json.loads(res.text)
    except Exception, e:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, e))
        return None

def replace_sysintfnwmapping_change(lst_sysintfnwmapping_change, lst_sysintfnwmapping):
    def delete_item(name, lst_sysintfnwmapping):
        for item in lst_sysintfnwmapping:
            if item["name"] == name:
                lst_sysintfnwmapping.remove(item)
                break

    for dct_item in lst_sysintfnwmapping_change:
        str_name = dct_item["name"]
        delete_item(str_name, lst_sysintfnwmapping)
        lst_sysintfnwmapping.append(dct_item)

def generate_group_nic_info(index, dct_groups_info):
    dct_print_info = {"group":index,
                      "nic":dct_groups_info["pcis"],
                      "hostid":dct_groups_info["hosts"]}
    return dct_print_info

def get_provider_by_network(str_network, lst_sysintfnw_info):
    logger.info("enter in get_provider_by_network. str_network:%s, lst_sysintfnw_info:%s" % \
                (str_network, lst_sysintfnw_info))
    for dct_sysintfnw in lst_sysintfnw_info:
        if dct_sysintfnw["name"] == str_network:
            if dct_sysintfnw.has_key("provider_name"):
                return dct_sysintfnw["provider_name"]

    return None

def get_nic_by_bond(str_bond, dct_config_network_cfg):
    lst_bond = dct_config_network_cfg["bond"]
    for dct_bond in lst_bond:
        if str_bond == dct_bond.keys()[0]:
            return dct_bond[dct_bond.keys()[0]]["slaves"]
    return []


def generate_hostcfg_print_info(dct_config_network_cfg, lst_sysintfnw_info):
    lst_provider_print = []

    for dct_providermapping in dct_config_network_cfg["providermapping"]:
        lst_network = []
        str_provider_name = dct_providermapping["name"]
        str_interface = dct_providermapping["interface"]
        for dct_network in dct_config_network_cfg["sysintfnwmapping"]:
            str_find_provider_name = get_provider_by_network(dct_network["name"], lst_sysintfnw_info)
            if str_find_provider_name is None:
                if not dct_network.has_key("interface"):
                    str_msg = "network provider config error, exit. dct_network:%s" % dct_network
                    logger.error(str_msg)
                    print str_msg
                    sys.exit(1)
                else:
                    str_find_interface = dct_network["interface"]
                    if str_find_interface == str_interface:
                        lst_network.append(dct_network["name"])
            elif str_provider_name == str_find_provider_name:
                lst_network.append(dct_network["name"])
            else:
                continue
        lst_nic = get_nic_by_bond(str_interface, dct_config_network_cfg)
        str_nic = "nic:%s, bond:%s" % (lst_nic, str_interface)
        lst_provider_print.append({"provider":str_provider_name,
                                       "network":lst_network,
                                       "nic":str_nic})
    return lst_provider_print

def input_need_to_operate(str_msg, default_choice, is_config=True):
    user_choice = default_choice
    while 1:
        try:
            user_choice = ""
            if is_config:
                inputstr = "%s, [y|n][%s]" % \
                           (str_msg, default_choice)
                user_choice = raw_input(inputstr)
            if (user_choice == ""):
                user_choice = default_choice
                break
            elif (user_choice != "n" and user_choice != "y"):
                print "please input correct character,only support \'y\',\'n\',\'\'!"
                continue
            else:
                break
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            print "please input correct character,only support \'y\',\'n\'"
            continue
    if user_choice == 'y':
        return True
    else:
        return False

def generate_pci_to_name(lst_nic_config, lst_port_all):
    lst_port = []
    for dctItem in lst_nic_config:
        if dctItem["option"] == "AUTO-PXE":
            lst_port.append({"name":dctItem["name"], "pci":"AUTO-PXE"})
        else:
            lst_port.append({"name":dctItem["name"], "pci":dctItem["option"]["PCISLOT"]})
    lst_config_pci = [item["pci"] for item in lst_port]
    lst_config_name = [item["name"] for item in lst_port]
    max_eth = int(max(lst_config_name).strip("eth"))

    lst_port_all.sort()

    # pic  first 0x0， second 0x1
    for strPci in lst_port_all:
        if strPci in lst_config_pci:
            continue
        max_eth = max_eth + 1
        name = "eth%s" % max_eth

        find = 0
        for tmp in lst_port_all:
            if tmp == strPci:
                find = find + 1

        # if have more than one pci , should be add dev_id by ourself
        if find == 2 :
            pciTmp1 = strPci + "=0x0"
            has = 0
            for tmp2 in lst_port:
                pciTmp2 = tmp2["pci"]
                if pciTmp1 == pciTmp2:
                    has = 1
                    break
            if has == 0:
                strPci = strPci + "=0x0"
            else:
                strPci = strPci + "=0x1"

        lst_port.append({"name":name, "pci":strPci})
    return lst_port

def get_max_trunk_id(lst_bond):
    logger.info("[get_max_trunk_id] lst_bond:%s" % lst_bond)
    lst_name = [item['name'] for item in lst_bond]
    logger.info("[get_max_trunk_id] lst_name:%s" % lst_name)
    str_max_trunk = max(lst_name)
    logger.info("[get_max_trunk_id] str_max_trunk:%s" % str_max_trunk)
    return int(str_max_trunk.strip("trunk"))

def get_port_dev_id_by_name(port, lst_port):
    dev_id = ""
    for dctPort in lst_port:
        if dctPort["name"] == port:
            networkPci = dctPort["pci"]
            networkList = networkPci.split("=")
            if len(networkList) == 3:
                dev_id = networkList[2]
            break


    return dev_id


def get_port_pci_by_name(str_name, lst_port):
    for dctPort in lst_port:
        if dctPort["name"] == str_name:
            return dctPort["pci"].split("=")[0]

    return None

def import_network_hostcfg_for_groups(dct_groups,
                                      dct_default_network_cfg,
                                      def_dct_hostcfg_info,
                                      lst_provider,
                                      lst_sysintfnw_info,
                                      is_config=True):
    dct_all_physnet_info = {}

    for index in dct_groups:

        print "config network for group %s " % index
        str_group = "group%s" % index

        dct_config_network_cfg = copy.deepcopy(dct_default_network_cfg)
        if def_dct_hostcfg_info.has_key(str_group):
            if def_dct_hostcfg_info[str_group].has_key(Constant.NETWORK_HOSTCFG_INFO_NIC_ADD):
                dct_config_network_cfg["nic"].\
                    append(def_dct_hostcfg_info[str_group][Constant.NETWORK_HOSTCFG_INFO_NIC_ADD])
            if def_dct_hostcfg_info[str_group].has_key(Constant.NETWORK_HOSTCFG_INFO_BOND_ADD):
                dct_config_network_cfg["bond"].\
                    append(def_dct_hostcfg_info[str_group][Constant.NETWORK_HOSTCFG_INFO_BOND_ADD])
            if def_dct_hostcfg_info[str_group].has_key(Constant.NETWORK_HOSTCFG_INFO_MAPPING_ADD):
                dct_config_network_cfg["providermapping"].\
                    append(def_dct_hostcfg_info[str_group][Constant.NETWORK_HOSTCFG_INFO_MAPPING_ADD])
            if def_dct_hostcfg_info[str_group].has_key(Constant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE):
                replace_sysintfnwmapping_change(def_dct_hostcfg_info[str_group][Constant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE],
                                                dct_config_network_cfg["sysintfnwmapping"])
        dct_all_physnet_info[str_group] = [item["name"] for item in dct_default_network_cfg["providermapping"]]
        if def_dct_hostcfg_info.has_key(str_group) and def_dct_hostcfg_info[str_group].has_key("providermapping_add"):
            dct_all_physnet_info[str_group].\
                extend([item["name"] for item in def_dct_hostcfg_info[str_group]["providermapping_add"]])

        dct_print_info = generate_group_nic_info(index, dct_groups[index])
        lst_print_info = [dct_print_info]
        utils.print_list(lst_print_info, ["group", "nic", "hostid"])

        print "------------------default hostcfg----------------------"
        lst_provider_print = generate_hostcfg_print_info(dct_config_network_cfg, lst_sysintfnw_info)
        utils.print_list(lst_provider_print, ["provider", "network", "nic"])

        str_msg = "do you want to change hostcfg for group%s" % index
        bRet = input_need_to_operate(str_msg, 'n', is_config)
        if not bRet:
            continue

        def_providermapping_add_flag = 'n'

        lst_nic_add = []
        lst_bond_add = []
        lst_providermapping_add = []
        lst_sysintfnwmapping_change = []

        # ask if need to add port
        # print port and pci
        lst_nic_config = dct_config_network_cfg["nic"]
        lst_port_all = dct_groups[index]["pcis"]

        lst_port = generate_pci_to_name(lst_nic_config, lst_port_all)

        print "------------------port info-----------------"
        utils.print_list(lst_port, ["name", "pci"])

        i_max_trunk_id = get_max_trunk_id(dct_config_network_cfg["bond"]) + 1

        while True:
            str_msg = "do you want to add provider mapping for group %s" % index
            bRet = input_need_to_operate(str_msg, def_providermapping_add_flag, is_config)
            if not bRet:
                break
            def_providermapping_info = "physnet2,kernel-ovs"
            inputstr = "input provider mapping info as provider,mappingtype[physnet2,kernel-ovs][%s] : " % \
                       (def_providermapping_info)
            providermapping_info = raw_input(inputstr)
            if (providermapping_info == ""):
                providermapping_info = def_providermapping_info
            if providermapping_info == "":
                print "please input correct info, such as:provider,mappingtype"
                continue
            if len(providermapping_info.split(",")) != 2:
                print "please input correct info, such as:provider,mappingtype"
                continue

            str_provider = providermapping_info.split(",")[0]

            str_mappingtype = providermapping_info.split(",")[1]
            if str_provider not in [item["name"] for item in lst_provider]:
                print "please input correct provider. %s" % [item["name"] for item in lst_provider]
                continue

            if str_mappingtype not in Constant.LST_MAPPINT_TYPE:
                print "please input correct mapping type. %s" % Constant.LST_MAPPINT_TYPE
                continue

            def_bond_or_port = "bond"
            inputstr = "do you want to add bond or port to provider:%s. [bond|port][%s]" % \
                       (str_provider, def_bond_or_port)
            bond_or_port = raw_input(inputstr)
            if (bond_or_port == ""):
                bond_or_port = def_bond_or_port
            if bond_or_port not in ["bond", "port"]:
                print "please input correct info"
                continue

            if bond_or_port == "bond":
                def_bond_mode = "nobond"
                inputstr = "input bondmode for trunk%s, as [nobond][%s]" % (i_max_trunk_id, def_bond_mode)
                str_bond_mode = raw_input(inputstr)
                if (str_bond_mode == ""):
                    str_bond_mode = def_bond_mode
                if str_bond_mode not in Constant.LST_BOND_MODE:
                    print "please input correct bondmode:%s" % Constant.LST_BOND_MODE
                    continue

                def_port_info = "eth2,eth3"
                inputstr = "input port for trunk%s, as [eth2,eth3][%s]" % (i_max_trunk_id, def_port_info)
                port_info = raw_input(inputstr)
                if (port_info == ""):
                    port_info = def_port_info
                if port_info == "":
                    print "please input correct info, such as:eth2,eth3"
                    continue
                lst_port_name = []
                lst_port_input = port_info.split(",")
                for port in lst_port_input:
                    if port.find(":") >= 0:
                        vf_num = port.split(":")[1]
                        port = port.split(":")[0]

                        dev_id = get_port_dev_id_by_name(port, lst_port)
                        if dev_id != "":
                            lst_nic_add.append({"name":port,
                                            "option":{"PCISLOT":get_port_pci_by_name(port, lst_port),
                                                      "vf_num":vf_num, "dev_id" : dev_id}})
                        else:
                            lst_nic_add.append({"name":port,
                                            "option":{"PCISLOT":get_port_pci_by_name(port, lst_port),
                                                      "vf_num":vf_num}})

                        print 'lst_nic_add = %s ' % lst_nic_add
                        lst_port_name.append(port)
                    else:
                        dev_id = get_port_dev_id_by_name(port, lst_port)
                        if dev_id != "":
                            lst_nic_add.append({"name":port,
                                            "option":{"PCISLOT":get_port_pci_by_name(port, lst_port), "dev_id": dev_id}})
                        else:
                            lst_nic_add.append({"name":port,
                                            "option":{"PCISLOT":get_port_pci_by_name(port, lst_port)}})

                        print 'lst_nic_add = %s ' % lst_nic_add
                        lst_port_name.append(port)



                str_bond_name = "trunk%s" % i_max_trunk_id
                lst_bond_add.append({str_bond_name:
                                             {"bond_mode":str_bond_mode,
                                              "slaves":lst_port_name}})
                str_providermapping_name = str_provider
                lst_providermapping_add.append({"name":str_providermapping_name,
                                                    "interface":str_bond_name,
                                                    "mappingtype":str_mappingtype})
            else:
                def_port = "eth2"
                inputstr = "input port for provider:%s, as [eth2][%s]" % (str_provider, def_port)
                port_name = raw_input(inputstr)
                if (port_name == ""):
                    port_name = def_port
                if port_name == "":
                    print "please input correct info, such as:eth2"
                    continue
                if port_name.find(":") >= 0:
                    vf_num = port_name.split(":")[1]
                    port_name = port_name.split(":")[0]
                    dev_id = get_port_dev_id_by_name(port_name, lst_port)

                    if dev_id != "":
                        lst_nic_add.append({"name":port_name,
                                        "option":{"PCISLOT":get_port_pci_by_name(port_name, lst_port),
                                                  "vf_num":vf_num, "dev_id": dev_id}})
                    else:

                        lst_nic_add.append({"name":port_name,
                                        "option":{"PCISLOT":get_port_pci_by_name(port_name, lst_port),
                                                  "vf_num":vf_num}})

                    print "lst_nic_add=%s" % lst_nic_add
                else:
                    dev_id = get_port_dev_id_by_name(port_name, lst_port)
                    if dev_id != "":
                        lst_nic_add.append({"name":port_name,
                                            "option":{"PCISLOT":get_port_pci_by_name(port_name, lst_port), "dev_id": dev_id}})
                    else:
                        lst_nic_add.append({"name":port_name,
                                            "option":{"PCISLOT":get_port_pci_by_name(port_name, lst_port)}})

                    print "lst_nic_add=%s" % lst_nic_add

                str_providermapping_name = str_provider
                lst_providermapping_add.append({"name":str_providermapping_name,
                                                    "interface":port_name,
                                                    "mappingtype":str_mappingtype})

            logger.info("dct_all_physnet_info:%s" % dct_all_physnet_info)
            dct_all_physnet_info[str_group].\
                extend([item["name"] for item in lst_providermapping_add])

            i_max_trunk_id = i_max_trunk_id + 1

        # change sysintfnwmapping
        dct_sysintfnwmapping = dct_default_network_cfg["sysintfnwmapping"]

        str_msg = "do you want to change sysintfnwmapping."
        bRet = input_need_to_operate(str_msg, 'n', is_config)
        if not bRet:
            logger.info("do not need to change. continue")
            def_dct_hostcfg_info[str_group] = {"nic_add":lst_nic_add,
                                           "bond_add":lst_bond_add,
                                           "providermapping_add":lst_providermapping_add,
                                           "sysintfnw_change":[]}
            continue

        for dct_net in dct_sysintfnwmapping:
            if dct_net["name"] == Constant.INTERNAL_BASE:
                continue
            print "-------------------sysintfnwmapping for %s----------------" % (dct_net["name"])

            utils.print_dict(dct_net)
            if dct_net.has_key("interface"):
                str_msg = "do you want to change interface config for %s" % dct_net["name"]
            else:
                str_msg = "do you want to add interface for %s" % dct_net["name"]

            def_sysintfnwmapping_change_flag = 'n'
            bRet = input_need_to_operate(str_msg, def_sysintfnwmapping_change_flag, is_config)
            if not bRet:
                continue

            def_interface_name = "trunk0"
            while True:
                try:
                    inputstr = "input interface name [name][%s] " % def_interface_name
                    interface_name = raw_input(inputstr)
                    if (interface_name == ""):
                        interface_name = def_interface_name

                    if interface_name == "":
                        print "please input correct info, such as:trunk0"
                        continue
                    elif dct_net.has_key("interface") and interface_name == dct_net["interface"]:
                        print "interface is same, please input correct info"
                        continue
                    break

                except KeyboardInterrupt:
                    sys.exit(1)
                except:
                    print "please input correct character,only support \'y\',\'n\'"
                    continue
            logger.info("add lst_sysintfnwmapping_change.")
            lst_sysintfnwmapping_change.append({'interface':interface_name,
                                                'name': dct_net["name"]})
        def_dct_hostcfg_info[str_group] = {Constant.NETWORK_HOSTCFG_INFO_NIC_ADD:lst_nic_add,
                                           Constant.NETWORK_HOSTCFG_INFO_BOND_ADD:lst_bond_add,
                                           Constant.NETWORK_HOSTCFG_INFO_MAPPING_ADD:lst_providermapping_add,
                                           Constant.NETWORK_HOSTCFG_INFO_SYSINTFNW_CHANGE:lst_sysintfnwmapping_change}
    logger.info("exit import_network_hostcfg_for_groups.")
    return dct_all_physnet_info