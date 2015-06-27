#!/usr/bin/env python
# coding:utf-8
# Helper functions for the CPS client.
import os
from os.path import join
import sys
import json
import time
import traceback
from fs_disk_constant import DiskConstant
import fs_log_util
import cps_server
from print_msg import PrintMessage as PrintUtil
import types

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
logger = fs_log_util.localLog.get_logger(LOG_FILE)
CFG_PATH_SRV_IP = '/etc/huawei/fusionsphere/cfg/serverIp.ini'


def net_host_cfg_nics_add(name, lst_nics, cpsServerUrl):
    logger.info("start to netHostcfgNicAdd. name:%s, lst_nics:%s,cpsServerUrl:%s." % (name, lst_nics, cpsServerUrl))
    url = "/cps/v1/hostcfg/network/types/%s/items/nic" % name
    body = {'nics': lst_nics}
    return cps_server.put_cps_http(url, body)


def net_host_cfg_bond_add(name, bond_detail, cpsServerUrl):
    logger.info("enter in netHostcfgBondAdd. name:%s, dct_bond:%s,cpsServerUrl:%s." % (name, bond_detail, cpsServerUrl))
    url = "/cps/v1/hostcfg/network/types/%s/items/bond" % name
    str_name = bond_detail.keys()[0]
    body = {"name":bond_detail.keys()[0],
            "bond_mode":bond_detail[str_name]["bond_mode"],
            "slaves":bond_detail[str_name]["slaves"]}
    return cps_server.put_cps_http(url, body)


def net_host_cfg_provider_mapping_add(name, one_providermapping, cpsServerUrl):
    logger.info("enter in netHostcfgMappingAdd. name:%s, dct_mapping:%s,"
                "cpsServerUrl:%s." % (name, one_providermapping,cpsServerUrl))
    url = "/cps/v1/hostcfg/network/types/%s/items/providermapping" % name
    return cps_server.put_cps_http(url, one_providermapping)


def net_host_cfg_sysintfnw_delete(str_hostcfgname, str_item_name, cpsServerUrl):
    logger.info("enter in net_host_cfg_sysintfnw_delete.url=%s." %  cpsServerUrl)
    body = {'name': str_item_name}
    url = "/cps/v1/hostcfg/network/types/%s/items/sysintfnwmapping" % str_hostcfgname
    return cps_server.delete_cps_http(url, body)


def net_hostcfg_sysintfnw_add(str_hostcfgname, one_sysintfnwmapping, cpsServerUrl):
    logger.info("enter in net_hostcfg_sysintfnw_add.url=%s." %  cpsServerUrl)
    url = "/cps/v1/hostcfg/network/types/%s/items/sysintfnwmapping" %  str_hostcfgname
    return cps_server.put_cps_http(url, one_sysintfnwmapping)


def netHostcfgSysintfnwMappingChange(str_hostcfgname, one_sysintfnwmapping, cpsServerUrl):
    logger.info("enter in netHostcfgSysintfnwMappingChange. str_hostcfgname:%s, dct_sysintfnwchange:%s" % \
                (str_hostcfgname, one_sysintfnwmapping))
    # delete old
    bRet = net_host_cfg_sysintfnw_delete(str_hostcfgname, one_sysintfnwmapping["name"], cpsServerUrl)
    if not bRet:
        logger.error("fail to netHostcfgSysintfnwDelete, str_hostcfgname:%s,dct_sysintfnwchange:%s" % \
                     (str_hostcfgname, one_sysintfnwmapping))
        return False
    # create new
    bRet = net_hostcfg_sysintfnw_add(str_hostcfgname, one_sysintfnwmapping, cpsServerUrl)
    if not bRet:
        logger.error("fail to netHostcfgSysintfnwAdd, str_hostcfgname:%s, dct_sysintfnwchange:%s" % \
                     (str_hostcfgname, one_sysintfnwmapping))
        return False
    return True

def get_default_network_hostcfg(cpsServerUrl):
    logger.info("enter in get_default_network_hostcfg.url=%s." %  cpsServerUrl)
    url = '/cps/v1/hostcfg/network/types/default?commit_state=commited'
    return cps_server.get_cps_http(url)


def stor_hostcfg_check(name, cps_url):
    logger.info("enter in storHostcfgCheck. name:%s, url=%s." % (name, cps_url))
    url = "/cps/v1/hostcfg/storage?commit_state=uncommit"
    (flag, data) = cps_server.get_cps_http_with_flag(url)
    if not flag:
        return False

    lst_hostcfg = json.loads(data)["hostcfg"]
    logger.info("lst_hostcfg:%s" % lst_hostcfg)
    for dctItem in lst_hostcfg:
        if dctItem["name"] == name:
            return True

    return False

def generate_storage_groups(cpsServerUrl, lst_allhostid, lst_ctrl_host):
    logger.info( 'generate storage groups by pci Type.cpsServerUrl=%s.'%cpsServerUrl)
    storageGroup = []

    control = ""#"control_"
    compute = ""#"compute_"
    groupFlag = compute

    for str_hostid in lst_allhostid:
        dctHostInfo = cps_server.get_host_detail_info(str_hostid)
        if dctHostInfo is None:
            continue

        lst_diskinfo = dctHostInfo[DiskConstant.DISKINFO_KEY]
        if str_hostid in lst_ctrl_host:
            groupFlag = control
        else:
            groupFlag = compute

        diskList = []
        #获取该host的所有pci信息，需要去除system 的pic槽号
        devList = []
        for item in lst_diskinfo:
            if item.has_key(DiskConstant.DEV_KEY):
                devList.append(item[DiskConstant.DEV_KEY])
        devList.sort()
        systemDisk = devList[0]

        for item in lst_diskinfo:
            if item.has_key(DiskConstant.DEV_KEY) and systemDisk != item[DiskConstant.DEV_KEY]:
                disk = item[DiskConstant.DEV_KEY] + "=" + item[DiskConstant.DISK_KEY] + "=" + item["size"].strip("GB") + "g"
                diskList.append(disk)
        groupId = groupFlag + str_hostid
        storageGrouptmp =  {DiskConstant.GROUP_KEY: groupId, DiskConstant.HOSTID_KEY:str_hostid, DiskConstant.DISK_KEY : diskList}

        storageGroup.append(storageGrouptmp)

    return storageGroup


def generate_storage_groups_by_pci_Type(cpsServerUrl, lst_allhostid, lst_ctrl_host):
    logger.info( 'generate storage groups by pci Type.cpsServerUrl=%s.'%cpsServerUrl)
    dct_host_pci = {}

    for str_hostid in lst_allhostid:
        dctHostInfo = cps_server.get_host_detail_info(str_hostid)
        dct_host_pci[str_hostid] = [ "no-found" ]
        if dctHostInfo is None:
            continue
        lst_diskinfo = dctHostInfo[DiskConstant.DISKINFO_KEY]

        diskList = []
        #获取该host的所有pci信息，需要去除system 的pic槽号
        devList = []
        for item in lst_diskinfo:
            if item.has_key(DiskConstant.DEV_KEY):
                devList.append(item[DiskConstant.DEV_KEY])
        devList.sort()

        for item in lst_diskinfo:
            #先不过滤系统盘，让用户看到系统盘大小，好分配空间
            if item.has_key(DiskConstant.DEV_KEY):
                disk = item[DiskConstant.DEV_KEY] + "=" + item[DiskConstant.DISK_KEY] + "=" + item["size"].strip("GB") + "g"
                diskList.append(disk)

        dct_host_pci[str_hostid] = diskList

    #对所有的host 的pci 进行分组
    controlGroup = []
    computeGroup = []
    control = DiskConstant.CONTROL_GROUP
    compute = DiskConstant.COMPUTE_GROUP

    for str_hostid in lst_allhostid:
        if str_hostid in lst_ctrl_host:
            add_host_to_storage_groups(controlGroup, dct_host_pci[str_hostid], str_hostid, control)
        else:
            add_host_to_storage_groups(computeGroup, dct_host_pci[str_hostid], str_hostid, compute)

    logger.info( 'generate storage groups by pci Type end controlGroup = %s,computeGroup=%s .' %(controlGroup,computeGroup ))
    return (controlGroup, computeGroup)


def generate_storage_groups_by_extend_host(cpsServerUrl, groupInfo , extendHostList, flag):
    logger.info( 'generate storage groups by pci Type.cpsServerUrl=%s.'%cpsServerUrl)
    dct_host_pci = {}

    for str_hostid in extendHostList:
        dct_host_pci[str_hostid] = ["no-found"]
        dctHostInfo = cps_server.get_host_detail_info(str_hostid)
        if dctHostInfo is None:
            continue

        lst_diskinfo = dctHostInfo[DiskConstant.DISKINFO_KEY]

        diskList = []
        #获取该host的所有pci信息，需要去除system 的pic槽号
        devList = []
        for item in lst_diskinfo:
            if item.has_key(DiskConstant.DEV_KEY):
                devList.append(item[DiskConstant.DEV_KEY])
        devList.sort()

        for item in lst_diskinfo:
            if item.has_key(DiskConstant.DEV_KEY) :
                disk = item[DiskConstant.DEV_KEY] + "=" + item[DiskConstant.DISK_KEY] + "=" + item["size"].strip("GB") + "g"
                diskList.append(disk)

        dct_host_pci[str_hostid] = diskList

    for str_hostid in extendHostList:
        add_host_to_storage_groups(groupInfo, dct_host_pci[str_hostid], str_hostid, flag)

    return groupInfo



def add_host_to_storage_groups(dct_groups, lst_pci, host, groupFlag):
    bFlag = False
    for item in dct_groups:
        if set(item[DiskConstant.DISK_KEY]) == set(lst_pci):
            if host in list(item[DiskConstant.HOSTID_KEY]):
                return dct_groups
            else:
                item[DiskConstant.HOSTID_KEY].append(host)
                bFlag = True
                break

    if not bFlag:
        if len(dct_groups) == 0:
            index = 1
        else:
            index = len(dct_groups) + 1

        groupId = groupFlag + "%s"%index
        item = {DiskConstant.GROUP_KEY : groupId, DiskConstant.DISK_KEY: lst_pci,
                DiskConstant.HOSTID_KEY: [host],  DiskConstant.EXTENDISK_KEY : [],
                DiskConstant.REMOVEDISK_KEY : [] }
        dct_groups.append(item)


def getChooseYN():
    while 1:
        try:
            inputstr = PrintUtil.get_msg_by_index("1000040")
            choose = raw_input(inputstr)
            if (choose == "" or choose == "n"):
                return "n"
            elif (choose == "y"):
                return "y"
            else:
                PrintUtil.print_msg_by_index("1000002")
                continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except:
            PrintUtil.print_msg_by_index("1000002")
            continue


def makeChooseByYourself(choosetType):
    message = "["
    for item in choosetType:
        message = message + item + "|"
    message = message[:-1] + "]" + "["+ choosetType[0] + "]"

    while 1:
        try:
            inputstr = PrintUtil.get_msg_by_index_ex("1000001", (message))
            choose = raw_input(inputstr)
            if (choose == ""  ):
                return choosetType[0]
            elif (choose in choosetType):
                return choose
            else:
                PrintUtil.print_msg_by_index("1000002")
                continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except:
            PrintUtil.print_msg_by_index("1000002")
            time.sleep(1)
            continue

def makeChooseByYourselfReverse(choosetType, default_type):
    message = "["
    for item in choosetType:
        message = message + item + "|"
    message = message[:-1] + "]" + "["+ default_type + "]"

    while 1:
        try:
            inputstr = PrintUtil.get_msg_by_index_ex("1000001", (message))
            choose = raw_input(inputstr)

            choose = choose.rstrip()
            if (choose == ""  ):
                return default_type
            elif (choose in choosetType):
                return choose
            else:
                PrintUtil.print_msg_by_index("1000002")
                logger.warning( "inpute is valid. choose = '%s', choosetType = '%s'."%(choose, choosetType))
                continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except:
            PrintUtil.print_msg_by_index("1000002")
            time.sleep(1)
            continue




def storHostcfgCheck( name, cpsurl):
    logger.info("enter in storHostcfgCheck. name:%s" % name)
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/storage?commit_state=uncommit" %cpsurl
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        lst_hostcfg = json.loads(res.text)["hostcfg"]
        logger.info("lst_hostcfg:%s" % lst_hostcfg)
        for dctItem in lst_hostcfg:
            if dctItem["name"] == name:
                return True
        else:
            return False
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False

def storHostcfgAdd(name, cpsurl):
    logger.info("start to storHostcfgAdd. name:%s" % name)
    # check hostcfg is exist
    bRet = stor_hostcfg_check(name, cpsurl)
    if bRet:
        logger.info("hostcfg:%s is already exist" % name)
        return True
    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/storage/types/%s" % (cpsurl, name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        logger.info("create storage hostcfg, hostcfgname=%s" % name)
        return True
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False





def diskadd(hostcfgname, partname, diskpci, partsize, cpsurl):
    """
    """
    logger.info("start to diskadd. hostcfgname:%s, partname:%s, diskpci:%s, partsize:%s" % \
                 (hostcfgname, partname, diskpci, partsize))
    body = {"name":partname, "disk":diskpci, "size":partsize}
    (result, ppNmae) = diskCheck(hostcfgname, body, cpsurl)
    if result is not None:
        if result:
            logger.info("disk %s is alread exist. return" % body)
            return True
        else:
            # need to delete disk
            bRet = diskDel(hostcfgname, ppNmae, cpsurl)
            logger.info("disk delete success. hostcfgname:%s, ppNmae:%s" % (hostcfgname, ppNmae))
            if not bRet:
                logger.error("fail to delete disk. %s" % ppNmae)
                return False

    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    body = {'partition-name': partname, 'disk': diskpci, 'partition-size': partsize}
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/storage/types/%s/items/physical-partition" % (cpsurl, hostcfgname)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False

        logger.info("create phsical partition from extend disk, hostcfgname=%s,disk=%s,partname = %s" % (hostcfgname, diskpci, partname))
        return True
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False


def diskDel(hostcfgname, ppname, cpsurl):
    method = "DELETE"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    body = {'name': ppname}
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/storage/types/%s/items/physical-partition" % (cpsurl, hostcfgname)

    logger.info("delete phsical partition from extend disk, hostcfgname=%s,partname = %s" % (hostcfgname, ppname))
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        return True
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return True

def diskCheckAndDel(hostcfgname,dev ,diskpci, cpsurl):

    body = {"name":dev, "disk":diskpci, "size": "all"}
    (result, ppNmae) = diskCheck(hostcfgname, body, cpsurl)
    if result is not None:
        # need to delete disk
        bRet = diskDel(hostcfgname, ppNmae, cpsurl)
        logger.info("disk delete success. hostcfgname:%s, ppNmae:%s" % (hostcfgname, ppNmae))
        if not bRet:
            logger.error("fail to delete disk. %s" % ppNmae)
            return False

    return True

def vgsCheck(hostcfgname, oldBody, cpsurl ):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/storage/types/%s?commit_state=uncommit" % (cpsurl, hostcfgname)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        if not json.loads(res.text).has_key("lvm-vg"):
            return None

        lst_disk = json.loads(res.text)["lvm-vg"]
        logger.info("lst_disk:%s" % lst_disk)
        for dctItem in lst_disk:
            if oldBody["partname"] == dctItem:
                return True
        else:
            return False
    except:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return None


def addDisk2Vg(hostcfgname, partname, cpsurl):
    logger.info("start to addDisk2Vg. hostcfgname:%s, partname:%s" % (hostcfgname, partname))
    # vgsCheck
    body = {"partname":partname}
    result = vgsCheck(hostcfgname, body, cpsurl)
    if result is not None:
        if result:
            logger.info("vgs %s is alread exist. return" % body)
            return True

    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    body = {'physicalpartition': partname}
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/storage/types/%s/items/lvm-vg" % (cpsurl, hostcfgname)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        logger.info("add phsical partition to system vg, hostcfgname=%s,partname=%s" % (hostcfgname, partname))
        return True
    except:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False

def diskCheck(hostcfgname, oldBody, cpsurl ):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/storage/types/%s?commit_state=uncommit" % (cpsurl, hostcfgname)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return (None, None)
        if not json.loads(res.text).has_key("physical-partition"):
            return (None, None)

        lst_disk = json.loads(res.text)["physical-partition"]
        logger.info("lst_disk:%s" % lst_disk)
        for dctItem in lst_disk:
            logger.info( "old disk = %s, new disk = %s ."%(oldBody["disk"], dctItem["disk"]))
            if oldBody["disk"] == dctItem["disk"]:
                logger.info("diskCheck. oldBody:%s, dctItem:%s" % (oldBody, dctItem))
                if oldBody["name"] == dctItem["name"] and oldBody["size"] == dctItem["size"]:
                    return (True, dctItem["name"])
                else:
                    return (False, dctItem["name"])

        return (None, None)
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return (None, None)


def lvCheck(hostcfgname, oldBody, cpsurl ):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/storage/types/%s?commit_state=uncommit" % (cpsurl, hostcfgname)
    size = "10g"
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return (False, size)

        if not json.loads(res.text).has_key("logical-volume"):
            return (None, size)

        lst_lv = json.loads(res.text)["logical-volume"]
        logger.info("lst_lv:%s" % lst_lv)
        for dctItem in lst_lv:
            if oldBody["lvname"] == dctItem["name"]:
                logger.info("lvCheck. oldBody:%s, dctItem:%s" % (oldBody, dctItem))
                if oldBody["mount"] == dctItem["path"] \
                    and oldBody["format"] == dctItem["format"] \
                    and oldBody["size"] == dctItem["size"]:
                    return (True, size)
                else:
                    return (False, dctItem["size"])

        return (None, size)
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return (None, size)

def lvDel(hostcfgname, lvname, cpsurl):
    method = "DELETE"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    body = {'name': lvname}
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/storage/types/%s/items/logical-volume" % (cpsurl, hostcfgname)

    logger.info("delete logical volume to hostcfg, hostcfgname=%s,lvname=%s" % (hostcfgname, lvname))
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        return True
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return True
        
def lvUpdate(hostcfgname, lvname, size, cpsurl):
    logger.info("enter in lvUpdate. hostcfgname:%s, lvname:%s, size:%s" % (hostcfgname, lvname, size))
    body = {'name': lvname, 'backendtype': 'local', 'size': size}
    
    method = "POST"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/storage/types/%s/items/logical-volume" % (cpsurl, hostcfgname)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, kwargs, res.text))
            return False
        logger.info("update logical volume to hostcfg, hostcfgname=%s,lvname=%s,lvsize=%s" % (hostcfgname, lvname, size))
        return True
    except:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False
        
def lvAdd(hostcfgname, lvname, size, mount, format_name, cpsurl):
    logger.info("enter in lvAdd. hostcfgname:%s, lvname:%s, size:%s, mount:%s,format:%s" % (hostcfgname, lvname, size,
                                                                                          mount, format_name))
    body = {'lvname': lvname, 'mount': mount, 'format': format_name, 'size': size}
    # check lv is already exists
    (result, sizeTmp)  = lvCheck(hostcfgname, body, cpsurl)
    logger.info("lvCheck result. hostcfgname:%s, result:%s" % (hostcfgname, result))
    if result is not None:
        if result:
            logger.info("lv %s is alread exist. return" % body)
            return True
        else:
            # need to delete lv
            bRet = lvDel(hostcfgname, lvname, cpsurl)
            logger.info("lv delete success. hostcfgname:%s, lvname:%s" % (hostcfgname, lvname))
            if not bRet:
                logger.error("fail to delete lv. %s" % lvname)
                return False

    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/storage/types/%s/items/logical-volume" % (cpsurl, hostcfgname)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, kwargs, res.text))
            #如果配置失败，尝试回退，当前最多只能尝试回退,使用20g是用于保证创建成功，否则会出现失败，磁盘变少，数据不会丢失，删除会丢失
            if  not create_lv_size(hostcfgname, lvname, sizeTmp, mount, format_name, cpsurl):
                if not create_lv_size(hostcfgname, lvname, "20g", mount, format_name, cpsurl):
                    logger.info("create logical volume  create_lv_size failed. ")
            return False
        logger.info("create logical volume to hostcfg, hostcfgname=%s,lvname=%s,lvsize=%s,mount=%s" % (hostcfgname, lvname, size, mount))
        return True
    except:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False

def create_lv_size(hostcfgname, lvname, size, mount, format_name, cpsurl):
    body = {'lvname': lvname, 'mount': mount, 'format': format_name, 'size': size}
    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/storage/types/%s/items/logical-volume" % (cpsurl, hostcfgname)
    res = cps_server.rest_cps_execute(method, url, **kwargs)
    if (res.status_code < 200 or res.status_code >= 300):
        logger.info("restore logical volume to hostcfg, hostcfgname=%s,lvname=%s,lvsize=%s,mount=%s" % (hostcfgname, lvname, size, mount))
    return False



def hostcfg_host_list(lst_hosts, host_type, name, cpsurl):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/%s?commit_state=uncommit" % (cpsurl, host_type)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False, lst_hosts
        lst_hostcfg = json.loads(res.text)["hostcfg"]
        logger.info("lst_hostcfg:%s" % lst_hostcfg)
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
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False, lst_hosts


def hostcfg_host_add(hosts, host_type, name, cpsurl):
    logger.info("enter in hostcfg_host_add. hosts:%s, type:%s, name:%s" % (hosts, host_type, name))
    # check if host is already exist
    bRet, lst_host_not_add = hostcfg_host_list(hosts, host_type, name, cpsurl)
    if bRet:
        logger.info("all host is configed. lst_host:%s" % lst_host_not_add)
        return True

    logger.info("hostcfg_host_add, lst_host_not_add:%s" % lst_host_not_add)
    method = "PUT"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    body = {'hosts': {'hostid': lst_host_not_add}}
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/hostcfg/%s/types/%s/hosts" % (cpsurl, host_type, name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)
        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False
        logger.info("assign host to hostcfg, hostcfgname=%s,host=%s" % (name, lst_host_not_add))
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        return True
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False

def getHostcfgList(cpsServerUrl):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg?commit_state=uncommit" % (cpsServerUrl)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))

        return json.loads(res.text)["hostcfg"]
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return None

def storageHostcfgDelete(name, cpsServerUrl):

    bRet = stor_hostcfg_check(name, cpsServerUrl)
    if not bRet:
        logger.info("hostcfg:%s is not exist" % name)
        return True

    method = "DELETE"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/storage/types/%s" % (cpsServerUrl, name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False

        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        return True
    except:
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False


def updateTemplateParams(cpsServerUrl, service_name, template_name, params):
    method = "POST"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    body = {'cfg': params}
    kwargs['data'] = json.dumps(body)
    url = "%s/cps/v1/services/%s/componenttemplates/%s/params" % (cpsServerUrl, service_name, template_name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return False

        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        logger.info("update template params,service=%15s template=%30s" % (service_name, template_name))
        return True
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return False


def checkIpFormatIsCorrect(ipList):
    for ip in ipList:
        q = ip.split('.')
        flag = len(q) == 4 and len(filter(lambda x: x >= 0 and x <= 255, \
                    map(int, filter(lambda x: x.isdigit(), q)))) == 4
        if not flag:
            return False

    return True

def checkSizeFormatIsCorrect(size):
    lowerSize = size
    sizeTmp = lowerSize
    if 'G' in lowerSize:
        sizeTmp = lowerSize.split('G')[0]
        if len(lowerSize.split('G')) != 2 :
            return False

    try:
        sizeTmp = lowerSize.split('G')[0]
        realSize = long(sizeTmp)
    except:
        return False

    return True

def getTemplateList(cpsServerUrl):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/services/all/componenttemplates?commit_state=commited" % (cpsServerUrl)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return (None, None)
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))

        templates = json.loads(res.text)["templates"]
        templateList = []
        nameList = []
        for item in templates:
            service = item["service"]
            template = item["name"]
            foundService = False
            for item in templateList:
                if item[DiskConstant.SERVICE] == service :
                    foundService = True
                    item[DiskConstant.TEMPLATE].append(template)
                    break
            tmp = {}
            if not foundService:
                tmp[DiskConstant.SERVICE] = service
                tmplist = [template]
                tmp[DiskConstant.TEMPLATE] = tmplist
                templateList.append(tmp)
            nameList.append(service + "." + template)

        return (templateList, nameList)
    except :
        logger.error("run request exception: %s" % (traceback.format_exc()))
        return (None, None)

def getTemplatePrams(cpsServerUrl, service ,template, commitSate):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/services/%s/componenttemplates/%s/params?commit_state=%s" % (cpsServerUrl, service, template, commitSate)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return None
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
        body = json.loads(res.text)

        if type(body['cfg']) == types.DictType:
            body.update(body['cfg'])
            body.pop('cfg')
        else:
            body = {}
        return body
    except :
        logger.error("run request :%s, method:%s, exception: %s" % (url, method, traceback.format_exc()))
        return None


def getControlHostList(cpsServerUrl):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hosts" % (cpsServerUrl)
    controlHostList = []
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return (None, None)
        logger.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))

        data = json.loads(res.text)["hosts"]
        for item in data:
            roles = item["roles"]
            hostid = item["id"]
            if DiskConstant.API_SERVER_NAME in roles:
                controlHostList.append(hostid)
        return controlHostList
    except :
        logger.error("run request exception: %s" % (traceback.format_exc()))
        return None

def getStorageGroupList(cpsServerUrl):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/storage?commit_state=uncommit" % (cpsServerUrl)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, kwargs, res.text))
            return None
        logger.info("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, kwargs, res.text))

        return json.loads(res.text)["hostcfg"]
    except :
        logger.error("run request :%s, method:%s, data:%s, exception: %s" % (url, method, kwargs, traceback.format_exc()))
        return None


def getStorageGroupDetail(cpsServerUrl, group_name):
    method = "GET"
    kwargs = {'headers': {"Content-type": "application/json"}}
    kwargs['verify'] = False
    url = "%s/cps/v1/hostcfg/storage/types/%s?commit_state=uncommit" % (cpsServerUrl, group_name)
    try:
        res = cps_server.rest_cps_execute(method, url, **kwargs)

        if (res.status_code < 200 or res.status_code >= 300):
            logger.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, kwargs, res.text))
            return None

        logger.info("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, kwargs, res.text))
        return json.loads(res.text)
    except :
        logger.error("run request :%s, method:%s, data:%s, exception: %s" % (url, method, kwargs, traceback.format_exc()))
        return None

def getSaveOption():
    while 1:
        input_str = "Do you want to save this configuration?[y|n][y]"
        flag = raw_input(input_str)
        if flag not in ["y", "n", ""]:
            print 'Please input correct information.'
            continue

        if flag == "n":
            return False
        else :
            return True
