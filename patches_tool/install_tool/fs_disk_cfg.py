#!/usr/bin/env python
# coding:utf-8
# Helper functions for the CPS client.

import sys
import json
import os
import ConfigParser
import time
import traceback
import copy
from os.path import join
from fs_disk_constant import DiskConstant
import fs_change_util
import fs_log_util
import cps_server
import fsCpsCliOpt as cliopt
import fsutils as utils
import fs_system_server
from print_msg import PrintMessage as PrintUtil

LOG_FILE = DiskConstant.LOG_FILE
logger = fs_log_util.localLog.get_logger(LOG_FILE)


class FSdiskOptConfig():
    def __init__(self):
        self.dangerous_message = "\033[1;31m%s\033[0m" % "Reducing service logical volume is dangerous " \
                                 "and it may not take effect."
        self.repository_store_size = DiskConstant.REPOSITOR_STORE_SIZE_VALUE
        self.ceilometer_data = DiskConstant.CEILOMETER_DATA_VALUE
        self.compute_image_cache = DiskConstant.COMPUTE_IMAGE_CACHE_VALUE
        self.control_image_cache = DiskConstant.COMPUTE_IMAGE_CACHE_VALUE
        self.backup_store_size = DiskConstant.BAKCUP_STORE_SIEZE_VALUE
        self.url = cps_server.get_cpsserver_url()
        self.isolate_host_list = []
        self.storage_control_group_list = []
        self.storage_compute_group_list = []

        #用于保存从zookeeper中 获取到的各个逻辑卷的最大值，
        #(作用，如果当前配置找不到相关的配置文件 则使用从zookeeper中获取的数据)
        self.repository_store_max_size = None
        self.ceilometer_data_max_size = None
        self.compute_image_cache_max_size = None
        self.control_image_cache_max_size = None
        self.backup_store_max_size = None

        # 这个control_host 需要特殊获取
        self.control_host = []
        self.compute_host = []
        self.StorageCroupInfo = {}
        self.controlGroupInfo = {}
        self.computeGroupInfo = {}
        self.default = DiskConstant.DISK_INI_PATH
        self.storageEffect = DiskConstant.STORAGE_EFFECT

        deployFile = join(DiskConstant.CURRENT_PATH, 'deployEnv.ini')
        if os.path.exists(deployFile):
            try:
                cpsconfig = ConfigParser.RawConfigParser()
                cpsconfig.read(deployFile)
                sectionList = cpsconfig.sections()
                for item in sectionList:
                    if item.find("deploycfg") is not -1:
                        deploy = dict(cpsconfig.items(item))
                        self.ceilometer_data = deploy.get("ceilometer_data")
                        self.compute_image_cache = deploy.get("compute_image_cache")
                        self.control_image_cache = deploy.get("compute_image_cache")
                        self.repository_store_size = deploy.get("repository_store_size")
                        self.backup_store_size = deploy.get("backup_store_size")
                        if self.backup_store_size is None:
                            self.backup_store_size = "20G"
            except :
                print ''

        if os.path.exists(DiskConstant.DEFUALT_SYS_PATH):
            self.__need_init()

    def __need_init(self):
        #glance相关的配置信息

        #尝试从default.ini取到前一次的配置信息，取失败或者没有继续使用生效的数据,防止分组数据丢失
        if os.path.exists(DiskConstant.DISK_INI_PATH):
            if not self.parseConfigInfoFromFile(DiskConstant.DISK_INI_PATH):
                self.parseConfigInfoFromFile(DiskConstant.STORAGE_EFFECT)
        elif os.path.exists(DiskConstant.STORAGE_EFFECT):
            self.parseConfigInfoFromFile(DiskConstant.STORAGE_EFFECT)

        #尝试做到 ，全部由zookeeper中的数据来进行恢复
        #1 部署了 api-server角色的节点为控制节点(后续再考虑)cliopt.getControlHostList(self.url)
        lst_allhostid, allhostsip = cps_server.get_all_hosts()

        self.control_host = json.loads(fs_system_server.system_get_ctrl_hosts())
        logger.info("DISK:control_host = %s " %self.control_host)
        (storage_control_group_list, storage_compute_group_list, isolate_host_list) = self.get_hostcfg_summany(self.control_host)
        logger.info("DISK:storage_control_group_list = %s " %storage_control_group_list)
        logger.info("DISK:storage_compute_group_list = %s " %storage_compute_group_list)
        logger.info("DISK:isolate_host_list = %s " %isolate_host_list)
        #2 获取所有的配置主机信息
        # 填充一些额外的信息,group的pci信息
        self.storage_control_group_list = storage_control_group_list
        self.storage_compute_group_list = storage_compute_group_list
        self.isolate_host_list = isolate_host_list
        self.get_hostcfg_extra_info(self.storage_control_group_list)
        self.get_hostcfg_extra_info(self.storage_compute_group_list)

        logger.info("DISK:storage_control_group_list = %s " %storage_control_group_list)
        self.controlGroupInfo = self.bulidStorageInfo(storage_control_group_list, {})
        logger.info("DISK:controlGroupInfo = %s " %self.controlGroupInfo)
        self.computeGroupInfo = self.bulidStorageInfo(storage_compute_group_list, {})
        logger.info("DISK:computeGroupInfo = %s " %self.computeGroupInfo)

        #这个主要是防止直接走生效，直接走配置，导致分组信息没有生成
        self.generate_storage_groups(self.url, lst_allhostid, self.control_host, self.isolate_host_list)
        self.compute_host = list(set(lst_allhostid) - set(self.control_host))

        logger.info("DISK:controlGroupInfo = %s " %self.controlGroupInfo)
        logger.info("DISK:computeGroupInfo = %s " %self.computeGroupInfo)

        self.change_logical_size_from_zookeeper()


    def change_logical_size_from_zookeeper(self):
        #如果建议数据都直接从zookeeper上获取，可以防止，多个单板都有配置文件残留
        #所以始终以zookeeper上生效的最大数据为准
        is_size_change = False

        if self.repository_store_max_size is not None:
            if self.repository_store_size != self.repository_store_max_size:
                self.repository_store_size = self.repository_store_max_size
                is_size_change = True
        if self.control_image_cache_max_size is not None:
            if self.control_image_cache != self.control_image_cache_max_size:
                self.control_image_cache = self.control_image_cache_max_size
                is_size_change = True
        if self.compute_image_cache_max_size is not None:
            if self.compute_image_cache != self.compute_image_cache_max_size:
                self.compute_image_cache = self.compute_image_cache_max_size
                is_size_change = True
        if self.ceilometer_data_max_size is not None:
            if self.ceilometer_data != self.ceilometer_data_max_size:
                self.ceilometer_data = self.ceilometer_data_max_size
                is_size_change = True
        if self.backup_store_max_size is not None:
            if self.backup_store_size != self.backup_store_max_size:
                self.backup_store_size = self.backup_store_max_size
                is_size_change = True

        if is_size_change:
            self.__saveToConfigInfoToFile(DiskConstant.DISK_INI_PATH)

        logger.info("DISK: repository max=%s,real=%s " % (self.repository_store_max_size, self.repository_store_size))
        logger.info("DISK: ceilometer max=%s,real=%s " % (self.ceilometer_data_max_size, self.ceilometer_data))
        logger.info("DISK: compute_image max=%s,real=%s " % (self.compute_image_cache_max_size, self.compute_image_cache))
        logger.info("DISK: control_image max=%s,real=%s " % (self.control_image_cache_max_size,self.control_image_cache))
        logger.info("DISK: backup_store max=%s,real=%s " % (self.backup_store_max_size, self.backup_store_size))


    def get_hostcfg_summany(self, control_host):
        """
        获取磁盘所有的分组信息
        """
        storage_control_group_list = []
        storage_compute_group_list = []
        storage_control_groupName_list = []
        storage_compute_groupName_list = []
        all_group = []
        isolate_host_list = []
        lst_allhostid, allhostsip = cps_server.get_all_hosts()
        group_list = self.get_storage_hostcfg_list()
        for one_group in group_list:
            groupName = one_group["name"]
            if "default" == groupName:
                continue
            group_detail = self.get_storage_hostcfg_detail(groupName)

            all_group.append(group_detail)
            if groupName.find(DiskConstant.CONTROL_GROUP) is not -1 :
                storage_control_group_list.append(group_detail)
                #获取 控制节点中关于 switf image ceilometer-data backup 的分区大小，支持一键式脚本在其他单板操作
                self.get_all_logical_volume_max_size(group_detail, DiskConstant.CONTROL_GROUP)
                storage_control_groupName_list.append(groupName)
            elif groupName.find(DiskConstant.COMPUTE_GROUP) is not -1 :
                #获取 计算节点中关于 image 的分区大小，支持一键式脚本在其他单板操作
                self.get_all_logical_volume_max_size(group_detail, DiskConstant.COMPUTE_GROUP)
                storage_compute_group_list.append(group_detail)
                storage_compute_groupName_list.append(groupName)

        # 找出还没有配置到group的hostid
        for one_host_id in lst_allhostid:
            if self.is_host_in_group(one_host_id, all_group) is False:
                isolate_host_list.append(one_host_id)

        #组装 isolate相关的配置,对 控制节点进行特殊操作，如果是新增的，则直接创建一个新的组，
        #控制节点可以后续进行分组，因为控制节点比较少
        removeList = []
        for hostid in  isolate_host_list:
            if hostid in control_host:
                #生成相关的配置信息
                data = {}
                index_start = 1
                removeList.append(hostid)
                if len(storage_control_groupName_list) == 0:
                    continue

                index_start = int(max(storage_control_groupName_list).strip(DiskConstant.CONTROL_GROUP)) + 1

                newGroupName = DiskConstant.CONTROL_GROUP + "%s"%index_start
                data = {"type":"storage", "hosts":{"hostid":[hostid]}, "name" : newGroupName}
                storage_control_group_list.append(data)
                storage_control_groupName_list.append(newGroupName)

        isolate_host_list = list(set(isolate_host_list) - set(removeList))

        return (storage_control_group_list, storage_compute_group_list, isolate_host_list)

    def get_all_logical_volume_max_size(self, group_detail, groupType):
        #获取 控制节点中关于 switf image ceilometer-data backup 的分区大小
        #获取 计算节点中关于 image 的分区大小，支持一键式脚本在其他单板操作

        #1 先判断group_detail 是否合法
        if not self.hostcfg_has_host(group_detail):
            logger.info("get_all_logical_volume_max_size group_detail hostcfg has not host.")
            return
        if not group_detail.has_key(DiskConstant.LOGICAL_VOLUME):
            logger.info("get_all_logical_volume_max_size group_detail hostcfg has not logical volume.")
            return

        logicalVolumeData = group_detail[DiskConstant.LOGICAL_VOLUME]

        if DiskConstant.CONTROL_GROUP == groupType:
            for item in logicalVolumeData:
                if not item.has_key(DiskConstant.NAME_KEY):
                    continue
                if  DiskConstant.SWIFT_NAME == item[DiskConstant.NAME_KEY]:
                    swiftSize = item[DiskConstant.SIZE_KEY]
                    self.repository_store_max_size = self.computeTheLargerSize(self.repository_store_max_size, swiftSize)
                    continue
                if DiskConstant.IMAGE_NAME == item[DiskConstant.NAME_KEY]:
                    imageSize = item[DiskConstant.SIZE_KEY]
                    self.control_image_cache_max_size = self.computeTheLargerSize(self.control_image_cache_max_size, imageSize)
                if DiskConstant.CEILOMETER_DATA_NAME == item[DiskConstant.NAME_KEY]:
                    ceilSize = item[DiskConstant.SIZE_KEY]
                    self.ceilometer_data_max_size = self.computeTheLargerSize(self.ceilometer_data_max_size, ceilSize)
                if DiskConstant.BACKUP_NAME == item[DiskConstant.NAME_KEY]:
                    backupSize = item[DiskConstant.SIZE_KEY]
                    self.backup_store_max_size = self.computeTheLargerSize(self.backup_store_max_size, backupSize)
        elif DiskConstant.COMPUTE_GROUP == groupType:
            for item in logicalVolumeData:
                if not item.has_key(DiskConstant.NAME_KEY):
                    continue
                if DiskConstant.IMAGE_NAME == item[DiskConstant.NAME_KEY]:
                    imageSize = item[DiskConstant.SIZE_KEY]
                    self.compute_image_cache_max_size = self.computeTheLargerSize(self.compute_image_cache_max_size, imageSize)

    def computeTheLargerSize(self, size1, size2):
        #判断2个size1 ,size2中哪个比较大，返回比较大的哪一个
        largeSize = size1
        if size1 is None:
            return size2.upper()

        try:
            tmp1 = int(size1.upper().replace('G', ''))
            tmp2 = int(size2.upper().replace('G', ''))
            if tmp1 > tmp2:
                largeSize = size1
            else:
                largeSize = size2
        except :
            logger.error("computeTheLargerSize failed. e:%s"%traceback.format_exc())

        return largeSize.upper()

    def compareTheLargerSize(self, size1, size2):
        #判断2个size1 ,size2中哪个比较大，返回比较大的哪一个
        # siz1 >= size2 return True
        try:
            tmp1 = int(size1.upper().replace('G', ''))
            tmp2 = int(size2.upper().replace('G', ''))
            if tmp1 > tmp2:
                print self.dangerous_message
                return False
            else:
                return True
        except :
            logger.error("compareTheLargerSize failed. e:%s"%traceback.format_exc())

        return False




    def get_storage_hostcfg_list(self):
        group_list = cliopt.getStorageGroupList(self.url)
        return group_list

    def get_storage_hostcfg_detail(self, group_name):
        group_detail = cliopt.getStorageGroupDetail(self.url, group_name)
        return group_detail

    def is_host_in_group(self, hostid, storage_group_list):
        for one_detail in storage_group_list:
            if one_detail["name"] == "default":
                continue

            if not one_detail.has_key("hosts"):
                continue

            host_sum = one_detail["hosts"]
            if not host_sum.has_key("hostid"):
                continue

            if hostid in one_detail["hosts"]["hostid"]:
                return True

        return False

    def get_hostcfg_extra_info(self, groupList):
        # 填充hostcfg的pci信息
        for one_hostcfg in groupList:
            if one_hostcfg["name"] == "default":
                continue

            if not self.hostcfg_has_host(one_hostcfg):
                continue

            one_host_id = one_hostcfg["hosts"]["hostid"][0]
            pci_info = self.get_host_pci_info_test(one_host_id)

            one_hostcfg["diskAll"] = pci_info

    def hostcfg_has_host(self, one_hostcfg):
        if not one_hostcfg.has_key("hosts"):
            return False

        host_sum = one_hostcfg["hosts"]
        if not host_sum.has_key("hostid"):
            return False

        return True

    def get_host_pci_info(self, hostid):
        host_detail = cps_server.get_host_detail_info(hostid)
        if  host_detail is None:
            return ["no-found"]
        host_ethinfo = host_detail['diskinfo']
        pci_list = []
        for dct_pci in host_ethinfo:
            str_pci_info = "%s=%s=%s" % (dct_pci["dev"],dct_pci["disk"],dct_pci["size"].strip("GB") + "g")
            pci_list.append(str_pci_info)
        return pci_list


    def get_host_pci_info_test(self, hostid):
        host_detail = cps_server.get_host_detail_info(hostid)
        if  host_detail is None:
            return ["no-found"]
        host_disk_info = host_detail['diskinfo']
        return host_disk_info

    def bulidStorageInfo(self, storage_control_group_list, controlGroupInfo = {}):
        def is_extend_disk(disk_info, path=None, pci_address=None,scsi_address=None):
            if (not path) and (not pci_address or not scsi_address) :
                logger.error("the input is null .")
                return False
            elif path:
                if disk_info.get('path', None) == path:
                    return True
            elif (pci_address and scsi_address):
                if disk_info.get("pci_address", '') == pci_address\
                    and disk_info.get("scsi_address", '') == scsi_address:
                    return True
            return False


        groupInfo = []

        for item in storage_control_group_list:
            groupName = item["name"]
            newItem = {}
            if not (item.has_key("hosts") and item["hosts"].has_key(DiskConstant.HOSTID_KEY)):
                if groupName.find(DiskConstant.CONTROL_GROUP) is not -1 or groupName.find(DiskConstant.COMPUTE_GROUP) is not -1 :
                    newItem[DiskConstant.GROUP_KEY ] = item["name"]
                    newItem[DiskConstant.HOSTID_KEY] = []
                    newItem[DiskConstant.DISK_KEY] = ["no-found"]
                    newItem[DiskConstant.EXTENDISK_KEY] = []
                    newItem[DiskConstant.REMOVEDISK_KEY] = []
                    newItem[DiskConstant.EXTENDISK_KEY] = []
                    groupInfo.append(newItem)
                continue

            allDisk = item["diskAll"]
            newItem[DiskConstant.GROUP_KEY ] = item["name"]
            newItem[DiskConstant.HOSTID_KEY] = item["hosts"][DiskConstant.HOSTID_KEY]
            newItem[DiskConstant.DISK_KEY] = allDisk
            newItem[DiskConstant.EXTENDISK_KEY] = []
            newItem[DiskConstant.REMOVEDISK_KEY] = []
            extendDisk = []

            if  item.has_key(DiskConstant.DISK_KEY):
                diskInfo = item[DiskConstant.DISK_KEY]
                for disk in diskInfo:
                    path = None
                    pci_address = None
                    scsi_address =None

                    if 'path' in disk:
                        diskName = disk["path"]
                        path = disk["path"]
                    elif 'disk_address' in disk:
                        disk_id = disk['disk_address']
                        pci_address = disk_id.get("pci_address", None)
                        scsi_address = disk_id.get("scsi_address", None)
                    else:
                        logger.error("disk = %s" % disk)
                        continue
                    logger.error("disk =%s." % (disk))
                    for tmp in allDisk:
                        if is_extend_disk(tmp, path, pci_address, scsi_address):
                            extendDisk.append(tmp)
            newItem[DiskConstant.EXTENDISK_KEY] = extendDisk
            groupInfo.append(newItem)

        return groupInfo

    def __get_ctrl_host(self):
        controlhost = []
        if os.path.exists(DiskConstant.DEFUALT_SYS_PATH):
            try:
                cpsconfig = ConfigParser.RawConfigParser()
                cpsconfig.read(DiskConstant.DEFUALT_SYS_PATH)
                sectionList = cpsconfig.sections()
                for item in sectionList:
                    if item.find("host_deploy") is not -1:
                        deploy = dict(cpsconfig.items(item))
                        controlhost = json.loads(deploy["ctrl_hosts"])
                        self.control_host = controlhost
                        return controlhost
            except :
                logger.error("__get_ctrl_host parse exception: %s" % (traceback.format_exc()))

        print "get ctrl host failed."
        logger.error("can not find controlhost.")
        sys.exit(1)


    def get_section_list(self):
        return [DiskConstant.STORAGE_SETCTION_KEY]


    def get_file_path(self):
        return DiskConstant.DISK_INI_PATH


    def getLogicalVolumeSie(self, type_name):
        if DiskConstant.TYPE_ONLY_DEPLOY != type_name:
            print ''
            PrintUtil.print_msg_by_index("1000003")
            print ""

        if DiskConstant.TYPE_ONLY_DEPLOY == type_name:
            logger.warning("getLogicalVolumeSie not need to config , type = %s." % DiskConstant.TYPE_ONLY_DEPLOY)
            return

        #由于uvp 不支持，当前暂时隐藏
        while 1:
            try:

                inputstr = PrintUtil.get_msg_by_index_ex("1000004", (self.repository_store_size))
                repository_store_size = raw_input(inputstr)
                if (repository_store_size == ""):
                    break
                else:
                    if not cliopt.checkSizeFormatIsCorrect(repository_store_size):
                        PrintUtil.print_msg_by_index("1000005")
                        time.sleep(1)
                        continue

                    repository_store_size = str(int(repository_store_size.replace('G', ''))) + 'G'
                    self.compareTheLargerSize(self.repository_store_size, repository_store_size)
                    self.repository_store_size = repository_store_size
                    break
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                PrintUtil.print_msg_by_index("1000005")

        while 1:
            try:
                control_image_cache = ""
                inputstr = PrintUtil.get_msg_by_index_ex("1000053", (self.control_image_cache))
                control_image_cache = raw_input(inputstr)
                if (control_image_cache == ""):
                    break
                else:
                    if not cliopt.checkSizeFormatIsCorrect(control_image_cache):
                        PrintUtil.print_msg_by_index("1000005")
                        time.sleep(1)
                        continue

                    control_image_cache = str(int(control_image_cache.replace('G', ''))) + 'G'
                    self.compareTheLargerSize(self.control_image_cache, control_image_cache)
                    self.control_image_cache = control_image_cache
                    break
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                PrintUtil.print_msg_by_index("1000005")
                time.sleep(1)

        while 1:
            try:
                compute_image_cache = ""
                inputstr = PrintUtil.get_msg_by_index_ex("1000054", (self.compute_image_cache))
                compute_image_cache = raw_input(inputstr)
                if (compute_image_cache == ""):
                    break
                else:
                    if not cliopt.checkSizeFormatIsCorrect(compute_image_cache):
                        PrintUtil.print_msg_by_index("1000005")
                        time.sleep(1)
                        continue

                    compute_image_cache = str(int(compute_image_cache.replace('G', ''))) + 'G'
                    self.compareTheLargerSize(self.compute_image_cache, compute_image_cache)
                    self.compute_image_cache = compute_image_cache
                    break
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                PrintUtil.print_msg_by_index("1000005")
                time.sleep(1)

        ceilometer_data = ""
        while 1:
            try:
                inputstr = PrintUtil.get_msg_by_index_ex("1000012", (self.ceilometer_data))
                ceilometer_data = raw_input(inputstr)
                if (ceilometer_data == ""):
                    ceilometer_data = self.ceilometer_data
                    break
                else:
                    if not cliopt.checkSizeFormatIsCorrect(ceilometer_data):
                        PrintUtil.print_msg_by_index("1000005")
                        time.sleep(1)
                        continue

                    ceilometer_data = str(int(ceilometer_data.replace('G', ''))) + 'G'
                    self.compareTheLargerSize(self.ceilometer_data, ceilometer_data)
                    self.ceilometer_data = ceilometer_data
                    break
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                PrintUtil.print_msg_by_index("1000005")
                time.sleep(1)

        #set backup storage size
        while 1:
            try:
                inputstr = PrintUtil.get_msg_by_index_ex("1000056", self.backup_store_size)
                backup_size = raw_input(inputstr)
                if (backup_size == ""):
                    backup_size = self.backup_store_size
                    break
                else:
                    if not cliopt.checkSizeFormatIsCorrect(backup_size):
                        PrintUtil.print_msg_by_index("1000005")
                        time.sleep(1)
                        continue
                    backup_size = str(int(backup_size.replace('G', ''))) + 'G'
                    self.compareTheLargerSize(self.backup_store_size, backup_size)
                    self.backup_store_size = backup_size
                    break
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                PrintUtil.print_msg_by_index("1000005")
                time.sleep(1)

        print ""
        PrintUtil.print_msg_by_index("1000017")

    def _extendDiskToHostByUserChoice(self, storageGroup, group):
        PrintUtil.print_msg_by_index_ex("1000019", (group))
        newStorageCroupInfo = copy.deepcopy(storageGroup)

        choose = cliopt.getChooseYN()
        if "n" == choose:
            return newStorageCroupInfo

        groupList = []
        for item in newStorageCroupInfo:
            groupList.append(item[DiskConstant.GROUP_KEY])

        while (1):
            inputstr = PrintUtil.get_msg_by_index("1000018")
            choice = raw_input(inputstr)
            choice = choice.strip()
            if "" == choice:
                break

            if choice not in groupList:
                PrintUtil.print_msg_by_index("1000002")
                continue

            groupInfo = {}
            for item in newStorageCroupInfo:
                if choice == item[DiskConstant.GROUP_KEY]:
                    groupInfo = item
                    break

            tmp = [groupInfo]
            print ''
            PrintUtil.print_msg_by_index("1000000")
            print ''

            PrintUtil.print_msg_by_index_ex("1000020", (choice))

            utils.print_list(self.__buildControlLogicalVolumeInfo(tmp, group), DiskConstant.PRINT_LIST, {}, 25)
            diskInfo = item[DiskConstant.DISK_KEY]

            #diskInfo 需要过滤掉系统盘
            diskExceSys = []
            devList = []
            for disk in diskInfo:
                devList.append(disk.split("=")[0])
            devList.sort()
            sysDev = devList[0]

            for disk in diskInfo:
                if disk.split("=")[0] != sysDev:
                    diskExceSys.append(disk)

            removeDisk = item[DiskConstant.REMOVEDISK_KEY]
            extendDisk = item[DiskConstant.EXTENDISK_KEY]
            diskExceSys.sort()

            addflag = False
            print ''
            for diskitem in diskExceSys:
                if diskitem in extendDisk:
                    continue
                PrintUtil.print_msg_by_index_ex("1000021", (diskitem, choice))
                choose = cliopt.getChooseYN()
                if "n" == choose:
                    continue
                addflag = True
                if diskitem not in extendDisk:
                    extendDisk.append(diskitem)
                if diskitem in removeDisk:
                    removeDisk.remove(diskitem)
            item[DiskConstant.EXTENDISK_KEY] = extendDisk

            if addflag :
                PrintUtil.print_msg_by_index_ex("1000022", (choice))
                utils.print_list(self.__buildControlLogicalVolumeInfo([item], group), DiskConstant.PRINT_LIST, {}, 25)
            else:
                print "Now new '%s' hostcfg information does not change." %choice

        return newStorageCroupInfo

    def __buildControlLogicalVolumeInfo(self, group, group_type):
        logicalVolume = []
        if group_type == DiskConstant.CONTROL_HOST_TYPE:
            logicalVolume = ["image=%s" % self.control_image_cache, "swift=%s" % self.repository_store_size,
                             "ceilometer-data=%s" % self.ceilometer_data, "backup=%s" % self.backup_store_size]
        elif group_type == DiskConstant.COMPUTE_HOST_TYPE:
            logicalVolume = ["image=%s" % self.compute_image_cache]

        newGroup = copy.deepcopy(group)
        for item in newGroup:
            item[DiskConstant.LOGICAL_VOLUME] = logicalVolume
        return newGroup

    def __extendALLGroupTypeDistToHost(self, controlGroup, computeGroup):
        print ''
        PrintUtil.print_msg_by_index("1000023")
        PrintUtil.print_msg_by_index("1000024")

        choose = cliopt.getChooseYN()
        if "n" == choose:
            print ''
            return (controlGroup, computeGroup)

        print ''
        PrintUtil.print_msg_by_index("1000025")
        PrintUtil.print_msg_by_index("1000026")

        utils.print_list(self.__buildControlLogicalVolumeInfo(controlGroup, DiskConstant.CONTROL_HOST_TYPE),
                         DiskConstant.PRINT_LIST, {}, 25)
        newControlStorageCroupInfo = self._extendDiskToHostByUserChoice(controlGroup, DiskConstant.CONTROL_HOST_TYPE)

        PrintUtil.print_msg_by_index("1000027")

        print ''
        PrintUtil.print_msg_by_index("1000028")
        PrintUtil.print_msg_by_index("1000029")
        utils.print_list(self.__buildControlLogicalVolumeInfo(computeGroup, DiskConstant.COMPUTE_HOST_TYPE),
                         DiskConstant.PRINT_LIST, {}, 25)
        newComputeStorageCroupInfo = self._extendDiskToHostByUserChoice(computeGroup, DiskConstant.COMPUTE_HOST_TYPE)

        PrintUtil.print_msg_by_index("1000030")
        print ''

        return (newControlStorageCroupInfo, newComputeStorageCroupInfo)

    def __removeALLGroupTypeDistToHost(self, controlGroup, computeGroup):
        self.controlGroupInfo = controlGroup
        self.computeGroupInfo = computeGroup
        print ''
        PrintUtil.print_msg_by_index("1000031")
        PrintUtil.print_msg_by_index("1000032")
        choose = cliopt.getChooseYN()
        if "n" == choose:
            print ''
            return (controlGroup, computeGroup)

        print ''
        PrintUtil.print_msg_by_index("1000025")
        PrintUtil.print_msg_by_index("1000026")
        utils.print_list(self.__buildControlLogicalVolumeInfo(controlGroup, DiskConstant.CONTROL_HOST_TYPE),
                         DiskConstant.PRINT_LIST, {}, 25)
        newControlStorageCroupInfo = self.__removeDiskFromHostByUserChoice(controlGroup, DiskConstant.CONTROL_HOST_TYPE)

        PrintUtil.print_msg_by_index("1000027")

        print ''
        PrintUtil.print_msg_by_index("1000028")
        PrintUtil.print_msg_by_index("1000029")
        utils.print_list(self.__buildControlLogicalVolumeInfo(computeGroup, DiskConstant.COMPUTE_HOST_TYPE),
                         DiskConstant.PRINT_LIST, {}, 25)
        newComputeStorageCroupInfo = self.__removeDiskFromHostByUserChoice(computeGroup, DiskConstant.COMPUTE_HOST_TYPE)

        PrintUtil.print_msg_by_index("1000030")
        print ''

        return (newControlStorageCroupInfo, newComputeStorageCroupInfo)

    def __removeDiskFromHostByUserChoice(self, storageGroup, group):
        PrintUtil.print_msg_by_index_ex("1000033", (group))
        newStorageCroupInfo = copy.deepcopy(storageGroup)

        choose = cliopt.getChooseYN()
        if "n" == choose:
            return newStorageCroupInfo

        groupList = []
        for item in newStorageCroupInfo:
            groupList.append(item[DiskConstant.GROUP_KEY])

        while (1):
            inputstr = PrintUtil.get_msg_by_index("1000034")
            choice = raw_input(inputstr)

            if "" == choice:
                break
            choice = choice.strip()
            if choice not in groupList:
                PrintUtil.print_msg_by_index("1000002")
                continue

            groupInfo = {}
            for item in newStorageCroupInfo:
                if choice == item[DiskConstant.GROUP_KEY]:
                    groupInfo = item
                    break

            tmp = [groupInfo]
            print ''
            PrintUtil.print_msg_by_index("1000000")
            print ''
            PrintUtil.print_msg_by_index_ex("1000020", (choice))
            utils.print_list(self.__buildControlLogicalVolumeInfo(tmp, group), DiskConstant.PRINT_LIST, {}, 25)

            removeDisk = item[DiskConstant.REMOVEDISK_KEY]
            addDiskInfo = item[DiskConstant.EXTENDISK_KEY]
            print ''
            remove_flag = False
            for diskitem in addDiskInfo:

                PrintUtil.print_msg_by_index_ex("1000035", (diskitem, choice))
                choose = cliopt.getChooseYN()
                if "n" == choose:
                    continue
                remove_flag = True
                removeDisk.append(diskitem)
                #删除需要从 add 的信息中删除
                addDiskInfo.remove(diskitem)
            item[DiskConstant.REMOVEDISK_KEY] = removeDisk

            if remove_flag :
                PrintUtil.print_msg_by_index_ex("1000022", choice)
                utils.print_list(self.__buildControlLogicalVolumeInfo([item], group), DiskConstant.PRINT_LIST, {}, 25)
            else:
                print "Now new '%s' hostcfg information does not change." %choice

        return newStorageCroupInfo

    def setControlGroup(self, controlhost):
        self.control_host = controlhost

    def getControlGroup(self):
        return self.control_host

    def setComputeGroup(self, lst_cmp_host):
        self.compute_host = lst_cmp_host

    def getComputeGroup(self):
        return self.compute_host

    def __saveToConfigInfoToFile(self, deployFile):
        cpsconfig = ConfigParser.RawConfigParser()
        cpsconfig.read(deployFile)
        sectionList = cpsconfig.sections()
        if DiskConstant.STORAGE_SETCTION_KEY not in sectionList:
            cpsconfig.add_section(DiskConstant.STORAGE_SETCTION_KEY)

        cpsconfig.set(DiskConstant.STORAGE_SETCTION_KEY, DiskConstant.CONTROL_HOST, json.dumps(self.control_host))
        cpsconfig.set(DiskConstant.STORAGE_SETCTION_KEY, DiskConstant.REPOSITOR_STORE_SIZE, self.repository_store_size)
        cpsconfig.set(DiskConstant.STORAGE_SETCTION_KEY, DiskConstant.CEILOMETER_DATA, self.ceilometer_data)
        cpsconfig.set(DiskConstant.STORAGE_SETCTION_KEY, DiskConstant.COMPUTE_IMAGE_CACHE, self.compute_image_cache)
        cpsconfig.set(DiskConstant.STORAGE_SETCTION_KEY, DiskConstant.CONTROL_IMAGE_CACHE, self.control_image_cache)
        cpsconfig.set(DiskConstant.STORAGE_SETCTION_KEY, DiskConstant.BACKUP_STORE_SIZE, self.backup_store_size)

        cpsconfig.write(open(deployFile, "w"))

    def parseConfigInfoFromFile(self, fileName):
        logger.error('begin to parse. %s ' % fileName)
        try:
            cpsconfig = ConfigParser.RawConfigParser()
            cpsconfig.read(fileName)
            sectionList = cpsconfig.sections()

            #自己生效的文件中是没有相关的配置信息的 DiskConstant.HOST_SECTION_KEY
            self.control_host = json.loads(fs_system_server.system_get_ctrl_hosts())

            if DiskConstant.STORAGE_SETCTION_KEY not in sectionList:
                logger.error("not found storage info.")
                return False

            self.repository_store_size = cpsconfig.get(DiskConstant.STORAGE_SETCTION_KEY,
                                                       DiskConstant.REPOSITOR_STORE_SIZE)
            self.ceilometer_data = cpsconfig.get(DiskConstant.STORAGE_SETCTION_KEY, DiskConstant.CEILOMETER_DATA)
            self.compute_image_cache = cpsconfig.get(DiskConstant.STORAGE_SETCTION_KEY,
                                                     DiskConstant.COMPUTE_IMAGE_CACHE)
            self.control_image_cache = cpsconfig.get(DiskConstant.STORAGE_SETCTION_KEY,
                                                     DiskConstant.CONTROL_IMAGE_CACHE)

            #backup size
            try:
                self.backup_store_size = cpsconfig.get(DiskConstant.STORAGE_SETCTION_KEY, DiskConstant.BACKUP_STORE_SIZE)
            except Exception,e:
                logger.error("can't find backup storage size,default 20G,e:%s."%e)
                self.backup_store_size = "20G"

            return True
        except:
            logger.error("parse exception: %s" % (traceback.format_exc()))
            logger.error(traceback.format_exc())
            return False

    def getPciByDiskInfo(self, pciInfo):

        return pciInfo.split('=')[1]

    def detPicDevNameByDiskInfo(self, pciInfo):
        return pciInfo.split('=')[0]

    def createControlStorageHostcfg(self, url, item):
        # create for controller host
        hostids = item[DiskConstant.HOSTID_KEY]
        group = item[DiskConstant.GROUP_KEY]
        extendisk = []
        removedisk = []   #需要增加删除 disk的操作
        if item.has_key(DiskConstant.EXTENDISK_KEY):
            extendisk = item[DiskConstant.EXTENDISK_KEY]
        if item.has_key(DiskConstant.REMOVEDISK_KEY):
            removedisk = item[DiskConstant.REMOVEDISK_KEY]

        bRet = cliopt.storHostcfgAdd(group, url)
        if not bRet:
            logger.error("fail to storHostcfgAdd, str_hostcfg_name:%s" % group)
            return False

        for str_pci in removedisk:
            pci = self.getPciByDiskInfo(str_pci)
            dev = self.detPicDevNameByDiskInfo(str_pci)
            if not cliopt.diskCheckAndDel(group, dev, pci, self.url):
                logger.error("fail to remove disk, str_hostcfg_name:%s, partname:%s, str_pci:%s" % (group, dev, pci))
                return False

        for str_pci in extendisk:
            pci = self.getPciByDiskInfo(str_pci)
            dev = self.detPicDevNameByDiskInfo(str_pci)
            if not cliopt.diskadd(group, dev, pci, 'all', self.url):
                logger.error("fail to diskadd, str_hostcfg_name:%s, partname:%s, str_pci:%s" % (group, dev, pci))
                return False

            if not cliopt.addDisk2Vg(group, dev, self.url):
                logger.error("fail to addDisk2Vg, str_hostcfg_name:%s, partname:%s" % (group, dev))
                return False

        #hostids 这个节点可能已经被删除了，需要过滤
        allhosts, allhostsip = cps_server.get_all_hosts()
        removeList = []
        for hostid in hostids:
            if hostid not in allhosts:
                removeList.append(hostid)
                logger.info('Remove hostid = %s.allhostsip =%s.' % (removeList, allhostsip))

        hostids = list(set(hostids) - set(removeList))
        if len(hostids) == 0:
            return True

        bRet = cliopt.hostcfg_host_add(hostids, "storage", group, self.url)
        if not bRet:
            logger.error("fail to hostcfg_host_add, lst_ctrl_hosts:%s, str_hostcfg_name:%s" % (hostids, group))
            return False

        cps_server.cps_commit()
        
        bRet = cliopt.lvUpdate(group, "swift", self.repository_store_size.lower(), self.url)
        if not bRet:
            logger.error("fail to lvAdd, swift")
            return False

        bRet = cliopt.lvUpdate(group, "image", self.control_image_cache.lower(), self.url)
        if not bRet:
            logger.error("fail to lvAdd, compute_image_cache")
            return False

        bRet = cliopt.lvUpdate(group, "ceilometer-data", self.ceilometer_data.lower(), self.url)
        if not bRet:
            logger.error("fail to lvAdd, ceilometer-data")
            return False

        #创建备份分区
        bRet = cliopt.lvUpdate(group, "backup", self.backup_store_size.lower(), self.url)
        if not bRet:
            logger.error("fail to lvAdd, backup")
            return False

        return True

    def createComputeStorageHostcfg(self, url, item):
        hostids = item[DiskConstant.HOSTID_KEY]
        group = item[DiskConstant.GROUP_KEY]
        extendisk = []
        removedisk = []
        if item.has_key(DiskConstant.EXTENDISK_KEY):
            extendisk = item[DiskConstant.EXTENDISK_KEY]
        if item.has_key(DiskConstant.REMOVEDISK_KEY):
            removedisk = item[DiskConstant.REMOVEDISK_KEY]

        bRet = cliopt.storHostcfgAdd(group, url)
        if not bRet:
            logger.error("fail to storHostcfgAdd, str_hostcfg_name:%s" % group)
            return False

        cps_server.cps_commit()
        
        for str_pci in removedisk:
            pci = self.getPciByDiskInfo(str_pci)
            dev = self.detPicDevNameByDiskInfo(str_pci)
            if not cliopt.diskCheckAndDel(group, dev, pci, self.url):
                logger.error("fail to remove disk, str_hostcfg_name:%s, partname:%s, str_pci:%s" % (group, pci, pci))
                return False

        for str_pci in extendisk:
            pci = self.getPciByDiskInfo(str_pci)
            dev = self.detPicDevNameByDiskInfo(str_pci)
            if not cliopt.diskadd(group, dev, pci, 'all', self.url):
                logger.error("fail to diskadd, str_hostcfg_name:%s, partname:%s, str_pci:%s" % (group, dev, pci))
                return False

            if not cliopt.addDisk2Vg(group, dev, self.url):
                logger.error("fail to addDisk2Vg, str_hostcfg_name:%s, partname:%s" % (group, dev))
                return False

        bRet = cliopt.lvUpdate(group, "image", self.compute_image_cache.lower(), self.url)
        if not bRet:
            logger.error("fail to lvAdd, compute_image_cache")
            return False

        #hostids 这个节点可能已经被删除了，需要过滤
        allhosts, allhostsip = cps_server.get_all_hosts()
        removeList = []
        for hostid in hostids:
            if hostid not in allhosts:
                removeList.append(hostid)
                logger.info('Remove hostid = %s allhostsip = %s..' % (removeList, allhostsip))

        hostids = list(set(hostids) - set(removeList))
        if len(hostids) == 0:
            return True

        bRet = cliopt.hostcfg_host_add(hostids, "storage", group, self.url)
        if not bRet:
            logger.error("fail to hostcfg_host_add, lst_ctrl_hosts:%s, str_hostcfg_name:%s" % (hostids, group))
            return False

        return True

    def beginToConfigByFile(self):
        logger.debug('begin to effect config control host= %s' % self.control_host)
        for item in self.StorageCroupInfo:
            hostid = item[DiskConstant.HOSTID_KEY]
            group = item[DiskConstant.GROUP_KEY]

            if hostid in self.control_host:
                self.createControlStorageHostcfg(self.url, item)
            else:
                self.createComputeStorageHostcfg(self.url, item)

        return True

    def beginToConfigByFileByPciType(self):
        logger.debug('begin to config by file by pci type.')

        if not os.path.exists(self.default):
            logger.error('default file not exist.')
            sys.exit(1)

        pre_env = os.getenv("PREINSTALL")

        for item in self.controlGroupInfo:
            group = item[DiskConstant.GROUP_KEY]
            if not self.createControlStorageHostcfg(self.url, item):
                print "create '%s' storage configuration failed. " % (group)
                if pre_env is not None:
                    logger.error("create '%s' storage configuration failed. "
                                 % (group))
                    sys.exit(1)

        for item in self.computeGroupInfo:
            group = item[DiskConstant.GROUP_KEY]

            if not self.createComputeStorageHostcfg(self.url, item):
                print "create '%s' storage configuration failed. " % (group)
                if pre_env is not None:
                    logger.error("create '%s' storage configuration failed. "
                                 % (group))
                    sys.exit(1)

        self.__saveToConfigInfoToFile(self.storageEffect)

        return True

    def generate_storage_groups(self, url, allhosts, lst_ctrl_host, extend_host):
        #什么信息都没有 从来都没生效过
        if len(self.controlGroupInfo) == 0:
            newAllHosts = list(set(allhosts) | set(extend_host))
            (controlGroup, computeGroup) = cliopt.generate_storage_groups_by_pci_Type(url, newAllHosts, lst_ctrl_host)
            self.controlGroupInfo = controlGroup
            self.computeGroupInfo = computeGroup
            self.control_host = lst_ctrl_host
            self.compute_host = list(set(newAllHosts) - set(lst_ctrl_host))
        else:
            logger.info('extend host mode. extend_host = %s' % extend_host)
            #需要重新生成 新的 compute group信息
            if len(extend_host) != 0:
                self.compute_host = list(set(allhosts) - set(lst_ctrl_host))
                self.computeGroupInfo = cliopt.generate_storage_groups_by_extend_host(url, self.computeGroupInfo,
                                                                                      extend_host,
                                                                                      DiskConstant.COMPUTE_GROUP)

    def extendorRemoveALLGroupTypeDistToHost(self, type_name, url, allhosts, lst_ctrl_host, extend_host):
        print ''
        self.generate_storage_groups(url, allhosts, lst_ctrl_host, extend_host)

        if DiskConstant.TYPE_ONLY_DEPLOY == type_name:
            logger.info(
                "extendorRemoveALLGroupTypeDistToHost not need to config , type = %s." % DiskConstant.TYPE_ONLY_DEPLOY)
            self.__saveToConfigInfoToFile(self.default)
            return True

        while (1):
            PrintUtil.print_msg_by_index("1000037")
            print ""
            PrintUtil.print_msg_by_index("1000038")

            PrintUtil.print_msg_by_index("1000048")
            PrintUtil.print_msg_by_index("1000049")
            PrintUtil.print_msg_by_index("1000047")
            chooseType = ["1", "2", "s"]
            choose = cliopt.makeChooseByYourselfReverse(chooseType, "s")
            if "s" == choose:
                print ''
                break
            elif "1" == choose:
                (self.controlGroupInfo, self.computeGroupInfo) = self.__extendALLGroupTypeDistToHost(
                    self.controlGroupInfo, self.computeGroupInfo)

            elif "2" == choose:
                (self.controlGroupInfo, self.computeGroupInfo) = self.__removeALLGroupTypeDistToHost(
                    self.controlGroupInfo, self.computeGroupInfo)

        print ""
        PrintUtil.print_msg_by_index("1000039")

        self.__saveToConfigInfoToFile(self.default)
        return True


    def get_group_host_list(self, group):
        hosts_list = []
        for group_item in group:
            if group_item.has_key(DiskConstant.HOSTID_KEY):
                group_host_list = group_item[DiskConstant.HOSTID_KEY]
                for host_id in group_host_list:
                    if host_id not in hosts_list:
                        hosts_list.append(host_id)

        return hosts_list



    def checkAllHostCfgIsActive(self):
        "最好 再检查一下 磁盘的大小是否生效，当前尚未做到。"
        logger.debug("begin to checkAllHostCfgIsActive.")

        ctrl_hosts = self.get_group_host_list(self.controlGroupInfo)
        logger.info("DISK:checkAllHostCfgIsActive.ctrl_hosts=%s"%ctrl_hosts)
        computehosts = self.get_group_host_list(self.computeGroupInfo)
        logger.info("DISK:checkAllHostCfgIsActive.computehosts=%s"%computehosts)
        count = 0
        time.sleep(10)
        disk_check_time = fs_change_util.get_disk_check_time()

        pre_env = os.getenv("PREINSTALL")

        while 1:
            count = count + 1

            if count == disk_check_time:
                #预安装
                if pre_env is not None:
                    break

                PrintUtil.print_msg_by_index("1000046")
                choice = cliopt.getChooseYN()
                if choice == "n":
                    count = 0
                elif choice == "y":
                    break

            allhostok = True
            PrintUtil.print_msg_by_index_ex("1000041", (time.strftime('%Y-%m-%d %H:%M:%S')))

            # check ctrl host
            for host in ctrl_hosts:
                host_info = cps_server.get_host_detail_info(host)
                if host_info is None:
                    #单板信息已经删除了
                    continue

                roles = host_info["roleinfo"]
                logger.info("roles: %s " %roles)
                if host_info.has_key('logical-volume'):
                    ceilometerok = False
                    imageok = False
                    swiftok = False
                    backupok = False
                    for item in host_info['logical-volume']:
                        if item['name'] == 'ceilometer-data' and item['size'].lower() == self.ceilometer_data.lower():
                            ceilometerok = True
                        if item['name'] == 'swift' and item['size'].lower() == self.repository_store_size.lower():
                            swiftok = True
                        if item['name'] == 'image' and item['size'].lower() == self.control_image_cache.lower():
                            imageok = True
                        if item['name'] == 'backup' and item['size'].lower() == self.backup_store_size.lower():
                            backupok = True

                    logger.info("[checkHostcfgsCommit] ceilometerok:%s,swiftok:%s,imageok:%s,backupok:%s" % (
                        ceilometerok, swiftok, imageok, backupok))

                    if "mongodb" not in roles:
                        ceilometerok = True
                    if "sys-server" not in roles:
                        backupok = True
                    if "compute" not in roles:
                        imageok = True
                    if "swift" not in roles:
                        swiftok = True
                    if (ceilometerok != True or swiftok != True or imageok != True or backupok != True):
                        PrintUtil.print_msg_by_index_ex("1000043", (host))
                        logger.info("[checkHostcfgsCommit] %40s still in progress" % host)
                        allhostok = False
                        continue
                    else:
                        PrintUtil.print_msg_by_index_ex("1000044", (host))
                        continue

            # check compute host
            for host in computehosts:
                host_info = cps_server.get_host_detail_info(host)
                if host_info is None:
                    continue

                roles = host_info["roleinfo"]
                logger.info("roles: %s " %roles)
                
                if host_info.has_key('logical-volume'):
                    imageok = False
                    for item in host_info['logical-volume']:
                        if item['name'] == 'image' and item['size'].lower() == self.compute_image_cache.lower():
                            imageok = True
                        else:
                            pass
                    if "compute" not in roles:
                        imageok = True
                    if (imageok == False):
                        PrintUtil.print_msg_by_index_ex("1000043", (host))
                        logger.info("[checkHostcfgsCommit] %s still in progress" % host)
                        allhostok = False
                    else:
                        PrintUtil.print_msg_by_index_ex("1000044", (host))
                else:
                    PrintUtil.print_msg_by_index_ex("1000043", (host))
                    logger.info("[checkHostcfgsCommit] %s still in progress" % host)
                    allhostok = False

            if allhostok == True:
                PrintUtil.print_msg_by_index("1000045")
                return
            else:
                time.sleep(20)
                continue
        if not allhostok:
            logger.error("check hostcfg error,it is a serious problem.")
            return


    #-------------------------------------------
    #整体对外的 4 个接口
    #-------------------------------------------
    #deploy的时候调用，用于生成默认的default.ini
    def create_def_config(self, cfg ):
        logger.debug('into create_def_config type.cfg=%s.'%cfg)

        #无需默认的配置文件了，尽量支持从zookeeper上进行恢复
        return

    #使用交互式方式，配置存储信息
    def config(self, type_name):
        logger.debug('into config type = %s.' % type_name)

        self.parseConfigInfoFromFile(DiskConstant.DISK_INI_PATH)
        allhosts, allhostsip = cps_server.get_all_hosts()
        allhostsip = []
        lst_ctrl_host = self.getControlGroup()
 
        extend_host = []
        extend_host = self.isolate_host_list

        logger.info('into create_def_config type extend_host = %s. allhostsip = %s.' % (extend_host, allhostsip))
        #先查看当前生效的配置信息,再解析一遍，会把配置的数据给冲掉的
        #把这些分成3部分，一部分 是 logical volume 的配置，一个是扩容， 一个是 storage 配置
        while (1):
            PrintUtil.print_msg_by_index("1000006")

            PrintUtil.print_msg_by_index("1000008")
            PrintUtil.print_msg_by_index("1000009")
            PrintUtil.print_msg_by_index("1000007")

            chooseType = ["1", "2", "s"]
            choose = cliopt.makeChooseByYourselfReverse(chooseType, "s")
            if "s" == choose:
                self.getLogicalVolumeSie(DiskConstant.TYPE_ONLY_DEPLOY)
                self.extendorRemoveALLGroupTypeDistToHost(DiskConstant.TYPE_ONLY_DEPLOY, self.url, allhosts,
                                                          lst_ctrl_host, extend_host)
                break
            elif "1" == choose:
                self.getLogicalVolumeSie(DiskConstant.TYPE_ONLY_CONFIG)
                self.extendorRemoveALLGroupTypeDistToHost(DiskConstant.TYPE_ONLY_DEPLOY, self.url, allhosts,
                                                          lst_ctrl_host, extend_host)
            elif "2" == choose:
                self.getLogicalVolumeSie(DiskConstant.TYPE_ONLY_DEPLOY)
                self.extendorRemoveALLGroupTypeDistToHost(DiskConstant.TYPE_ONLY_CONFIG, self.url, allhosts,
                                                          lst_ctrl_host, extend_host)

        PrintUtil.print_msg_by_index("1000010")
        return True

    #根据配置文件 ，刷新zookeeper的配置信息，使其生效
    def validate(self, type_name, phase):
        logger.debug('into validate type = %s phase =%s.' % (type_name, phase))
        self.parseConfigInfoFromFile(DiskConstant.DISK_INI_PATH)

        self.beginToConfigByFileByPciType()

        cps_server.cps_commit()

        self.checkAllHostCfgIsActive()

    def force_clean(self):
        logger.debug('into create_def_config type.')
        print '--------------Begin disk configuration force clean !--------------------------------'
        #将环境上的所有存储的数据 全部清空，重新配置，待开发
        hostcfgList = cliopt.getHostcfgList(self.url)
        for item in hostcfgList:
            if item["type"] == "storage" and item["name"] != "default":
                hostcfgName = item["name"]
                logger.info('begin to delete hostcfg :%s .' % hostcfgName)

                if cliopt.storageHostcfgDelete(hostcfgName, self.url):
                    logger.info('begin to delete hostcfg :%s . sucess.' % hostcfgName)
                else:
                    logger.error('begin to delete hostcfg :%s . failed.' % hostcfgName)

        cps_server.cps_commit()
        print '-------------- Disk configuration force clean  end !--------------------------------'

    def extendHostConfig(self, extendHostList):
        self.parseConfigInfoFromFile(DiskConstant.DISK_INI_PATH)
        allhosts, allhostsip = cps_server.get_all_hosts()
        lst_ctrl_host = self.getControlGroup()

        extend_host = []
        extend_host = self.isolate_host_list

        logger.info('DISK:extendHostConfig to extend_host :%s '
                     'extendHostList = %s allhostsip = %s.' % (extend_host, extendHostList, allhostsip))
        self.getLogicalVolumeSie(DiskConstant.TYPE_ONLY_DEPLOY)
        self.extendorRemoveALLGroupTypeDistToHost(DiskConstant.TYPE_ONLY_DEPLOY, self.url, allhosts,
                                                          lst_ctrl_host, extend_host)

    def test(self):
        print ''


if __name__ == "__main__":
    opt = FSdiskOptConfig()
    #这个可以提供一个 专门用来提供输入控制节点的信息

    print "Please choose default(1), config(2), test(3) or force_clean(4) or extendHostConfig(5). "
    chooseType = ["1", "2", "3", "4", "5"]
    choose_new = cliopt.makeChooseByYourself(chooseType)

    if "1" == choose_new:
        opt.create_def_config(None)
    elif "2" == choose_new:
        opt.config('1')
        opt.validate('1', None)
    elif "3" == choose_new:
        opt.computeTheLargerSize("51G", "53G")
    elif "4" == choose_new:
        opt.force_clean()
    elif "5" == choose_new:
        opt.extendHostConfig(None)



