#!/usr/bin/env python
# coding:utf-8
# Helper functions for the CPS client.
import os
from os.path import join


class DiskConstant(object):
    #host_cfg config
    HOST_CFG = "host_cfg"

    REPOSITOR_STORE_SIZE_VALUE = "50G"
    CEILOMETER_DATA_VALUE = "20G"
    COMPUTE_IMAGE_CACHE_VALUE = "5G"
    GLANCE_STORE_SIZE_VALUE = "10G"
    BAKCUP_STORE_SIEZE_VALUE = "20G"

    SWIFT_NAME = "swift"
    IMAGE_NAME = "image"
    CEILOMETER_DATA_NAME = "ceilometer-data"
    BACKUP_NAME = "backup"

    SIZE_KEY = "size"
    NAME_KEY = "name"

    #获取当前文件所在的路径
    CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))

    DISK_INI_PATH = join(CURRENT_PATH, 'fs_disk.ini')

    DEFUALT_SYS_PATH = join(CURRENT_PATH, 'default_sys.ini')
    STORAGE_EFFECT = join(CURRENT_PATH, "defaultStorageEffect.ini")
    LOG_FILE = join(CURRENT_PATH, "fsinstall.log")

    COMPUTE_HOST_TYPE = "compute"
    CONTROL_HOST_TYPE = "control"

    GROUP_KEY = "hostcfgname"
    DISK_KEY = "disk"
    EXTENDISK_KEY = "extenddisk"
    REMOVEDISK_KEY = "removedisk"
    LOGICAL_VOLUME = "logical-volume"
    HOSTID_KEY = "hostid"
    DISKINFO_KEY = "diskinfo"
    DEV_KEY = "dev"

    PRINT_LIST = [GROUP_KEY, HOSTID_KEY, LOGICAL_VOLUME, DISK_KEY, EXTENDISK_KEY, REMOVEDISK_KEY]

    STORAGE_SETCTION_KEY = "hostsetting_storage"
    HOST_SECTION_KEY = "host_deploy"
    STORAGE_IPSCAN_SECTION_KEY = "storage_configuration"
    CINDER_IS_CHANGE = "cinder_is_change"

    STORAGE_GROUP_INFO = "StorageCroupInfo"
    CONTORL_GROUP_GROUP_INFO = "controlGroupInfo"
    COMPUTE_GROUP_GROUP_INFO = "computeGroupInfo"

    CEILOMETER_DATA = "ceilometer_data"
    BACKUP_STORE = "backup"
    BACKUP_STORE_SIZE = "backup_store_size"
    COMPUTE_IMAGE_CACHE = "compute_image_cache"
    CONTROL_IMAGE_CACHE = "control_image_cache"
    GLANCE_STORE_SIZE = "glance_store_size"
    REPOSITOR_STORE_SIZE = "repository_store_size"
    GLANCE_STORE_FILE = "glance_default_store"
    CONTROL_HOST = "ctrl_hosts"
    COMPUTE_HOST = "computer_host"
    CONTROL_GROUP = "control_group_"
    COMPUTE_GROUP = "compute_group_"

    TYPE_ONLY_DEPLOY = "deploy"
    TYPE_DEPLOY_CONFIG = "deploy & config"
    TYPE_ONLY_CONFIG = "config"

    HOST_MODE = "host_mode"

    API_SERVER_NAME = "sys-server"

    GLANCE_DEFAULT_STORE = "file"

    #对接ipsan dsware 的storage配置
    DEF_CINDER_DEFAULT_STORE = "file"
    CINDER_DEFAULT_STORE_KEY = "cinder_default_store"
    DEF_STORAGE_CONTROLLER_IPS = "127.0.0.1,127.0.0.1"
    STORAGE_CONTROLLER_IPS_KEY = "storage_controller_ips"
    DEF_DEFAULT_TARGET_IPS = "127.0.0.1"
    DEFAULT_TARGET_IPS_KEY = "default_target_ips"
    STORAGE_PASSWORDS = None
    DEF_STORAGE_PASSWORDS_KEY = "storage_passwords"
    DEF_STORAGE_POOL_NAME = "default"
    STORAGE_POOL_NAMES_KEY = "storage_pool_names"
    DEF_STORAGE_USERNAMES = "default"
    STORAGE_USERNAMES_KEY = "storage_usernames"
    DEF_STORAGE_PROTOCOL = "iSCSI"
    STORAGE_PROTOCOL_KEY = "protocols"
    ULTRAPATHFLAG_KEY = "UltraPathFlag"
    DEF_ULTRAPATHFLAG = "false"
    DEF_ENABLE_BACKEND_KEY = "enabled_backend"
    STORAGE_ENABLE_BACKEND = "FusionStorage0"

    FUSIONSTORAGEAGEN_KEY = "fusionstorageagent"
    DEF_FUSIONSTORAGEAGEN__VALUE = "192.168.0.1,192.168.0.2,192.168.0.3"

    STORAGE_CHANGE = "false"
    STORAGE_CHANGE_KEY = "storage_change"

    storageMap = {"ipsan": "cinder.volume.drivers.huawei.HuaweiISCSIDriver",
                  "fusionstorage": "cinder.volume.drivers.dsware.HuaweiDswareDriver",
                  "file": "cinder.volume.drivers.lvm.LVMISCSIDriver"}

    SERVICE = "service"
    TEMPLATE = "template"
    COMMIT_STATE = "commited"
    UNCOMMIT_STATE = "uncommit"

    PASSWORD_KEY = "password"










