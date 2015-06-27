#!/usr/bin/env python
# coding:utf-8
# Helper functions for the CPS client.

import sys
import json
import os
import ConfigParser
import traceback
from fs_cinder_constant import CinderConstant
import fs_log_util
import cps_server
import fsCpsCliOpt as cliopt
import fs_cinder_constant
from print_msg import PrintMessage as PrintUtil
import fsutils as utils
import getpass
import fs_change_util
from os.path import join
from FSComponentUtil import crypt
import time

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')

logger = fs_log_util.localLog.get_logger(LOG_FILE)
driver_map = {"file":"cinder.volume.drivers.lvm.LVMISCSIDriver",
              "ipsan":"cinder.volume.drivers.huawei.HuaweiISCSIDriver",
              "fusionstorage":"cinder.volume.drivers.dsware.HuaweiDswareDriver",
              "other":"OtherDriver"}
need_crypt_keylist = ['s3_store_access_key_for_cinder', 's3_store_secret_key_for_cinder', 'fc_pwd_for_cinder']

class BlockStorageConfiguration():
    def __init__(self):
        self.drivers = []
        self.default_sc = None
        self.changes = False
        self.params = cps_server.get_template_params("cinder","cinder-volume")
        if self.params['cfg']['driver_data'] == '' or self.params['cfg']['driver_data'] == '{}':
            self.driver_data = dict()
        else:
            self.driver_data = json.loads(json.dumps(self.params['cfg']['driver_data']))
        self.volume_hosts = self.params['cfg']['volume_hosts']
        self.max_storage_index = self.get_max_storage_index()
        self.storage_ultrapathflag = self.params['cfg']['use_ultrapath_for_image_xfer']
        self.fusionstorageagent = self.params['cfg']['fusionstorageagent']
        self.build_info()
        if 'other_storage_cfg' in self.params['cfg'] and self.params['cfg']['other_storage_cfg']:
            self.other_conf = self.params['cfg']['other_storage_cfg']
        else:
            self.other_conf = {}
    
    def rebuild_hosts(self):
        params = cps_server.get_template_params("cinder","cinder-volume")
        hosts = self.params['cfg']['volume_hosts']
        if self.volume_hosts != hosts:
            self.changes = True
            self.volume_hosts = hosts
        index = 0
        while self.volume_hosts == '' or self.volume_hosts is None:
            if index == 3:
                raise
            if index > 0:
                print "get volume hosts failed, sleep 2s and retry!"
                time.sleep(2)
            index += 1
            hosts = cps_server.get_role_host_list("blockstorage-driver")
            tmp = ','.join(hosts)
            self.changes = True
            self.volume_hosts = tmp
            

    def build_info(self):
        ipsan_index = 0
        all_index = 0
        for key,value in sorted(self.driver_data.items(),key=lambda x:int(x[0])):
            sc = StorageConfiguration(int(key))
            sc.cinder_default_store = self.driver_data[key]['storage_type']
            if sc.cinder_default_store == "ipsan":
                sc.default_target_ips = self.params['cfg']['default_target_ips'].split('|')[ipsan_index] if ipsan_index < len(self.params['cfg']['default_target_ips'].split('|')) else CinderConstant.DEF_DEFAULT_TARGET_IPS
                sc.storage_controller_ips = self.params['cfg']['storage_controller_ips'].split('|')[ipsan_index] \
                                        if ipsan_index < len(self.params['cfg']['storage_controller_ips'].split('|')) else CinderConstant.DEF_STORAGE_CONTROLLER_IPS
                sc.storage_passwords =  self.params['cfg']['storage_passwords'].split('|')[ipsan_index] \
                                        if ipsan_index < len(self.params['cfg']['storage_passwords'].split('|')) else self.params['cfg']['storage_passwords'].split('|')[0]
                if sc.storage_passwords != "":
                    sc.storage_passwords = crypt.decrypt(sc.storage_passwords)
                sc.storage_pool_names = self.params['cfg']['storage_pool_names'].split('|')[ipsan_index] \
                                        if ipsan_index < len(self.params['cfg']['storage_pool_names'].split('|')) else CinderConstant.DEF_STORAGE_POOL_NAME
                sc.storage_usernames = self.params['cfg']['storage_usernames'].split('|')[ipsan_index] \
                                        if ipsan_index < len(self.params['cfg']['storage_usernames'].split('|')) else CinderConstant.DEF_STORAGE_USERNAMES
                sc.storage_protocols = self.params['cfg']['protocols'].split('|')[ipsan_index] \
                                        if ipsan_index < len(self.params['cfg']['protocols'].split('|')) else CinderConstant.DEF_STORAGE_PROTOCOL
                ipsan_index += 1
            sc.fusionstorageagent = self.fusionstorageagent
            private_enabled_backend = sc.cinder_default_store + str(sc.index)
            sc.storage_enable_backend = self.params['cfg']['enabled_backend'].split(',')[all_index] \
                                        if all_index < len(self.params['cfg']['enabled_backend'].split(',')) else private_enabled_backend
            all_index += 1
            sc.setStorageConfigurationInfo(CinderConstant.TYPE_ONLY_DEPLOY)
            self.drivers.append(sc)
        if self.default_sc is not None and len(self.drivers) == 0:
            self.drivers.append(self.default_sc)
        elif self.default_sc is None and len(self.drivers) > 0:
            self.default_sc = self.drivers[0]

    def create_def_config(self, configger):
        self.default_sc.setStorageConfigurationInfo(CinderConstant.TYPE_ONLY_DEPLOY)

    def get_section_list(self):
        return [CinderConstant.STORAGE_DEPLOY_POLICY_SETCTION_KEY, CinderConstant.STORAGE_IPSAN_SETCTION_KEY,
                CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY,]

    def get_file_path(self):
        if self.default_sc is not None:
            pass
        elif len(self.drivers) > 0:
            self.default_sc = self.drivers[0]
        else:
            self.default_sc = StorageConfiguration(self.max_storage_index)
            self.drivers.append(self.default_sc)
        return self.default_sc.get_file_path()

    def get_max_storage_index(self):
        if self.driver_data is None or len(self.driver_data.keys()) is 0:
            #print "driver_data is None"
            self.default_sc = StorageConfiguration(0)
            self.auto_create = True
            return 0
        self.auto_create = False
        return int(max(self.driver_data.items(),key=lambda x:int(x[0]))[0]) + 1
        
    def print_base_info(self):
        index = 0
        if len(self.driver_data.items()) > 0:
            for key,value in sorted(self.driver_data.items(),key=lambda x:int(x[0])):
                if value.get("storage_type",None) is None or value.get("backend_name",None) is None:
                    continue
                print "[%d] Modify Backend Storage Config for type %s which name is %s" % (index,value['storage_type'],value['backend_name'])
                index += 1
            value = max(self.driver_data.items(),key=lambda x:int(x[0]))[1]
            print "[%d] delete Backend Storage Config for type %s which name is %s" % (index,value['storage_type'],value['backend_name'])
        
        
        total = index if index == 0 else (index + 1)
        print "[%d] Add a new Backend Storage Config" % total
        print "[s] save & quit"
        return index,total
    
    def update_private_info(self,driver):
        if driver.cinder_default_store == 'ipsan':
            self.storage_ultrapathflag = driver.storage_ultrapathflag
        elif driver.cinder_default_store == 'fusionstorage':
            self.fusionstorageagent = driver.fusionstorageagent

    def setStorageConfigurationInfo(self,type):
        while 1:
            try:
                index,total = self.print_base_info()
                select = raw_input("Please select one to config [0 - %d|s][s]" % total)
                if select == "s" or select == '':
                    return True
                elif int(select) < index:
                    ret = self.drivers[int(select)].config(type, True)
                    if ret is None or ret is True:
                        self.refresh_storage_config(int(select),False)
                        self.update_private_info(self.drivers[int(select)])
                        self.changes = True
                    continue
                elif int(select) == index and index != total:
                    max_id = int(max(self.driver_data.items(),key=lambda x:int(x[0]))[0])
                    ret = self.refresh_storage_config(max_id,True)
                    self.changes = True
                    continue
                elif int(select) == total:
                    ret = self.add_storage_config()
                    continue
                else:
                    print "unknown option %s,please input again" % select
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                print "unknown error,please input again"

    
    def refresh_storage_config(self,index,delete_flag):
        i = 0
        for key,value in sorted(self.driver_data.items(),key=lambda x:int(x[0])):
            if value.get("storage_type",None) is None or value.get("backend_name",None) is None:
                continue
            if delete_flag is True:
                if int(key) == index:
                    filename = self.drivers[i].default
                    if os.path.exists(filename):
                        os.remove(filename)
                    self.drivers.pop(i)
                    if self.default_sc == self.driver_data[key]:
                        self.default_sc = self.drivers[0] if len(self.drivers) > 0 else StorageConfiguration(0)
                    if len(self.drivers) == 0:
                        self.drivers.append(self.default_sc)
                        self.auto_create = True
                    del self.driver_data[key]
                    if int(key) == self.max_storage_index - 1:
                        self.max_storage_index = int(key)
                    self.changes = True
                    if len(self.other_conf) > 0:
                        self.other_conf.pop(str(index), None)
                        params = {"other_storage_cfg": self.other_conf}
                        if not cps_server.update_template_params("cinder", "cinder-volume", params):
                            logger.error("update service cinder template cinder-volume params failed.")
            
                        if not cps_server.update_template_params("cinder", "cinder-backup", params):
                            logger.error("update service cinder template cinder-backup params failed.")
                        cps_server.cps_commit()
                    break
            elif i == index:
                self.driver_data[key].update({'storage_type':self.drivers[index].cinder_default_store,
                                                   'backend_name':self.drivers[index].storage_enable_backend})
                if self.drivers[index].other_config is not None:
                    self.other_conf[str(index)] = self.drivers[index].other_config.section_dict.copy()
                self.changes = True
                break
            i += 1
        
    
    def add_storage_config(self):
        if self.default_sc is not None and self.max_storage_index == self.default_sc.index:
            sc = self.default_sc
        else:
            sc = StorageConfiguration(self.max_storage_index)
        index = str(sc.index)
        sc.storage_ultrapathflag = self.storage_ultrapathflag
        result = sc.config(type)
        if result is None or result is True:
            self.auto_create = False
            if self.changes is False:
                self.changes = sc.configChanges
            storage_info = {'storage_type':sc.cinder_default_store,
                            'backend_name':sc.storage_enable_backend}
            self.driver_data.update({str(self.max_storage_index):storage_info})
            if sc.other_config is not None:
                self.other_conf[str(index)] = sc.other_config.section_dict.copy()
            if sc not in self.drivers:
                self.drivers.append(sc)
            self.update_private_info(sc)
            self.max_storage_index += 1
        else:
            if self.default_sc != sc:
                del sc
        return result
    def del_blockstorage_role(self):
        role_name = "blockstorage"
        deployed_hosts = cps_server.get_role_host_list(role_name)
        if len(deployed_hosts) > 0:
            cps_server.role_host_delete(role_name, deployed_hosts)


    def add_blockstorage_role(self):
        role_name = "blockstorage"
        deployedhosts = cps_server.get_role_host_list(role_name)
        allhosts = utils.get_all_hosts()
        if allhosts is None:
            return
        need_deploy_list = []
        for host in allhosts:
            if not host in deployedhosts:
                need_deploy_list.append(host)
        if len(need_deploy_list) > 0:
            cps_server.role_host_add(role_name, need_deploy_list)

    def storage_commit(self, type, phase,has_fusionstorage,has_ipsan,has_lvm,has_other):

        if has_fusionstorage is True:
            self.add_blockstorage_role()
        else:
            self.del_blockstorage_role()

        #提交，当前未做
        cps_server.cps_commit()

        #修改对应的组件信息
        if has_ipsan is True:
            params = {"default_target_ips": self.default_target_ips,
                      "storage_controller_ips": self.storage_controller_ips,
                      "default_target_ips": self.default_target_ips,
                      "storage_passwords": self.storage_passwords,
                      "storage_pool_names": self.storage_pool_names,
                      "storage_usernames": self.storage_usernames,
                      "use_ultrapath_for_image_xfer": self.storage_ultrapathflag,
                      "protocols": self.storage_protocols,
                      "enabled_backend": self.storage_enable_backend,
                      "volume_driver": self.volume_driver,
                      "products": self.storage_product,
                      "resturls": self.storage_resturl}

            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume failed"
                logger.error("update service cinder template cinder-volume failed.")
                return False

            params = {"volume_driver": self.volume_driver,
                      "enabled_backend": self.storage_enable_backend,
                      "use_ultrapath_for_image_xfer": self.storage_ultrapathflag}
            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False
                
            params1 = {"storage_driver": self.volume_driver,
                      "storage_ip": self.default_target_ips}
            if not cps_server.update_template_params("ceilometer", "ceilometer-agent-hardware", params1):
                print "Update service ceilometer template ceilometer-agent-hardware params failed."
                logger.error("update service ceilometer template ceilometer-agent-hardware params failed.")
                return False
                
            params = {"libvirt_iscsi_use_ultrapath" : self.storage_ultrapathflag}
            if not cps_server.update_template_params("nova", "nova-compute", params):
                print "Update service cinder template cinder-backup params:  failed."
                logger.warning("update service cinder template cinder-backup params failed.")

        if has_fusionstorage is True:
            params = {"fusionstorageagent": self.fusionstorageagent,
                      "enabled_backend": self.storage_enable_backend,
                      "use_ultrapath_for_image_xfer": self.storage_ultrapathflag,
                      "volume_driver": self.volume_driver}
            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume params failed."
                logger.error("update service cinder template cinder-volume params failed.")
                return False

            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False
                
            params1 = {"storage_driver": self.volume_driver,
                      "storage_ip": self.default_target_ips}
            if not cps_server.update_template_params("ceilometer", "ceilometer-agent-hardware", params1):
                print "Update service ceilometer template ceilometer-agent-hardware params failed."
                logger.error("update service ceilometer template ceilometer-agent-hardware params failed.")
                return False
                
            params = {"libvirt_iscsi_use_ultrapath" : self.storage_ultrapathflag}
            if not cps_server.update_template_params("nova", "nova-compute", params):
                print "Update service cinder template cinder-backup params failed."
                logger.warning("update service cinder template cinder-backup params failed.")

        if has_lvm is True:
            params = {"default_target_ips": self.default_target_ips,
                      "storage_controller_ips": self.storage_controller_ips,
                      "default_target_ips": self.default_target_ips,
                      "storage_pool_names": self.storage_pool_names,
                      "storage_usernames": self.storage_usernames,
                      "enabled_backend": self.storage_enable_backend,
                      "use_ultrapath_for_image_xfer": self.storage_ultrapathflag,
                      "volume_driver": self.volume_driver}

            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume params failed."
                logger.error("update service cinder template cinder-volume params failed.")
                return False

            params = {"volume_driver" : self.volume_driver}
            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False
            
            params1 = {"storage_driver": self.volume_driver,
                      "storage_ip": self.default_target_ips}
            if not cps_server.update_template_params("ceilometer", "ceilometer-agent-hardware", params1):
                print "Update service ceilometer template ceilometer-agent-hardware params failed."
                logger.error("update service ceilometer template ceilometer-agent-hardware params failed.")
                return False
        
        if not has_lvm and not has_fusionstorage and not has_ipsan:
            params = {"volume_driver" : self.volume_driver,
                      "enabled_backend": self.storage_enable_backend}
            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume params failed."
                logger.error("update service cinder template cinder-volume params failed.")
                return False

            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False
            
            params = {"libvirt_iscsi_use_ultrapath" : self.storage_ultrapathflag}
            if not cps_server.update_template_params("nova", "nova-compute", params):
                print "Update service cinder template cinder-backup params:  failed."
                logger.error("update service cinder template cinder-backup params failed.")
                
        if has_other is True:
            params = {"other_storage_cfg": self.other_conf}
            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume params failed."
                logger.error("update service cinder template cinder-volume params failed.")
                return False            
            
            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False

            ultrapathflag = self.storage_ultrapathflag
            for section in self.other_conf.values():
                if ultrapathflag == "true":
                    break
                for value in section.values():
                    if "storage_ultrapathflag" in value:
                        ultrapathflag = value["storage_ultrapathflag"]
                        if ultrapathflag == "true":
                            break

            params = {"libvirt_iscsi_use_ultrapath" : ultrapathflag}
            if not cps_server.update_template_params("nova", "nova-compute", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")

        #提交，当前未做
        cps_server.cps_commit()

    def config(self, type):
        logger.error('into config type = %s.' % type)
        
        if self.auto_create is True:
            return self.add_storage_config()
        return self.setStorageConfigurationInfo(type)

    def validate(self, type, phase):
        for driver in self.drivers:
            if driver.configChanges is True or driver == self.default_sc:
                if not driver.parseConfigInfoFromFile(driver.default):
                    continue
                storage_info = {'storage_type':driver.cinder_default_store,
                            'backend_name':driver.storage_enable_backend}
                self.driver_data.update({str(driver.index):storage_info})
                self.update_private_info(driver)
                self.changes = True
        
        if self.changes is True:
            self.rebuild_hosts()
            params = {"driver_data": self.driver_data,
                       "volume_hosts": self.volume_hosts}
            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume failed"
                logger.error("update service cinder template cinder-volume failed.")
                raise
            
            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                raise
            
            default_target_ips = ""
            storage_controller_ips = ""
            storage_passwords = ""
            storage_pool_names = ""
            storage_usernames = ""
            storage_protocols = ""
            enabled_backend = ""
            volume_driver = ""
            storage_product = ""
            storage_resturl = ""
            def collect_info(dst_str,sp,src_dst):
                if dst_str != "":
                    dst_str += sp
                dst_str += src_dst
                return dst_str
            has_ipsan = False
            has_fusionstorage = False
            has_lvm = False
            has_other = False
            for driver in self.drivers:
                if driver.cinder_default_store == 'ipsan':
                    default_target_ips = collect_info(default_target_ips,'|',driver.default_target_ips)
                    storage_controller_ips = collect_info(storage_controller_ips,'|',driver.storage_controller_ips)
                    if driver.storage_passwords is None or driver.storage_passwords == "":
                        print "please input password for backend %s" % driver.storage_enable_backend
                        driver.storage_passwords = driver._input_ipsan_password()
                    storage_passwords = collect_info(storage_passwords,'|',driver.storage_passwords)
                    storage_pool_names = collect_info(storage_pool_names,'|',driver.storage_pool_names)
                    storage_usernames = collect_info(storage_usernames,'|',driver.storage_usernames)
                    storage_protocols = collect_info(storage_protocols,'|',driver.storage_protocols)
                    storage_product = collect_info(storage_product,'|',driver.storage_product)
                    storage_resturl = collect_info(storage_resturl,'|',driver.storage_resturl)
                    has_ipsan = True
                elif driver.cinder_default_store == 'file':
                    has_lvm = True
                elif driver.cinder_default_store == 'fusionstorage':
                    has_fusionstorage = True
                elif driver.cinder_default_store == 'other':
                    has_other = True
                    for section in self.other_conf.values():
                        for value in section.values():
                            if driver_map["file"] in value.values():
                                has_lvm = True
                            elif driver_map["fusionstorage"] in value.values():
                                has_fusionstorage = True
                if driver.cinder_default_store not in driver_map.keys():
                    volume_driver =  collect_info(volume_driver,'|',driver.cinder_default_store)
                elif driver_map[driver.cinder_default_store] not in volume_driver:
                    volume_driver =  collect_info(volume_driver,'|',driver_map[driver.cinder_default_store]) 

                enabled_backend = collect_info(enabled_backend,',',driver.storage_enable_backend)
            self.default_target_ips = default_target_ips if default_target_ips != "" else CinderConstant.DEF_DEFAULT_TARGET_IPS
            self.storage_controller_ips = storage_controller_ips if storage_controller_ips != "" else CinderConstant.DEF_STORAGE_CONTROLLER_IPS
            self.storage_passwords = storage_passwords if storage_passwords != "" else CinderConstant.STORAGE_PASSWORDS
            self.storage_pool_names = storage_pool_names if storage_pool_names != "" else CinderConstant.DEF_STORAGE_POOL_NAME
            self.storage_usernames = storage_usernames if storage_usernames != "" else CinderConstant.DEF_STORAGE_USERNAMES
            self.storage_protocols = storage_protocols if storage_protocols != "" else CinderConstant.DEF_STORAGE_PROTOCOL
            self.storage_enable_backend = enabled_backend if enabled_backend != "" else CinderConstant.STORAGE_ENABLE_BACKEND
            self.volume_driver = volume_driver if volume_driver != "" else driver_map['file']
            self.storage_product = storage_product if storage_product != "" else CinderConstant.PRODUCT
            self.storage_resturl = storage_resturl if storage_resturl != "" else CinderConstant.RESTURL
            self.storage_commit(type, phase,has_fusionstorage,has_ipsan,has_lvm,has_other)
            self.changes = False
        

class StorageConfiguration():
    def __init__(self,index=0):

        self.url = cps_server.get_cpsserver_url()
        self.cinder_default_store = CinderConstant.DEF_CINDER_DEFAULT_STORE
        self.default_target_ips = CinderConstant.DEF_DEFAULT_TARGET_IPS
        self.storage_controller_ips = CinderConstant.DEF_STORAGE_CONTROLLER_IPS
        self.storage_passwords = CinderConstant.STORAGE_PASSWORDS
        self.storage_pool_names = CinderConstant.DEF_STORAGE_POOL_NAME
        self.storage_usernames = CinderConstant.DEF_STORAGE_USERNAMES
        self.storage_protocols = CinderConstant.DEF_STORAGE_PROTOCOL
        self.storage_ultrapathflag = CinderConstant.DEF_ULTRAPATHFLAG
        self.storage_enable_backend = CinderConstant.STORAGE_ENABLE_BACKEND

        self.fusionstorageagent = CinderConstant.DEF_FUSIONSTORAGEAGEN__VALUE
        #起来 如果有生效 文件，先从配置文件中获取一下
        self.index = index
        self.default = CinderConstant.CINDER_INI_PATH + '.' + str(index)
        self.storageEffect = CinderConstant.STORAGE_EFFECT
        self.configChanges = False
        self.other_config = None
        self.storage_product = CinderConstant.PRODUCT
        self.storage_resturl = CinderConstant.RESTURL
        #尝试从default.ini取到前一次的配置信息，没有继续使用默认的数据
        if os.path.exists(self.default):
            self.parseConfigInfoFromFile(self.default)

    def get_section_list(self):
        return [CinderConstant.STORAGE_DEPLOY_POLICY_SETCTION_KEY, CinderConstant.STORAGE_IPSAN_SETCTION_KEY,
                CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY,]

    def get_file_path(self):
        return self.default


    def parseConfigInfoFromFile(self, fileName):
        logger.info('begin to parse. %s ' % fileName)
        try:
            cpsconfig = ConfigParser.RawConfigParser()
            cpsconfig.read(fileName)
            sectionList = cpsconfig.sections()

            if CinderConstant.STORAGE_DEPLOY_POLICY_SETCTION_KEY not in sectionList:
                logger.error("not found storage info.")
                return False
            self.cinder_default_store = cpsconfig.get(CinderConstant.STORAGE_DEPLOY_POLICY_SETCTION_KEY,CinderConstant.CINDER_DEFAULT_STORE_KEY)

            if CinderConstant.STORAGE_IPSAN_TYPE == self.cinder_default_store:
                if CinderConstant.STORAGE_IPSAN_SETCTION_KEY not in sectionList:
                    logger.error("not found ipsan storage info.")
                    return False
                #ipsan 的配置
                self.storage_controller_ips = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.STORAGE_CONTROLLER_IPS_KEY)
                self.default_target_ips = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.DEFAULT_TARGET_IPS_KEY)
                self.storage_pool_names = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.STORAGE_POOL_NAMES_KEY)
                self.storage_usernames = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.STORAGE_USERNAMES_KEY)
                self.storage_protocols = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.STORAGE_PROTOCOL_KEY)
                self.storage_ultrapathflag = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.ULTRAPATHFLAG_KEY)
                self.storage_enable_backend = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.DEF_ENABLE_BACKEND_KEY)
                self.storage_product = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.STORAGE_PRODUCT_KEY)
                self.storage_resturl = cpsconfig.get(CinderConstant.STORAGE_IPSAN_SETCTION_KEY,CinderConstant.STORAGE_RESTURL_KEY)
                return True

            elif CinderConstant.STORAGE_FUSIONSTORAGE_TYPE == self.cinder_default_store:
                if CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY not in sectionList:
                    logger.error("not found ipsan storage info.")
                    return False
                #dsware的配置
                self.fusionstorageagent = cpsconfig.get(CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY,CinderConstant.FUSIONSTORAGEAGEN_KEY)
                self.storage_enable_backend = cpsconfig.get(CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY,CinderConstant.DEF_ENABLE_BACKEND_KEY)
                return True
            elif CinderConstant.STORAGE_FILE_TYPE == self.cinder_default_store:
                return True
            else:
                logger.error("can not find cinder info")
                return False
        except:
            logger.error("parse exception: %s" % (traceback.format_exc()))
            logger.error(traceback.format_exc())
            return False

    def __saveToConfigInfoToFile(self, deployFile, flag):
        if not os.path.exists(self.default):
            #如果文件不存在，则创建
            ini_file = open(self.default, 'w')
            ini_file.close()
            logger.debug("write_data.default.ini doesn't exist,file is %s." % self.default)

        cpsconfig = ConfigParser.RawConfigParser()
        cpsconfig.read(deployFile)
        sectionList = cpsconfig.sections()
        if CinderConstant.STORAGE_DEPLOY_POLICY_SETCTION_KEY not in sectionList:
            cpsconfig.add_section(CinderConstant.STORAGE_DEPLOY_POLICY_SETCTION_KEY)
        if CinderConstant.STORAGE_IPSAN_SETCTION_KEY not in sectionList:
            cpsconfig.add_section(CinderConstant.STORAGE_IPSAN_SETCTION_KEY)
        if CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY not in sectionList:
            cpsconfig.add_section(CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY)

        cpsconfig.set(CinderConstant.STORAGE_DEPLOY_POLICY_SETCTION_KEY, CinderConstant.CINDER_DEFAULT_STORE_KEY,self.cinder_default_store)

        #ipsan
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.DEFAULT_TARGET_IPS_KEY, self.default_target_ips)
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.STORAGE_CONTROLLER_IPS_KEY,self.storage_controller_ips)
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.STORAGE_POOL_NAMES_KEY,self.storage_pool_names)
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.STORAGE_USERNAMES_KEY,self.storage_usernames)
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.STORAGE_PROTOCOL_KEY,self.storage_protocols)
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.ULTRAPATHFLAG_KEY,self.storage_ultrapathflag)
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.DEF_ENABLE_BACKEND_KEY,self.storage_enable_backend)
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.STORAGE_PRODUCT_KEY,self.storage_product)
        cpsconfig.set(CinderConstant.STORAGE_IPSAN_SETCTION_KEY, CinderConstant.STORAGE_RESTURL_KEY,self.storage_resturl)

        #dsware
        cpsconfig.set(CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY, CinderConstant.FUSIONSTORAGEAGEN_KEY,self.fusionstorageagent)
        cpsconfig.set(CinderConstant.STORAGE_FUSTIONSTORAGE_SETCTION_KEY, CinderConstant.DEF_ENABLE_BACKEND_KEY,self.storage_enable_backend)

        cpsconfig.write(open(deployFile, "w"))


    def __getPassword(self):
        while 1:
            inputstr = PrintUtil.get_msg_by_index_ex("1000105", "")
            storage_passwords1 = getpass.getpass(inputstr)
            if storage_passwords1 == "":
                print 'Please input password.'
                continue

            inputstr = PrintUtil.get_msg_by_index_ex("1000105", "again")
            storage_passwords2 = getpass.getpass(inputstr)
            if storage_passwords2 == "":
                print 'Please input password.'
                continue

            if storage_passwords1 != storage_passwords2:
                print 'Password inconsistent.Please input password again.'
            else :
                return storage_passwords2

    def setStorageConfigurationInfo(self, type, modify=False):

        if CinderConstant.TYPE_ONLY_DEPLOY == type:
            logger.info(
                "extendorRemoveALLGroupTypeDistToHost not need to config , type = %s." % CinderConstant.TYPE_ONLY_DEPLOY)

            self.__saveToConfigInfoToFile(self.default, "false")
            return True

        PrintUtil.print_msg_by_index("1000101")
        while (1):
            try:

                cinder_default_store = self.cinder_default_store
                if not modify:
                    input_str = PrintUtil.get_msg_by_index_ex("1000102", self.cinder_default_store)
                    cinder_default_store = raw_input(input_str)
    
                    if cinder_default_store == "":
                        cinder_default_store =  self.cinder_default_store

                if cinder_default_store == "ipsan":
                    fs_change_util.set_section_change_flag(fs_change_util.CINDER_TYPE,fs_change_util.CHANGE_TYPE)

                    self.cinder_default_store = cinder_default_store
                    input_str = PrintUtil.get_msg_by_index_ex("1000103", self.default_target_ips)
                    default_target_ips = raw_input(input_str)
                    if default_target_ips == "":
                        default_target_ips = self.default_target_ips

                    targetIpList = default_target_ips.split("|")
                    is_Fault = False
                    for item in targetIpList:
                        if not cliopt.checkIpFormatIsCorrect(item.split(",")):
                            PrintUtil.print_msg_by_index("1000111")
                            is_Fault = True
                            break

                    if is_Fault:
                        continue

                    self.default_target_ips = default_target_ips
                    
                    input_str = "Please input OceanStor Product Type [T|18000|V3][%s] :" % self.storage_product
                    storage_product = raw_input(input_str)
                    if storage_product != "":
                        self.storage_product = storage_product
                    
                    if self.storage_product not in ["T","18000","V3"]:
                        continue
                                        
                    if self.storage_product == "T":
                        input_str = PrintUtil.get_msg_by_index_ex("1000104", self.storage_controller_ips)
                        storage_controller_ips = raw_input(input_str)
                        if storage_controller_ips == "":
                            storage_controller_ips = self.storage_controller_ips
    
                        is_Fault = False
                        controlIpList = storage_controller_ips.split("|")
                        for item in controlIpList:
                            if len(item.split(',')) != 2:
                                PrintUtil.print_msg_by_index("1000111")
                                is_Fault = True
                                break
    
                            if not cliopt.checkIpFormatIsCorrect(item.split(',')):
                                PrintUtil.print_msg_by_index("1000111")
                                is_Fault = True
                                break
    
                        if is_Fault:
                            continue
    
                        self.storage_controller_ips = storage_controller_ips
                        self.storage_resturl = "https://127.0.0.1:8088/deviceManager/rest/"
                    elif self.storage_product == "18000":
                        input_str = "Please input REST url for OceanStor 18000[%s]:" % self.storage_resturl
                        storage_resturl = raw_input(input_str)
                        if storage_resturl != "":
                            self.storage_resturl = storage_resturl
                    elif self.storage_product == "V3":
                        input_str = "Please input REST url for OceanStor V3[%s]:" % self.storage_resturl
                        storage_resturl = raw_input(input_str)
                        if storage_resturl != "":
                            self.storage_resturl = storage_resturl

                    input_str = PrintUtil.get_msg_by_index_ex("1000107", self.storage_usernames)
                    storage_user_names = raw_input(input_str)
                    if storage_user_names != "":
                        self.storage_usernames = storage_user_names

                    self.storage_passwords = self.__getPassword()

                    input_str = PrintUtil.get_msg_by_index_ex("1000106", self.storage_pool_names)
                    storage_pool_names = raw_input(input_str)
                    if storage_pool_names != "":
                        self.storage_pool_names = storage_pool_names

                    input_str = "Please input the protocols for ipsan [iSCSI|FC] [%s] :" % self.storage_protocols
                    protocols = raw_input(input_str)
                    if protocols != "":
                        self.storage_protocols = protocols

                    # enable_backend
                    self.storage_enable_backend = self.cinder_default_store + str(self.index)
                    input_str = "Please input enable backend storage name for cinder[%s]:" % self.storage_enable_backend
                    enable_backend = raw_input(input_str)
                    if enable_backend != "":
                        self.storage_enable_backend = enable_backend

                    ## do you want to use UltraPath mutiple path function
                    input_str = "Do you want to use UltraPath? [true|false][%s] :" % self.storage_ultrapathflag
                    ultra_path_flag = raw_input(input_str)
                    if ultra_path_flag not in ["true", "false", ""]:
                        print 'Please input correct UltraPath flag.'
                        continue

                    if ultra_path_flag != "":
                        self.storage_ultrapathflag = ultra_path_flag

                    break
                elif cinder_default_store == "fusionstorage":
                    fs_change_util.set_section_change_flag(fs_change_util.CINDER_TYPE, fs_change_util.CHANGE_TYPE)
                    self.cinder_default_store = cinder_default_store
                    url =  cps_server.get_cpsserver_url()
                    all_hosts, all_hosts_ip = cps_server.get_all_hosts()
                    if len(all_hosts) < 3:
                        logger.warning("host num little than 3 ,can not deploy dsware!host are %s" %all_hosts)
                        PrintUtil.print_msg_by_index("1000108")
                        continue

                    # enable_backend
                    self.storage_enable_backend = self.cinder_default_store + str(self.index)
                    input_str = "Please input enable backend storage name for cinder[%s]:"%self.storage_enable_backend
                    enable_backend = raw_input(input_str)
                    if enable_backend != "":
                        self.storage_enable_backend = enable_backend

                    self.fusionstorageagent = all_hosts_ip[0] + ',' + all_hosts_ip[1] + ',' + all_hosts_ip[2]

                    break
                elif cinder_default_store == "file":
                    fs_change_util.set_section_change_flag(fs_change_util.CINDER_TYPE, fs_change_util.CHANGE_TYPE)
                    self.cinder_default_store = CinderConstant.DEF_CINDER_DEFAULT_STORE
                    self.default_target_ips = CinderConstant.DEF_DEFAULT_TARGET_IPS
                    self.storage_controller_ips = CinderConstant.DEF_STORAGE_CONTROLLER_IPS
                    self.storage_passwords = CinderConstant.STORAGE_PASSWORDS
                    self.storage_pool_names = CinderConstant.DEF_STORAGE_POOL_NAME
                    self.storage_usernames = CinderConstant.DEF_STORAGE_USERNAMES
                    self.storage_enable_backend = self.cinder_default_store + str(self.index)
                    break
                elif cinder_default_store == "other":
                    self.cinder_default_store = cinder_default_store
                    if not modify:
                        self.storage_enable_backend = self.cinder_default_store + str(self.index)
                        input_str = "Please input Backend Storage Config name[%s]:" % self.storage_enable_backend
                        config_name = raw_input(input_str)
                        if config_name != "":
                            self.storage_enable_backend = config_name
                    self.other_config = OtherConfiguration(self.default, self.index)
                    self.other_config.config()
                    break
                else:
                    PrintUtil.print_msg_by_index("1000109")
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                logger.error(traceback.format_exc())
                PrintUtil.print_msg_by_index("1000109")
                continue

        PrintUtil.print_msg_by_index("1000110")
        if cliopt.getSaveOption():
            #保存
            self.__saveToConfigInfoToFile(self.default, "true")
            self.configChanges = True
        else:
            #不保存
            fs_change_util.set_section_change_flag(fs_change_util.CINDER_TYPE,fs_change_util.NO_CHANGE_TYPE)
            self.configChanges = False


    def _input_ipsan_password(self):
        storage_passwords = ""
        if fs_cinder_constant.storage_passwords is None or fs_cinder_constant.storage_passwords == "":
            ipsan_passwords = os.getenv("IPSANPASSWORD")
            if ipsan_passwords is not None:
                return ipsan_passwords
            storage_passwords = self.__getPassword()
        else:
            storage_passwords = fs_cinder_constant.storage_passwords

        return storage_passwords

    #-------------------------------------------
    #整体对外的 4 个接口
    #-------------------------------------------
    #deploy的时候调用，用于生成默认的default.ini
    def create_def_config(self, configger):
        logger.error('into create_def_config type.')
        self.setStorageConfigurationInfo(CinderConstant.TYPE_ONLY_DEPLOY)

    def del_blockstorage_role(self):
        role_name = "blockstorage"
        deployed_hosts = cps_server.get_role_host_list(role_name)
        if len(deployed_hosts) > 0:
            cps_server.role_host_delete(role_name, deployed_hosts)


    def add_blockstorage_role(self):
        role_name = "blockstorage"
        deployedhosts = cps_server.get_role_host_list(role_name)
        allhosts = utils.get_all_hosts()
        if allhosts is None:
            return
        need_deploy_list = []
        for host in allhosts:
            if not host in deployedhosts:
                need_deploy_list.append(host)
        if len(need_deploy_list) > 0:
            cps_server.role_host_add(role_name, need_deploy_list)

    #使用交互式方式，配置存储信息
    def config(self, type, modify=False):
        logger.info('into config type = %s.' % type)

        self.parseConfigInfoFromFile(self.default)

        self.setStorageConfigurationInfo("1", modify)

        return True

    #根据配置文件 ，刷新zookeeper的配置信息，使其生效
    def validate(self, type, phase):
        if self.configChanges is False:
            return

        logger.info('into validate type = %s.' % type)
        if not self.parseConfigInfoFromFile(self.default):
            logger.error('Cinder parseConfigInfoFromFile failed.')
            return

        if "fusionstorage" == self.cinder_default_store:
            self.add_blockstorage_role()
        else:
            self.del_blockstorage_role()

        #提交，当前未做
        cps_server.cps_commit()

        fs_change_util.set_section_change_flag(fs_change_util.CINDER_TYPE,fs_change_util.NO_CHANGE_TYPE)
        self.configChanges == False

        #修改对应的组件信息
        if "ipsan" == self.cinder_default_store:
            if self.storage_passwords is None or self.storage_passwords == "":
                self.storage_passwords = self._input_ipsan_password()
            params = {"default_target_ips": self.default_target_ips,
                      "storage_controller_ips": self.storage_controller_ips,
                      "default_target_ips": self.default_target_ips,
                      "storage_passwords": self.storage_passwords,
                      "storage_pool_names": self.storage_pool_names,
                      "storage_usernames": self.storage_usernames,
                      "use_ultrapath_for_image_xfer": self.storage_ultrapathflag,
                      "protocols": self.storage_protocols,
                      "enabled_backend": self.storage_enable_backend,
                      "volume_driver": "cinder.volume.drivers.huawei.HuaweiISCSIDriver"}

            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume failed"
                logger.error("update service cinder template cinder-volume failed.")
                return False

            params = {"volume_driver": "cinder.volume.drivers.huawei.HuaweiISCSIDriver",
                      "enabled_backend": self.storage_enable_backend,
                      "use_ultrapath_for_image_xfer": self.storage_ultrapathflag}
            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False
                
            params1 = {"storage_driver": "cinder.volume.drivers.huawei.HuaweiISCSIDriver",
                      "storage_ip": self.default_target_ips}
            if not cps_server.update_template_params("ceilometer", "ceilometer-agent-hardware", params1):
                print "Update service ceilometer template ceilometer-agent-hardware params failed."
                logger.error("update service ceilometer template ceilometer-agent-hardware params failed.")
                return False
                
            params = {"libvirt_iscsi_use_ultrapath" : self.storage_ultrapathflag}
            if not cps_server.update_template_params("nova", "nova-compute", params):
                print "Update service cinder template cinder-backup params:  failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False

                # UltraPathFlag change

        elif "fusionstorage" == self.cinder_default_store:
            params = {"fusionstorageagent": self.fusionstorageagent,
                      "enabled_backend": self.storage_enable_backend,
                      "use_ultrapath_for_image_xfer": "false",
                      "volume_driver": "cinder.volume.drivers.dsware.HuaweiDswareDriver"}
            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume params failed."
                logger.error("update service cinder template cinder-volume params failed.")
                return False

            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False
                
            params1 = {"storage_driver": "cinder.volume.drivers.dsware.HuaweiDswareDriver",
                      "storage_ip": self.default_target_ips}
            if not cps_server.update_template_params("ceilometer", "ceilometer-agent-hardware", params1):
                print "Update service ceilometer template ceilometer-agent-hardware params failed."
                logger.error("update service ceilometer template ceilometer-agent-hardware params failed.")
                return False
                
            params = {"libvirt_iscsi_use_ultrapath" : "false"}
            if not cps_server.update_template_params("nova", "nova-compute", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False

        elif "file" == self.cinder_default_store:
            params = {"default_target_ips": self.default_target_ips,
                      "storage_controller_ips": self.storage_controller_ips,
                      "default_target_ips": self.default_target_ips,
                      "storage_pool_names": self.storage_pool_names,
                      "storage_usernames": self.storage_usernames,
                      "use_ultrapath_for_image_xfer": "false",
                      "volume_driver": "cinder.volume.drivers.lvm.LVMISCSIDriver"}

            if not cps_server.update_template_params("cinder", "cinder-volume", params):
                print "Update service cinder template cinder-volume params failed."
                logger.error("update service cinder template cinder-volume params failed.")
                return False

            params = {"volume_driver" : "cinder.volume.drivers.lvm.LVMISCSIDriver"}
            if not cps_server.update_template_params("cinder", "cinder-backup", params):
                print "Update service cinder template cinder-backup params failed."
                logger.error("update service cinder template cinder-backup params failed.")
                return False
            
            params1 = {"storage_driver": "cinder.volume.drivers.lvm.LVMISCSIDriver",
                      "storage_ip": self.default_target_ips}
            if not cps_server.update_template_params("ceilometer", "ceilometer-agent-hardware", params1):
                print "Update service ceilometer template ceilometer-agent-hardware params failed."
                logger.error("update service ceilometer template ceilometer-agent-hardware params failed.")
                return False
                
        #提交，当前未做
        cps_server.cps_commit()
        self.__saveToConfigInfoToFile(self.default, "false")


    def test(self):
        print 'test'

class OtherConfiguration:
    def __init__(self, default_file, index):
        self.default = default_file
        self.index = index
        self.cinder_default_store = "other"
        self.storage_config = StorageConfiguration(index)
        self.storage_config_path = "/etc/cinder/cinder_other.conf"
        self.params = cps_server.get_template_params("cinder","cinder-volume")
        if 'other_storage_cfg' in self.params['cfg'] and self.params['cfg']['other_storage_cfg'] and str(index) in self.params['cfg']['other_storage_cfg']:
            self.section_dict = self.params['cfg']['other_storage_cfg'][str(index)]
            for section in self.section_dict:
                if "UserPasswords" in self.section_dict[section]:
                    self.section_dict[section]["UserPasswords"] = crypt.decrypt(self.section_dict[section]["UserPasswords"])
        else:
            self.section_dict = {}
        self.STORAGE_SEC_PREFIX = "BackendStorage"
            
    def config(self):
        while True:
            print "[1] config backend storage"
            print "[2] config normal section"
            sel = raw_input("Please choose [1-2|q][q]")
            if sel == 'q' or sel == '':
                break
            
            backend_config = False
            if sel == '1':
                backend_config = True
            elif sel == '2':
                backend_config = False
            else:
                print "wrong select"
                continue

            while True:
                index = 0
                index_dic = {}
                for section in self.section_dict:
                    if backend_config is True and "volume_driver" in self.section_dict[section]:
                        print "[%d] Modify Backend Storage %s" % (index, section)
                        print "[%d] Delete Backend Storage %s" % (index + 1, section)
                    elif backend_config is False and "volume_driver" not in self.section_dict[section]:
                        print "[%d] Modify Section %s" % (index, section)
                        print "[%d] Delete Section %s" % (index + 1, section)
                    else:
                        continue
                    index_dic[index] = section
                    index_dic[index + 1] = section
                    index += 2
    
                if backend_config is False:
                    print "[%d] Add a new section" % index
                else:
                    print "[%d] Add a new backend storage" % index
                    print "[%d] Add the backend storages in bulk" % (index+1) 

                print "[q] quit"
                sel = raw_input("Please select one to config [0 - %d|q][q]" % (index+1) )
                if sel == 'q' or sel == '':
                    break
                
                sel = int(sel)
                if sel < len(index_dic):
                    if sel % 2 == 0:
                        self.modify_section(index_dic[sel])
                    else:
                        self.delete_section(index_dic[sel])
                elif sel == index:
                    self.add_section(backend_config)
                elif sel == index + 1:
                    result =self.add_section_in_batch()
                    if 1 == result :
                        break


            
    def display_section(self, section):
        if section not in self.section_dict:

            print "no section %s" % section
            return
        print "[%s]" % section
        for k, v in self.section_dict[section].items():
            if "assword" in k:
                print "%s = *****" % (k)
            else:
                print "%s = %s" % (k, v)
        
    def display_all_section(self):
        for section in self.section_dict.keys():
            print section
    def add_section_in_batch(self):
        if not os.path.exists(self.storage_config_path):
            logger.error("the config file [%s]is not exits,please put the config file." % self.storage_config_path)
            print "the config file [%s] is not exits,please put the config file in /etc/cinder/." % self.storage_config_path
            return 1
        fp = open(self.storage_config_path)
        first_line = fp.readline().split()
        if 0 ==len(first_line):
            logger.error("the first line of cinder_other.conf is NULL.")    
            fp.close()
            return 1
        if "backend_id" != first_line[0] or "volume_backend_name" != first_line[1]  or "volume_driver" != first_line[2]:
            print " The value of the first three columns  of the first line  ofthe file[%s] " \
                  "must is  backend_id  volume_backend_name  volume_driver "  % self.storage_config_path
            fp.close()
            return 1
        file_context = fp.readlines()
        for i in range(len(file_context)):
            config_info = file_context[i].split("\r\n")[0].split()
            if 0 == len(config_info):
                continue
            section = config_info[0]
            if section in self.section_dict:
                logger.warning("The key[%s] of  the [%s] line has  already been  exist    " % (section,i))
                continue
            self.section_dict[section]={}
            for j in range(1,len(first_line)):
               self.section_dict[section][first_line[j]] = config_info[j]
        fp.close()



    def add_section(self, is_storage=False):
        if is_storage is False:
            #add new section
            section = ""
            while True:
                input_name = raw_input("Please input section name:")
                if input_name in self.section_dict:
                    print "section name exist"
                elif input_name != '':
                    section = input_name
                    break
            
            self.section_dict[section] = {}
            while True:
                k = raw_input("Please input key:")
                while k == '':
                    k = raw_input("Please input key:")
                
                inputstr = "Please input value:"
                v = getpass.getpass(inputstr) if k in need_crypt_keylist else raw_input(inputstr)
                self.section_dict[section][k] = crypt.encrypt(v) if k in need_crypt_keylist else v                
                self.display_section(section)
                
                y = raw_input("quit[y|n][n]")
                if y == 'y':
                    break
            return
            
        #add new backend storage
        backend_name = raw_input("Please input backend id:")
        while backend_name == "":
            backend_name = raw_input("Please input backend id:")
            
        volume_driver = raw_input("Please input volume driver:")
        while volume_driver == "":
            volume_driver = raw_input("Please input volume driver:")
            
        section = backend_name
        self.section_dict[section] = {}
        self.section_dict[section]["volume_backend_name"] = backend_name
        self.section_dict[section]["volume_driver"] = volume_driver
        while True:
            if volume_driver == driver_map["ipsan"]:
                sel = raw_input("Do you want to config ipsan?[y|n][y]")
                if sel == 'n':
                    break 
                input_str = PrintUtil.get_msg_by_index_ex("1000103", CinderConstant.DEF_DEFAULT_TARGET_IPS)
                default_target_ips = raw_input(input_str)
                if default_target_ips == "":
                    default_target_ips = CinderConstant.DEF_DEFAULT_TARGET_IPS

                targetIpList = default_target_ips.split("|")
                is_Fault = False
                for item in targetIpList:
                    if not cliopt.checkIpFormatIsCorrect(item.split(",")):
                        PrintUtil.print_msg_by_index("1000111")
                        is_Fault = True
                        break

                if is_Fault:
                    continue

                self.section_dict[section]["DefaultTargetIPs"] = default_target_ips

                input_str = PrintUtil.get_msg_by_index_ex("1000104", CinderConstant.DEF_STORAGE_CONTROLLER_IPS)
                storage_controller_ips = raw_input(input_str)
                if storage_controller_ips == "":
                    storage_controller_ips = CinderConstant.DEF_STORAGE_CONTROLLER_IPS

                is_Fault = False
                controlIpList = storage_controller_ips.split("|")
                for item in controlIpList:
                    if len(item.split(',')) != 2:
                        PrintUtil.print_msg_by_index("1000111")
                        is_Fault = True
                        break

                    if not cliopt.checkIpFormatIsCorrect(item.split(',')):
                        PrintUtil.print_msg_by_index("1000111")
                        is_Fault = True
                        break

                if is_Fault:
                    continue

                self.section_dict[section]["ControllerIPs"] = storage_controller_ips

                input_str = PrintUtil.get_msg_by_index_ex("1000107", CinderConstant.DEF_STORAGE_USERNAMES)
                self.section_dict[section]["UserNames"] = CinderConstant.DEF_STORAGE_USERNAMES
                storage_user_names = raw_input(input_str)
                if storage_user_names != '':
                    self.section_dict[section]["UserNames"] = storage_user_names

                self.section_dict[section]["UserPasswords"] = self.__getPassword()

                input_str = PrintUtil.get_msg_by_index_ex("1000106", CinderConstant.DEF_STORAGE_POOL_NAME)
                self.section_dict[section]["StoragePoolNames"] = CinderConstant.DEF_STORAGE_POOL_NAME
                storage_pool_names = raw_input(input_str)
                if storage_pool_names != '':
                    self.section_dict[section]["StoragePoolNames"] = storage_pool_names

                input_str = "Please input the protocols for ipsan [iSCSI|FC][iSCSI]:"
                protocols = raw_input(input_str)
                if protocols == '':
                    self.section_dict[section]["Protocols"] = "iSCSI"
                else:
                    self.section_dict[section]["Protocols"] = protocols

                ## do you want to use UltraPath mutiple path function
                while True:
                    input_str = "Do you want to use UltraPath? [true|false]:"
                    ultra_path_flag = raw_input(input_str)
                    if ultra_path_flag not in ["true", "false"]:
                        print 'Please input correct UltraPath flag.'
                    else:
                        break

                self.section_dict[section]["storage_ultrapathflag"] = ultra_path_flag
            elif volume_driver == driver_map["file"]:
                sel = raw_input("Do you want to config LVM?[y|n][y]")
                if sel == 'n':
                    break 
                self.section_dict[section]["storage_enable_backend"] = self.cinder_default_store + str(self.index)
            elif volume_driver == driver_map["fusionstorage"]:
                sel = raw_input("Do you want to config dsware?[y|n][y]")
                if sel == 'n':
                    break 
                url =  cps_server.get_cpsserver_url()
                all_hosts, all_hosts_ip = cps_server.get_all_hosts()
                if len(all_hosts) < 3:
                    logger.warning("host num little than 3 ,can not deploy dsware!host are %s" %all_hosts)
                    PrintUtil.print_msg_by_index("1000108")
                    continue

                # enable_backend
                self.section_dict[section]["storage_enable_backend"] = backend_name
            break

        while True:
            sel = raw_input("Have extra keys to input?[y|n][n]")
            if sel == '' or sel == 'n':
                break
            k = raw_input("Please input key:")
            while k == '':
                k = raw_input("Please input key:")
                if k in self.section_dict[section]:
                    print "the key %s already exists!" % k
                    k = ''
            
            inputstr = "Please input value:"
            v = getpass.getpass(inputstr) if k in need_crypt_keylist else raw_input(inputstr)
            self.section_dict[section][k] = crypt.encrypt(v) if k in need_crypt_keylist else v   


    
    def modify_section(self, section):
        if section not in self.section_dict:
            print "no section %s" % section
            return
        while True:
            index = 0
            index_dic = {}
            for key in self.section_dict[section]:
                if "assword" in key:
                    print "[%d] Modify Key %s which value is *****" % (index, key)
                else:
                    print "[%d] Modify Key %s which value is %s" % (index, key, self.section_dict[section][key])
                print "[%d] Delete Key %s" % (index + 1, key)
                index_dic[index] = key
                index_dic[index + 1] = key
                index += 2
            print "[%d] Add new key" % index
            print "[q] quit"
            sel = raw_input("Please select one to config [0 - %d|q][q]" % index)
            if sel == 'q' or sel == '':
                break
            
            sel = int(sel)
            if sel < len(index_dic): #modify or delete key
                if sel % 2 == 0: #modify key
                    key = index_dic[sel]
                    inputstr = "Please input new value:"
                    nv = getpass.getpass(inputstr) if key in need_crypt_keylist else raw_input(inputstr)
                    self.section_dict[section][key] = crypt.encrypt(nv) if key in need_crypt_keylist else nv
                else: #delete key
                    self.section_dict[section].pop(index_dic[sel])
            elif sel == index: #add new key
                nk = raw_input("Please input new key:")
                while nk == '':
                    nk = raw_input("Please input new key:")
                
                inputstr = "Please input new value:"
                nv = getpass.getpass(inputstr) if nk in need_crypt_keylist else raw_input(inputstr)
                self.section_dict[section][nk] = crypt.encrypt(nv) if nk in need_crypt_keylist else nv
            else:
                print "wrong input, please select again"
                continue  

            self.display_section(section)
            y = raw_input("quit[y|n][n]")
            if y == 'y':
                break
    
    def delete_section(self, section):
        if section in self.section_dict:
            self.section_dict.pop(section)
            
    def __getPassword(self):
        while 1:
            inputstr = PrintUtil.get_msg_by_index_ex("1000105", "")
            storage_passwords1 = getpass.getpass(inputstr)
            if storage_passwords1 == "":
                print 'Please input password.'
                continue

            inputstr = PrintUtil.get_msg_by_index_ex("1000105", "again")
            storage_passwords2 = getpass.getpass(inputstr)
            if storage_passwords2 == "":
                print 'Please input password.'
                continue

            if storage_passwords1 != storage_passwords2:
                print 'Password inconsistent.Please input password again.'
            else :
                return storage_passwords2
            

if __name__ == "__main__":
    opt = BlockStorageConfiguration()
    allhosts, allhostsip = cps_server.get_all_hosts()

    #这个可以提供一个 专门用来提供输入控制节点的信息

    print "Please choose default(1), config(2), validate(3) or force_clean(4). "
    chooseType = ["1", "2", "3", "4", "5"]
    choose = cliopt.makeChooseByYourself(chooseType)

    if "1" == choose:
        opt.create_def_config(None)
    elif "2" == choose:
        opt.config('1')
        opt.validate('1', None)
    elif "3" == choose:
        opt.validate('1', None)
    elif "4" == choose:

        print "To be continue."
    elif "5" == choose:
        ipList = ["169.test.6.1", "dfa.324,2.9"]
        cliopt.checkIpFormatIsCorrect(ipList)



