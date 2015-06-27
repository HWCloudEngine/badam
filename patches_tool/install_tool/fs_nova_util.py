#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import json
import os
import traceback
from os.path import join
import requests
import fs_keystone_server
import fs_log_util
import fs_nova_constant
import fs_system_server

#日志定义
import fsutils

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class NovaUtil():
    def __init__(self):
        pass

    def nova_get_data(self, section, keys):
        """
        获取配置文件中的数据
        """
        cf = ConfigParser.RawConfigParser()
        if not os.path.exists(fs_nova_constant.NOVA_INI_PATH):
            LOG.info("get_data.default.ini doesn't exist,file is %s." % fs_nova_constant.NOVA_INI_PATH)
            return None
        else:
            try:
                cf.read(fs_nova_constant.NOVA_INI_PATH)
                values = []
                for key in keys:
                    value = cf.get(section, key)
                    values.append(value)
                return values
            except Exception, err:
                LOG.error("get data file. Exception, e:%s, err:%s" % (traceback.format_exc(), err))
                return None

    def nova_get_data_by_key(self, section, key):
        """
        获取配置文件中的数据
        """
        cf = ConfigParser.RawConfigParser()
        if not os.path.exists(fs_nova_constant.NOVA_INI_PATH):
            LOG.info("get_data.default.ini doesn't exist,file is %s." % fs_nova_constant.NOVA_INI_PATH)
            return None
        else:
            try:
                cf.read(fs_nova_constant.NOVA_INI_PATH)
                if not cf.has_option(section, key):
                    return None
                value = cf.get(section, key)
                return value
            except Exception, err:
                LOG.error("get data file. Exception, e:%s err:%s." % (traceback.format_exc(), err))
                return None

    def nova_get_config(self):
        try:
            cf = ConfigParser.RawConfigParser()
            if not os.path.exists(fs_nova_constant.NOVA_INI_PATH):
                #若配置文件不存在，则直接退出
                LOG.error("default.ini doesn't exist,file is %s." % fs_nova_constant.NOVA_INI_PATH)
                return None
            else:
                cf.read(fs_nova_constant.NOVA_INI_PATH)
                return cf
        except:
            return None


    def nova_write_data(self, section, keys_and_values):
        """
        修改配置文件中的值,将传入参数的值持久化到配置文件当中。
        """
        cf = ConfigParser.RawConfigParser()
        if not os.path.exists(fs_nova_constant.NOVA_INI_PATH):
            LOG.debug("write_data.default.ini doesn't exist,file is %s." % fs_nova_constant.NOVA_INI_PATH)
            #如果文件不存在，则创建
            ini_file = open(fs_nova_constant.NOVA_INI_PATH, 'w')
            ini_file.close()

        try:
            cf.read(fs_nova_constant.NOVA_INI_PATH)
            if not cf.has_section(section):
                cf.add_section(section)
            for k, v in keys_and_values.iteritems():
                cf.set(section, k, v)
            cf.write(open(fs_nova_constant.NOVA_INI_PATH, "w"))
            return True
        except Exception, err:
            LOG.error("write data file. Exception, e:%s,err:%s." % (traceback.format_exc(), err))
            return False

    def _get_aggr(self, dc_admin_token, nova_url, tenant_id):
        """
        查询aggregates
        """
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dc_admin_token},
                  'verify': False}
        nova_url = nova_url.replace("$(tenant_id)s", "")
        url = "%s%s/os-aggregates" % (nova_url, tenant_id)
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (url, method, str(res.status_code), fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return None
            return json.loads(res.text)
        except Exception, e:
            LOG.error("_get_aggr Exception, e:%s,err:%s." % (traceback.format_exc(), e))
            return None

    def rmv_aggr_for_ctrl_host(self):
        """
        从单板池中删除首节点，如此虚拟机则可以创建在首节点中。
        """

        #获取token
        dc_token = fs_keystone_server.keystone_get_dc_token()
        if dc_token is None:
            LOG.error("fail to get token")
            return False

        keystone_url = fs_keystone_server.keystone_get_endpoint("keystone")['keystone']['admin_url']
        tenant_id = self._get_tenant_id(keystone_url, fs_keystone_server.keystone_get_dc_sys_project(), dc_token)

        if tenant_id is None:
            LOG.error("fail to get tenant id")
            return False

        nova_url = fs_keystone_server.keystone_get_endpoint("nova")['nova']['internal_url']
        #查询aggregates，看是否创建
        tex = self._get_aggr(dc_token, nova_url, tenant_id)
        if tex is None:
            LOG.error("fail to get_aggr.")
            return False

        aggr_ids = []
        for item in tex["aggregates"]:
            aggr_ids.append(item["id"])

        if len(aggr_ids) == 0:
            LOG.info("aggr_id doesn't exist")
            return True

        #删除aggr_id中的控制节点
        hosts = self._get_ctrl_host()
        for aggr_id in aggr_ids:
            for host in hosts:
                flag = self._aggr_host_rmv(aggr_id, host, tenant_id, dc_token, nova_url)
                if not flag:
                    LOG.error("fail to rmv aggr host")
                    return False
        return True

    def _aggr_host_rmv(self, aggr_id, host, tenant_id, dc_admin_token, nova_url):
        """
        删除aggregates。
        """
        method = "POST"
        body = {"remove_host": {"host": host}}
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dc_admin_token},
                  'verify': False,
                  'data': json.dumps(body)}

        nova_url = nova_url.replace("$(tenant_id)s", "")
        url = "%s%s/os-aggregates/%s/action" % (nova_url, tenant_id, aggr_id)
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (url, method, str(res.status_code), fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
            if res.status_code == 404:
                LOG.info("host(%s) already remove from aggr(id:%s)" % (str(host), str(aggr_id)))
                return True
            if res.status_code < 200 or res.status_code >= 300:
                #该单板不存在的的情况还需要考虑
                return False
            return True
        except Exception, e:
            LOG.error("run request :%s, method:%s, exception: %s, e:%s." % (url, method, traceback.format_exc(), e))
            return False

    def create_aggr_for_ctrl_host(self):
        """
        创建单板池，然后再规定虚拟机不可创建在单板池上，则可以实现首节点不创建虚拟机的功能。
        """
        #获取token
        dc_name = fs_system_server.system_get_local_dc()
        dc_sys_project = "dc_system_" + dc_name

        dc_token = fs_keystone_server.keystone_get_dc_token()
        if dc_token is None:
            LOG.error("fail to get token")
            return False

        keystone_url = fs_keystone_server.keystone_get_endpoint("keystone")['keystone']['admin_url']
        #获取"name": "admin"的tenant_id
        tenant_id = self._get_tenant_id(keystone_url, dc_sys_project, dc_token)

        if tenant_id is None:
            LOG.error("fail to get tenant id")
            return False

        aggr_name = "manage-aggr"
        az_name = "manage-az"
        nova_url = fs_keystone_server.keystone_get_endpoint("nova")['nova']['internal_url']

        #创建单板池，如果存在则将单板池的id返回
        aggr_id = self._create_aggr(aggr_name, az_name, tenant_id, dc_token, nova_url)
        if aggr_id is None:
            LOG.error("fail to create aggr_id")
            return None

        hosts = self._get_ctrl_host()

        #将控制节点加入到单板池中
        for host in hosts:
            flag = self._aggr_host_add(aggr_id, host, tenant_id, dc_token, nova_url)
            if not flag:
                LOG.error("fail to add aggr host")
                return False

        return True

    def _get_ctrl_host(self):
        """
        获取ctrl_host信息，从default_sys.ini中读取。
        """
        try:
            hosts = fs_system_server.system_get_ctrl_hosts()
            LOG.info("host id is %s" % str(hosts))
            return json.loads(hosts)
        except Exception, err:
            LOG.error("_get_ctrl_host. Exception, e:%s , err=%s." % (traceback.format_exc(), err))
            return False

    def _aggr_host_add(self, aggr_id, host, tenant_id, dc_admin_token, nova_url):
        method = "POST"
        body = {"add_host": {"host": host}}
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dc_admin_token},
                  'verify': False, 'data': json.dumps(body)}

        nova_url = nova_url.replace("$(tenant_id)s", "")
        url = "%s%s/os-aggregates/%s/action" % (nova_url, tenant_id, aggr_id)
        try:
            res = requests.request(method, url, **kwargs)
            if res.status_code == 409:
                LOG.info("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
                return True
            LOG.info("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return False
            return True
        except Exception, e:
            return False


    def _create_aggr(self, aggr_name, az_name, tenant_id, dc_admin_token, nova_url):
        #查询单板池，看是否存在
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dc_admin_token}, 'verify': False}
        nova_url = nova_url.replace("$(tenant_id)s", "")
        url = "%s%s/os-aggregates" % (nova_url, tenant_id)
        try:
            res = requests.request(method, url, **kwargs)

            if res.status_code < 200 or res.status_code >= 300:
                LOG.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
                return None
            LOG.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
            #获取查询的单板池，满足："name": aggr_name, "availability_zone": az_name；若存在，则直接返回id；若不存在则继续
            for aggregates in json.loads(res.text)['aggregates']:
                if aggregates["name"] == aggr_name and aggregates["metadata"]["availability_zone"] == az_name:
                    return aggregates["id"]
                    #若不存在则继续
            LOG.info("aggregates hasn't existed, continue.")
        except Exception, e:
            LOG.error("run request :%s, method:%s,  exception: %s, e:%s." % (url, method, traceback.format_exc(), e))
            return None
            #没有存在单板池，进行创建
        method = "POST"
        body = {"aggregate": {"name": aggr_name, "availability_zone": az_name}}
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': dc_admin_token}, 'verify': False,
                  'data': json.dumps(body)}

        nova_url = nova_url.replace("$(tenant_id)s", "")
        url = "%s%s/os-aggregates" % (nova_url, tenant_id)
        try:
            res = requests.request(method, url, **kwargs)

            if res.status_code < 200 or res.status_code >= 300:
                LOG.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
                return None
            LOG.info("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
            return json.loads(res.text)['aggregate']['id']
        except Exception, e:
            return None

    def _get_tenant_id(self, keystone_url, tenant_name, def_cloud_admin_token):
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        url = "%s/tenants" % keystone_url
        try:
            res = requests.request(method, url, **kwargs)
            if res.status_code < 200 or res.status_code >= 300:
                LOG.error("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))
                return None
            LOG.info("run request :%s, method:%s, data:%s, the response info is :%s" % (url, method, fsutils.get_safe_message(kwargs), fsutils.get_safe_message(res.text)))

            tenant_id = None
            for tenant in json.loads(res.text)['tenants']:
                if tenant['name'] == tenant_name:
                    tenant_id = tenant['id']
                    break

            if tenant_id is None:
                return None
            return tenant_id
        except Exception, e:
            LOG.error("run request :%s, method:%s, exception: %s" % (url, method, e))
            return None