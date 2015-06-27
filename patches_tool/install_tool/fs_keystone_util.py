#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import json
import os
import traceback
import getpass
from os.path import join
import requests
import sys
import fs_keystone_constant
import fs_keystone_endpoint
import fs_keystone_server
import fs_log_util
import fs_system_server
import fsutils
import cps_server
import fsCpsCliOpt as cliopt
from openstack_language import DZ_ADMIN_PASSWORD, CLOUD_ADMIN_WRONG, PASSWORD_MORE_THAN_THREE, CLOUD_ADMIN_PASSWORD
from print_msg import PrintMessage

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)
#用户输入的密码缓存
cloud_password = None
cloud_admin_token = None
dc_admin_password = None


class KeystoneUtil():
    def __init__(self):
        pass

    def get_dc_password(self):
        global dc_admin_password
        if not self.get_is_dc_admin_build():
            self.build_dc_admin()

        if dc_admin_password is None or dc_admin_password == "":
            dc_admin_password = self._input_dc_password()
        return dc_admin_password

    def _input_dc_password(self):
        temp_dc_password = os.getenv('DCPASSWORD')
        if temp_dc_password is not None:
            return temp_dc_password
        i = 0
        while i <= 2:
            i += 1
            msg = PrintMessage.get_msg(DZ_ADMIN_PASSWORD)
            dc_password_temp = getpass.getpass(msg)
            if not self._is_dc_password_work(dc_password_temp):
                PrintMessage.print_msg(CLOUD_ADMIN_WRONG)
                continue
            if dc_password_temp != "":
                return dc_password_temp
            else:
                PrintMessage.print_msg(CLOUD_ADMIN_WRONG)
                continue
        PrintMessage.print_msg(PASSWORD_MORE_THAN_THREE)

        choose = "y"
        while 1:
            input_str = "Does dc_admin build?[y|n][y]"
            choose = raw_input(input_str)
            choose = choose.strip()
            if choose in ["y", "n", ""]:
                break
        if choose in ["n"]:
            self.set_dc_admin_build(fs_keystone_constant.SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG_NO)
            print "Please create dc_admin first!"
        else:
            raise  fs_keystone_server.PasswordException("quit due to 3 failed password")

    def get_cloud_password(self):
        global cloud_password
        if cloud_password is None or cloud_password == "":
            cloud_password = self._input_cloud_password()
        return cloud_password

    def _input_cloud_password(self):
        i = 0
        pre_pwenv = os.getenv('CLOUDPASSWORD')
        while i <= 2:
            i += 1
            msg = PrintMessage.get_msg(CLOUD_ADMIN_PASSWORD)
            #预安装
            if pre_pwenv is not None:
                cloud_password_temp = pre_pwenv
            else:
                cloud_password_temp = getpass.getpass(msg)
            if not self._is_password_work(cloud_password_temp):
                PrintMessage.print_msg(CLOUD_ADMIN_WRONG)
                continue
            if cloud_password_temp != "":
                #如果是正确的秘密，赋给缓存
                return cloud_password_temp
            else:
                PrintMessage.print_msg(CLOUD_ADMIN_WRONG)
                continue
        print "Password authentication is not passed."
        raise fs_keystone_server.PasswordException("quit due to 3 failed password")


    def keystone_get_cloud_admin_token(self):
        global cloud_admin_token
        token = None
        if cloud_admin_token is None:
            cloud_admin_token = self.keystone_get_token(fs_keystone_constant.CLOUD_USER, self.get_cloud_password(), fs_keystone_constant.CLOUD_TENANT, None)
            token = cloud_admin_token
        else:
            token = cloud_admin_token

        return token


    def keystone_set_cloud_admin_token(self):
        global cloud_admin_token
        cloud_admin_token = None


    def get_dc_net_project(self):
        local_dc, local_az, domainpostfix = fs_system_server.system_get_local_domain()
        return "dc_network_" + local_dc

    def get_dc_admin_name(self):
        dcname, local_az, domainpostfix = fs_system_server.system_get_local_domain()
        return dcname + '_admin'

    def get_dc_sys_project(self):
        local_dc, local_az, domainpostfix = fs_system_server.system_get_local_domain()
        return "dc_system_" + local_dc

    def set_dc_password(self, dcname):
        pre_pwenv = os.getenv('DCPASSWORD')
        if pre_pwenv is not None:
            return pre_pwenv

        while 1:
            message = "Please set the password for dc admin user(The dc admin user name is %s):" %dcname
            temp_pass = getpass.getpass(message)
            if temp_pass == '':
                print "Please input correct password"
                continue

            temp_pass2 = getpass.getpass("Please input your dc admin password again:")
            if temp_pass2 != temp_pass:
                print "Password is not same!"
                continue
            return temp_pass


    def get_keystone_user_list(self, keystone_endpoint, cloud_admin_token_name):
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': cloud_admin_token_name},
                  'verify': False}
        url = "%s/users" % keystone_endpoint
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return None

            usersList = json.loads(res.text)['users']
            usr_list = []
            for item in usersList:
                usr_list.append(item["name"])

            return usr_list
        except Exception, e:
            LOG.info("run request e:%s, e:%s,"%(traceback.format_exc(), e))
            return None


    def get_keystone_tenant_list(self, keystone_endpoint, cloud_admin_token_name):
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': cloud_admin_token_name},
                  'verify': False}
        url = "%s/tenants" % keystone_endpoint
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return None

            tenantsList = json.loads(res.text)['tenants']
            tenant  = []
            for item in tenantsList:
                tenant.append(item["name"])
            return tenant
        except :
            return None

    def is_dc_admin_create(self,keystone_endpoint, cloud_admin_token):
        local_dc, local_az, domainpostfix = fs_system_server.system_get_local_domain()
        config = ConfigParser.RawConfigParser()
        config.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        glance_dc = fs_system_server.system_get_glance_dc()
        glance_az = fs_system_server.system_get_glance_az()
        glance_flag = glance_dc == local_dc and glance_az == local_az
        if not glance_flag:
            print 'Please build dc_admin at %s %s' % (glance_dc, glance_az)
            return (True, None,None, None, None)
        dc_admin = local_dc + '_admin'
        # crete dc project
        dc_system_name = "dc_system_" + local_dc
        dc_test_name = "dc_test_" + local_dc
        dc_network_name = "dc_network_" + local_dc

        user_list = self.get_keystone_user_list(keystone_endpoint, cloud_admin_token)
        if dc_admin not in user_list:
            return (False, dc_admin, dc_system_name, dc_test_name, dc_network_name)

        tenant_list = self.get_keystone_tenant_list(keystone_endpoint, cloud_admin_token)
        if dc_system_name not in tenant_list:
            return (False, dc_admin, dc_system_name, dc_test_name, dc_network_name)
        if dc_test_name not in tenant_list:
            return (False, dc_admin, dc_system_name, dc_test_name, dc_network_name)
        if dc_network_name not in tenant_list:
            return (False, dc_admin, dc_system_name, dc_test_name, dc_network_name)

        return (True, dc_admin, dc_system_name, dc_test_name, dc_network_name)


    def build_dc_admin(self, dc_password_input=""):
        global dc_admin_password
        if self.get_is_dc_admin_build():
            print 'Dc_admin has been created!'
            if (not dc_password_input == "") and self._is_dc_password_work(dc_password_input):
                self.init_dc_password(dc_password_input)
            return
        elif dc_admin_password  is not None and self._is_dc_password_work(dc_admin_password):
            dc_password_input = dc_admin_password
            LOG.info("build_dc_admin exist, try tetant.")
        elif dc_admin_password is not None :
            dc_password_input = dc_admin_password
            LOG.info("build_dc_admin exist, input exit.")

        dcname, local_az, domainpostfix = fs_system_server.system_get_local_domain()
        config = ConfigParser.RawConfigParser()
        config.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        glance_dc = fs_system_server.system_get_glance_dc()
        glance_az = fs_system_server.system_get_glance_az()
        glance_flag = glance_dc == dcname and glance_az == local_az
        if not glance_flag:
            print 'Please build dc_admin at %s %s' % (glance_dc, glance_az)
            return
        dcadmin = dcname + '_admin'
        keystone_url = fs_keystone_endpoint.calc_endpoint(config, fs_keystone_endpoint.KEYSTONE)
        def_cloud_admin_token = self.keystone_get_token(fs_keystone_constant.CLOUD_USER, self.get_cloud_password(),
                                                        fs_keystone_constant.CLOUD_TENANT, config)
        failed_number = 0
        while 1:
            if not dc_password_input == '':
                dc_dcpassword_temp = dc_password_input
            else:
                dc_dcpassword_temp = self.set_dc_password(dcadmin)

            if self.createUsr(dcadmin, dc_dcpassword_temp, '', def_cloud_admin_token,
                              keystone_url['keystone']['admin_url']):
                break
            else:
                PrintMessage().print_msg(["Create user failed!", "创建用户失败!"], True)
                message_list = ["Please check whether the password meets the requirements according to the information!", "请检查密码是否合法!"]
                PrintMessage().print_msg(message_list, True)
                failed_number += 1
                if failed_number >= 3:
                    message_list = ["Too many failures, please try again later.", "失败次数太多，请稍微重试."]
                    PrintMessage().print_msg(message_list, True)
                    return
                continue
        print 'Build %s success!' %dcadmin

        # crete dc project
        dc_system_name = "dc_system_" + dcname
        dc_test_name = "dc_test_" + dcname
        dc_network_name = "dc_network_" + dcname
        dcproject = {'system': {'name': dc_system_name, 'description': "the system project for " + dcname},
                     'test': {'name': dc_test_name, 'description': "the test project for " + dcname},
                     'network': {'name': dc_network_name, 'description': "the network project for " + dcname}}

        for item in dcproject.iteritems():
            if not self.createProject(item[1]['name'], item[1]['description'], def_cloud_admin_token,
                                      keystone_url['keystone']['admin_url']):
                return False

        # user role add for cloud admin
        user = 'cloud_admin'
        role = 'admin'
        for item in dcproject.iteritems():
            if not self.user_role_add(user, role, item[1]['name'], def_cloud_admin_token,
                                      keystone_url['keystone']['admin_url']):
                return False

        # user role add for dc admin
        dcproject['service'] = {'name': "service", 'description': "xxx"}
        user = dcadmin
        role = 'internal_admin'
        for item in dcproject.iteritems():
            if not self.user_role_add(user, role, item[1]['name'], def_cloud_admin_token,
                                      keystone_url['keystone']['admin_url']):
                return False

        self.set_dc_admin_build(fs_keystone_constant.SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG_YES)
        self.set_dc_admin_name(dcadmin)
        self.init_dc_password(dc_dcpassword_temp)
        message = "3 tenant are created for %s, the tenant name are :%s,%s,%s"%(dcadmin,dc_test_name,dc_network_name, dc_system_name)
        print message
        return True

    def user_role_add(self, username, rolename, tenantname, def_cloud_admin_token, keystone_url):
        # get user id
        userid = self.getUsrid(username, def_cloud_admin_token, keystone_url)
        if userid is None:
            return False

        # get role id
        roleid = self.getRoleid(rolename, def_cloud_admin_token, keystone_url)
        if roleid is None:
            return False

        # get tenant id
        tenantid = self.getTenantid(tenantname, def_cloud_admin_token, keystone_url)
        if tenantid is None:
            return False

        # user role add
        method = "PUT"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        url = "%s/tenants/%s/users/%s/roles/OS-KSADM/%s" % (
            keystone_url, tenantid, userid, roleid)
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if 200 <= res.status_code < 300:
                return True
            elif res.status_code == 409:
                return True
            else:
                return False

        except :
            return False

    def getUsrid(self, username, def_cloud_admin_token, keystone_url):
        # get userid
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        url = "%s/users" % keystone_url
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return None

            userid = None
            for user in json.loads(res.text)['users']:
                if user['name'] == username:
                    userid = user['id']
                    break

            if userid is None:
                return None

            return userid
        except :
            return None

    def getRoleid(self, rolename, def_cloud_admin_token, keystone_url):
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        url = "%s/OS-KSADM/roles" % keystone_url
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return None

            roleid = None
            for role in json.loads(res.text)['roles']:
                if role['name'] == rolename:
                    roleid = role['id']
                    break

            if roleid is None:
                return None
            return roleid
        except :
            return None

    def getTenantid(self, tenantname, def_cloud_admin_token, keystone_url):
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        url = "%s/tenants" % keystone_url
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or 300 <= res.status_code:
                return None

            tenantid = None
            for tenant in json.loads(res.text)['tenants']:
                if tenant['name'] == tenantname:
                    tenantid = tenant['id']
                    break

            if tenantid is None:
                return None
            return tenantid
        except :
            return None

    def createProject(self, name, description, def_cloud_admin_token, keystone_url):
        method = "POST"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        body = {"tenant": {"enabled": True, "name": name, "description": description}}
        kwargs['data'] = json.dumps(body)
        url = "%s/tenants" % keystone_url
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if 200 <= res.status_code < 300:
                return True
            elif res.status_code == 409:
                print "tenant :%s already exist" % name
                return True
            else:
                return False

        except :
            return False

    def createUsr(self, name, password, email, def_cloud_admin_token, keystone_url):
        method = "POST"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        body = {"user": {"email": email, "password": password, "enabled": True, "name": name, "tenantId": None}}
        kwargs['data'] = json.dumps(body)
        url = "%s/users" % keystone_url
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if 200 <= res.status_code < 300:
                return True
            elif res.status_code == 409:
                print "user :%s already exist" % name
                return True
            else:
                return False

        except :
            return False


    def get_is_dc_admin_build(self):
        flag = False
        try:
            config = ConfigParser.RawConfigParser()
            config.read(fs_keystone_constant.KEYSTONE_INI_PATH)
            flag = config.get(fs_keystone_constant.SECTION_KEYSTONE_CONFIG,
                              fs_keystone_constant.SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG) == \
                   fs_keystone_constant.SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG_YES
        except:
            LOG.info("get_is_dc_admin_build exception :%s. "%traceback.format_exc())
            flag = False

        if not flag:
            cloud_admin_token = KeystoneUtil().keystone_get_token("cloud_admin", self.get_cloud_password(), "admin", None)
            keystone_endpoint = fs_keystone_endpoint.calc_endpoint(None, 'keystone')['keystone']['admin_url']
            (flag, dc_admin, dc_system_name, dc_test_name, dc_network_name) =\
                self.is_dc_admin_create(keystone_endpoint, cloud_admin_token)
            LOG.info("get_is_dc_admin_build name=%s,%s,%s,%s. "%(dc_admin, dc_system_name, dc_test_name, dc_network_name))
            if flag :
                self.set_dc_admin_build(fs_keystone_constant.SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG_YES)

        return flag

    def set_dc_admin_build(self, flag):
        config = ConfigParser.RawConfigParser()
        config.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        if not config.has_section(fs_keystone_constant.SECTION_KEYSTONE_CONFIG):
            config.add_section(fs_keystone_constant.SECTION_KEYSTONE_CONFIG)
        config.set(fs_keystone_constant.SECTION_KEYSTONE_CONFIG,
                   fs_keystone_constant.SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG, flag)
        with open(fs_keystone_constant.KEYSTONE_INI_PATH, 'w') as fd:
            config.write(fd)

    def set_dc_admin_name(self, dc_admin):
        config = ConfigParser.RawConfigParser()
        config.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        if not config.has_section(fs_keystone_constant.SECTION_KEYSTONE_CONFIG):
            config.add_section(fs_keystone_constant.SECTION_KEYSTONE_CONFIG)
        config.set(fs_keystone_constant.SECTION_KEYSTONE_CONFIG, fs_keystone_constant.SECTION_KEYSTONE_CONFIG_DC_ADMIN,
                   dc_admin)
        with open(fs_keystone_constant.KEYSTONE_INI_PATH, 'w') as fd:
            config.write(fd)

    def init_dc_password(self, input_name):
        if input_name == '':
            return
        global dc_admin_password
        dc_admin_password = input_name


    def input_dc_password(self):
        i = 0
        while i <= 2:
            i += 1
            msg = PrintMessage.get_msg(DZ_ADMIN_PASSWORD)
            dc_password_temp = getpass.getpass(msg)
            if not self._is_dc_password_work(dc_password_temp):
                PrintMessage.print_msg(CLOUD_ADMIN_WRONG)
                continue
            if dc_password_temp != "":
                return dc_password_temp
            else:
                PrintMessage.print_msg(CLOUD_ADMIN_WRONG)
                continue
        PrintMessage.print_msg(PASSWORD_MORE_THAN_THREE)
        raise fs_keystone_server.PasswordException("quit due to 3 failed password")

    def _is_password_work(self, password):
        config = None
        if os.path.exists(fs_keystone_constant.KEYSTONE_INI_PATH):
            config = ConfigParser.RawConfigParser()
            config.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        if KeystoneUtil().keystone_get_token(fs_keystone_constant.CLOUD_USER, password,
                                             fs_keystone_constant.CLOUD_TENANT, config):
            return True
        else:
            return False

    def _is_dc_password_work(self, password):
        config = ConfigParser.RawConfigParser()
        config.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        if self.keystone_get_token(self.get_dc_admin_name(), password, self.get_dc_net_project(), config):
            return True
        else:
            return False


    def _get_service_list(self, keystone_endpoint, def_cloud_admin_token):
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        url = "%s/OS-KSADM/services" % keystone_endpoint
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return None
            return json.loads(res.text)['OS-KSADM:services']
        except Exception, e:
            return None

    def _get_endpoints_env(self, keystone_endpoint, def_cloud_admin_token):
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        url = "%s/endpoints" % keystone_endpoint
        try:
            res = requests.request(method, url,timeout = 10, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return None
            return json.loads(res.text)['endpoints']
        except Exception, e:
            return None

    def _create_endpoint_env(self, keystone_endpoint, def_cloud_admin_token, create_endpoint, service_id, region_name):
        method = "POST"
        body = {"endpoint": {"adminurl": create_endpoint['admin_url'], "service_id": service_id, "region": region_name,
                             "internalurl": create_endpoint['internal_url'],
                             "publicurl": create_endpoint['public_url']}}
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False, 'data': json.dumps(body)}
        url = "%s/endpoints" % keystone_endpoint
        try:
            res = requests.request(method, url,timeout = 10, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return False
        except Exception, e:
            LOG.info("occur unknow exception : %s,e=%s." %(traceback.format_exc(), e))
            return False
        return True

    def _rmv_single_endpoint_env(self, endpoint_id, keystone_endpoint, def_cloud_admin_token):
        """
        删除单个endpoint。
        """
        method = "delete"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token},
                  'verify': False}
        url = "%s/endpoints/%s" % (keystone_endpoint, endpoint_id)
        try:
            res = requests.request(method, url, timeout = 10,**kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return False

            return True
        except Exception, e:
            LOG.error("exception occurs while running _rmv_single_endpoint_env : %s,%s." %(traceback.format_exc(),e))
            return False


    def _rmv_endpoint_env(self, keystone_endpoint, def_cloud_admin_token, region_name):
        """
        删除环境中的所有endpoint。
        """
        #获取环境中已经创建的endpoint
        check_list = fs_keystone_endpoint.get_check_list()
        services_list = self._get_service_list(keystone_endpoint, def_cloud_admin_token)
        service_id_list = []
        for service in services_list:
            if service['name'] in check_list:
                service_id_list.append(service['id'])
        endpoints_env = self._get_endpoints_env(keystone_endpoint, def_cloud_admin_token)
        for end_env in endpoints_env:
            reg = end_env["region"]
            service_id = end_env["service_id"]
            if reg == region_name and service_id in service_id_list:
                #只删除该az，dc的endpoint
                endpoint_id = end_env['id']
                LOG.info("try remove endpoint_id: %s" % endpoint_id)
                flag = self._rmv_single_endpoint_env(endpoint_id, keystone_endpoint, def_cloud_admin_token)
                if not flag:
                    return False
        return True


    def is_in_check_list(self, node, check_list):
        for check_node in check_list:
            if check_node in node:
                return True
        return False


    def keystone_create_endpoints(self, cf, def_cloud_admin_token, validate_phase):
        """
        创建endpoints.以keystone_endpoint中的值为需要创建的全量数据，若环境中没有创建，则创建。
        """
        #获取keystone的endpoint
        keystone_endpoints = fs_keystone_endpoint.calc_endpoint(cf, 'keystone',is_current_endpoint=True)['keystone']['admin_url']

        #获取当前部署节点的az、dz信息
        az_region = fs_system_server.system_get_local_az()
        dc_region = fs_system_server.system_get_local_dc()
        key_az_region = fs_system_server.system_get_keystone_az()
        key_dc_region = fs_system_server.system_get_keystone_dc()
        glance_az_region = fs_system_server.system_get_glance_az()
        glance_dc_region = fs_system_server.system_get_glance_dc()
        region_name = az_region + "." + dc_region


        #创建前先删除环境中的endpoint
        if validate_phase == 'uds':
            if glance_dc_region == dc_region:
                flag = self._rmv_endpoint_env(keystone_endpoints, def_cloud_admin_token, dc_region)
                if not flag:
                    LOG.error("fail to remove endpoint.")
                    return False
        else:
            flag = self._rmv_endpoint_env(keystone_endpoints, def_cloud_admin_token, region_name)
            if not flag:
                LOG.error("fail to remove endpoint.")
                return False

        #获取services
        services_list = self._get_service_list(keystone_endpoints, def_cloud_admin_token)

        #缓存中获取需要创建的全量endpoint
        pre_endpoint_dict = fs_keystone_endpoint.calc_endpoint(cf, "ALL",False)
        uds_endpoint_dict = {}
        not_uds_endpoint_dict = {}
        for item in pre_endpoint_dict.iteritems():
            if item[0] == 'global_s3' or item[0] == 's3':
                uds_endpoint_dict[item[0]] = item[1]
            else:
                not_uds_endpoint_dict[item[0]] = item[1]
        if validate_phase == 'uds':
            endpoint_list = uds_endpoint_dict
        else:
            endpoint_list = not_uds_endpoint_dict

        #判断keystone与glance是否部署在该az.dz内
        if az_region == key_az_region and dc_region == key_dc_region:
            auth = 'true'
        else:
            auth = 'false'

        if az_region == glance_az_region and dc_region == glance_dc_region:
            image = 'true'
        else:
            image = 'false'
        endpoints_env = self._get_endpoints_env(keystone_endpoints, def_cloud_admin_token)
        #遍历需创建的endpoint，若需要则创建。
        for item in endpoint_list.iteritems():
            region_name = az_region + "." + dc_region
            #去除不需要创建的情况
            if item[0] == 'global_s3':
                if item[1]['admin_url'] == '' and item[1]['internal_url'] == '' and item[1]['public_url'] == '':
                    continue
                # only the first az need to create s3 endpoint
                elif auth == 'false':
                    continue
                elif self.is_enpoint_exist(endpoints_env, item):
                    LOG.info("global_s3 exist %s" % str(item))
                    continue
                else:
                    region_name = dc_region
            elif item[0] == 's3':
                if item[1]['admin_url'] == '' and item[1]['internal_url'] == '' and item[1]['public_url'] == '':
                    continue
                # only the first az need to create s3 endpoint
                elif image == 'false':
                    continue
                elif self.is_enpoint_exist(endpoints_env, item):
                    LOG.info("s3 exist %s" % str(item))
                    continue
                else:
                    region_name = dc_region
            if item[0] == 'swift':
                item[1]['admin_url'] = item[1]['admin_url'].replace("https", "http")
                item[1]['internal_url'] = item[1]['internal_url'].replace("https", "http")
            if item[0] == 'keystone' and auth == 'false':
                continue

            if item[0] == 'glance' and image == 'false':
                continue

            service_id = None
            for service in services_list:
                if service['name'] == item[0]:
                    service_id = service['id']
                    break

            if service_id is None:
                LOG.error("service name: %s not exist" % item[0])
                continue
                #创建endpoint
            LOG.info("try create endpoint :%s" % item[0])
            flag = self._create_endpoint_env(keystone_endpoints, def_cloud_admin_token, item[1], service_id,
                                             region_name)
            if not flag:
                LOG.error("Fail to create endpoint!")
                return False

        return True

    def is_enpoint_exist(self, endpoints_env, item):
        for end_env in endpoints_env:
            if item[1]['admin_url'] == end_env["adminurl"] and item[1]['internal_url'] == end_env["internalurl"] and item[1]['public_url'] == end_env["publicurl"]:
                return True
        return False

    def keystone_get_token(self, username, password, tenant, cf):
        """
        获取token。
        @rtype : object
        @param username:获取token的用户名
        @param password:获取token的密码
        @param tenant:例如”service“
        @param endpoint_url:endpoint的url，例如https://identity.az1.dc1.vodafone.com:8023/identity/v2.0/tokens
        """
        endpoint_url = fs_keystone_endpoint.calc_endpoint(cf, "keystone")['keystone']['admin_url'] + "/tokens"
        method = "POST"
        kwargs = {'headers': {"Content-type": "application/json"}, 'verify': False}
        body = {'auth': {'passwordCredentials': {'username': username, 'password': password}, 'tenantName': tenant}}
        kwargs['data'] = json.dumps(body)
        try:
            LOG.info("enter keystone_get_token")
            res = requests.request(method, endpoint_url, timeout = 10,**kwargs)
            LOG.info(
                "keystone_get_token run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                    endpoint_url, method, str(res.status_code), fsutils.get_safe_message(kwargs),
                    fsutils.get_safe_message(res.text)))
            if res.status_code < 200 or res.status_code >= 300:
                return None

            return json.loads(res.text)['access']['token']['id']
        except Exception, e:
            LOG.info("keystone_get_token run request :%s, method:%s,  data:%s" % (
                endpoint_url, method, fsutils.get_safe_message(kwargs)))
            LOG.info("keystone_get_token %s" % traceback.format_exc())
            return None

    def keystone_get_data(self, section, keys):
        """
        获取配置文件中的数据
        """
        cf = ConfigParser.ConfigParser()
        if not os.path.exists(fs_keystone_constant.KEYSTONE_INI_PATH):
            LOG.info("get_data.default.ini doesn't exist,file is %s." % fs_keystone_constant.KEYSTONE_INI_PATH)
            return None
        else:
            try:
                cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)
                values = []
                for key in keys:
                    value = cf.get(section, key)
                    values.append(value)
                return values
            except Exception, err:
                LOG.error("get data file. Exception, e:%s,e:%s." % (traceback.format_exc(), err))
                return None

    def keystone_write_data(self, section, key, value):
        """
        修改配置文件中的值,将传入参数的值持久化到配置文件当中。
        """
        cf = ConfigParser.ConfigParser()

        if not os.path.exists(fs_keystone_constant.KEYSTONE_INI_PATH):
            #如果文件不存在，则创建
            ini_file = open(fs_keystone_constant.KEYSTONE_INI_PATH, 'w')
            ini_file.close()
            LOG.debug("write_data.default.ini doesn't exist,file is %s." % fs_keystone_constant.KEYSTONE_INI_PATH)
        try:
            cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)
            if not cf.has_section(section):
                cf.add_section(section)
            cf.set(section, key, value)
            cf.write(open(fs_keystone_constant.KEYSTONE_INI_PATH, "w"))
            return True
        except Exception, err:
            LOG.error("write data file. Exception, e:%s" % traceback.format_exc())
            return False
    def get_http_type_ex(self):
        http_type = "https"
        cf = ConfigParser.ConfigParser()
        cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        if cf.has_section("http_mode"):
            if cf.has_option("http_mode","url_http_type"):
                http_type = cf.get("http_mode", "url_http_type")
        return http_type
    def get_current_http_type(self):
        http_type = "https" 
        cf = ConfigParser.ConfigParser()
        cf.read(fs_keystone_constant.KEYSTONE_INI_PATH)
        if cf.has_section("http_mode"):
            if cf.has_option("http_mode","current_http_type"):
                http_type = cf.get("http_mode", "current_http_type")
        return http_type
    def get_haproxy_cfg(self):
        ret_port=None
        try:
            cpsurl = cps_server.get_cpsserver_url()
            cfg = cliopt.getTemplatePrams(cpsurl,"haproxy","haproxy", "commited")
            json_external_api=json.loads(cfg["external_api_ip"])
            LOG.info(json_external_api)
            for item in json_external_api:
                backendservice = item.get("backendservice")
                if backendservice == "all":
                    ret_port = item.get("frontendport") 
                    break
            if ret_port is None:
                for item in json_external_api:
                    ret_port = item.get("frontendport")
                    break
            LOG.info("get haproxy port:%s",ret_port)
            return ret_port
        except Exception, e:
            LOG.error("run request exception: %s, e:%s." % (traceback.format_exc(), e))
            return None
    def get_haproxy_http_type(self):
        try:
            cpsurl = cps_server.get_cpsserver_url()
            cfg = cliopt.getTemplatePrams(cpsurl,"haproxy","haproxy", "commited")
            json_external_api=json.loads(cfg["external_api_ip"])
            frontssl = json.loads(cfg["frontssl"])
            LOG.error("external_api_ip is %s,frontssl is %s " % (json_external_api,frontssl))
            if len(json_external_api) == 0:
                LOG.error("external_api_ip is not configured,please check haproxy config.")
                return None
            if len(frontssl) == 0 :
                return "http"
            else:
                return "https"
        except Exception, e:
            LOG.error("run request exception: %s,e:%s." % (traceback.format_exc(), e))
            return None
