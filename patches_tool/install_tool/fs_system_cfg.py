#!/usr/bin/env python
#-*-coding:utf-8-*-
import ConfigParser
import commands
import fs_system_server
import requests
import os
import sys
import json
import traceback
import time
import change_auth_mode
import fs_glance_server
import fs_keystone_cfg
import fs_keystone_server
import fs_log_util
import cps_server
import fsinstall
import fsutils as utils
import fs_system_constant
import fs_system_util
from print_msg import PrintMessage as PrintUtil
from os.path import join

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class SysConfig():
    def __init__(self):
        self.glance_dc = "1"
        self.glance_az = "1"
        self.keystone_dc = "1"
        self.keystone_az = "1"
        self.glance_type_file = 'file'
        self.glance_type_uds = 'uds+https'
        self.def_s3_publicurl = ''
        self.def_s3_internalurl = ''
        self.def_s3_adminurl = ''
        self.def_global_publicurl = ''
        self.def_global_internalurl = ''
        self.def_global_adminurl = ''
        self.def_glance_default_store = self.glance_type_file
        self.network_type_api = 'external_api'
        self.network_type_om = 'external_om'
        self.auth_mode_change = False
        self.config_file_name = "system.ini"


    def get_dns_server(self):
        result = cps_server.get_template_params('dns', 'dns-server')
        if result is None:
            return '', '', ''
        dns_address = result['cfg']['address']
        dns_network = result['cfg']['network']
        dns_server = result['cfg']['server']
        return dns_address, dns_network, dns_server


    def runCommand(self, cmd):
        try:
            (status, output) = commands.getstatusoutput(cmd)
            return status, output
        except Exception, e:
            LOG.error("failed: %s, e:%s." % (traceback.format_exc(), e))
            return 1, output


    def update_dns_address(self, cfg_dict):
        return cps_server.update_template_params('dns', 'dns-server', cfg_dict)


    def input_dns_address(self, dns_address):
        while 1:
            try:
                print_uds_address()
                inputstr = PrintUtil.get_msg_by_index("1000205") % dns_address
                external_dns_ip = raw_input(inputstr)
                external_dns_ip = external_dns_ip.strip()
                if external_dns_ip == "" or external_dns_ip == dns_address:
                    break
                flag, new_external_dns_ip = self.check_dns_address(external_dns_ip)
                if not flag:
                    PrintUtil.print_msg_by_index("1000206")
                    continue
                fs_system_util.save_one_option(fs_system_constant.SECTION_DNS_CONFIG,
                                               fs_system_constant.SECTION_SYS_CONFIG_DNS_ADDRESS, new_external_dns_ip)
                break
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                PrintUtil.print_msg_by_index("1000208")
                LOG.error("failed: %s" % str(traceback.format_exc()))
                break

    def input_dns_server(self, dns_server):
        new_external_dns_server = ""
        while 1:
            try:
                inputstr = PrintUtil.get_msg_by_index("1000209") % dns_server
                external_dns_server = raw_input(inputstr)
                external_dns_server = external_dns_server.strip()
                if external_dns_server == "" or external_dns_server == dns_server:
                    break
                flag, new_external_dns_server = self.check_dns_server(external_dns_server)
                if not flag:
                    PrintUtil.print_msg_by_index("1000210")
                    continue
                fs_system_util.save_one_option(fs_system_constant.SECTION_DNS_CONFIG,
                                               fs_system_constant.SECTION_SYS_CONFIG_DNS_SERVER,
                                               external_dns_server)
                break
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                PrintUtil.print_msg_by_index("1000210")
                LOG.error("failed: %s new_external_dns_server =%s."
                          "" % (traceback.format_exc(), new_external_dns_server))
                break

    def dns_netwrok_str_to_json(self, dns_network_str):
        if dns_network_str == '' or dns_network_str == None:
            return []
        try:
            return json.loads(dns_network_str)
        except:
            return []

    def input_new_ip(self):
        while 1:
            ip = raw_input("Please input ip:")
            if utils.is_ip(ip) or ip.strip() == "":
                return ip.strip()
            print "Please input correct ip"

    def input_new_gateway(self):
        while 1:
            gateway = raw_input("Please input gateway:")
            if utils.is_ip(gateway) or gateway.strip() == "":
                return gateway.strip()
            print "Please input correct gateway"

    def input_new_mask(self):
        while 1:
            mask = raw_input("Please input mask:[1-32]")
            if mask.isdigit():
                try:
                    mask_digit = int(mask)
                    if 0 < mask_digit < 33:
                        return mask
                except:
                    pass
            elif mask.strip() == "":
                return ""
            print "Please input correct mask"

    def input_new_systeminterface(self):
        while 1:
            systeminterface = raw_input("Please input systeminterface:")
            if systeminterface.strip() == "":
                return ""
            try:
                sys_interfaces = cps_server.get_sys_interfaces_list()
                for network in sys_interfaces:
                    if network["name"] == "internal_base" or network["name"] == "storage_data0" or network["name"] \
                            == "storage_data1" or network["name"] == "tunnel_bearing":
                        continue
                    trip_sysinterface = systeminterface.strip()
                    if network["name"] == trip_sysinterface :
                        return systeminterface.strip()
            except:
                LOG.error("Fail to get_sys_interfaces.sys_interfaces is %s  exception:%s." % (str(sys_interfaces),
                                                                                              traceback.format_exc()))
                return systeminterface.strip()
            print "Please input correct systeminterface"


    def input_dns_network(self, dns_network):
        dns_network_list = self.dns_netwrok_str_to_json(dns_network)
        is_changed = False
        while 1:
            try:
                temp_dict = {}
                i = 0
                for network_item in dns_network_list:
                    i += 1
                    temp_dict[str(i)] = network_item
                    print "[%s] Remove %s" % (str(i), str(network_item))
                print "[a] Add network"
                print "[s] Save&quit"
                if i == 0:
                    out_put_str = "Please choose [a|s][s]"
                elif i == 1:
                    out_put_str = "Please choose [1|a|s][s]"
                else:
                    out_put_str = "Please choose [1-%s|a|s][s]" % str(i)
                external_dns_network = raw_input(out_put_str)
                if external_dns_network == "" or external_dns_network == 's':
                    break
                if external_dns_network == 'a':
                    dns_network_list.append({"ip": self.input_new_ip(), "mask": self.input_new_mask(),
                                             "systeminterface": self.input_new_systeminterface(),
                                             "gateway": self.input_new_gateway()})
                    is_changed = True
                    continue
                if temp_dict.has_key(external_dns_network):
                    dns_network_list.remove(temp_dict.get(external_dns_network))
                    is_changed = True
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                PrintUtil.print_msg_by_index("1000212")
                LOG.error("failed: %s" % str(traceback.format_exc()))
                break
        if is_changed:
            fs_system_util.save_one_option(fs_system_constant.SECTION_DNS_CONFIG,
                                           fs_system_constant.SECTION_SYS_CONFIG_DNS_NETWORK,
                                           json.dumps(dns_network_list))

    def config_dns(self):
        dns_address, dns_network, dns_server = self.get_dns_server()
        while 1:
            print "[1] Dns address"
            print "[2] Dns server"
            print "[3] Dns network"
            print "[s] Save&quit"
            def_choose = 's'
            input_string = "Please choose [1-3|s][%s]" % def_choose
            input_choose = raw_input(input_string)
            if input_choose == '':
                input_choose = def_choose
            if input_choose == '1':
                self.input_dns_address(dns_address)
                continue
            if input_choose == '2':
                self.input_dns_server(dns_server)
                continue
            if input_choose == '3':
                self.input_dns_network(dns_network)
                continue
            if input_choose == 's':
                break
            print "Please input correct character,only support [1-3|s]"


    def check_dns_address(self, external_dns_ip):
        new_dns_address_list = []
        dns_ip_list = external_dns_ip.split(',')
        for dns_ip in dns_ip_list:
            dns_ip = dns_ip.strip()
            flag, dns_ip_temp = self.check_one_dns_address(dns_ip)
            if flag:
                new_dns_address_list.append(dns_ip_temp)
            else:
                return False, ''
        return True, ','.join(new_dns_address_list)

    def check_dns_server(self, external_dns_server):
        new_dns_server_list = []
        dns_server_list = external_dns_server.split(',')
        for dns_server in dns_server_list:
            dns_server = dns_server.strip()
            flag, dns_ip_temp = self.check_one_dns_server(dns_server)
            if flag:
                new_dns_server_list.append(dns_ip_temp)
            else:
                return False, ''
        return True, ','.join(new_dns_server_list)

    def check_one_dns_address(self, dns_ip):
        dns_ip = dns_ip.strip('/')
        dns_ip_split_list = dns_ip.split('/')
        if len(dns_ip_split_list) != 2:
            return False, ''
        domain = dns_ip_split_list[0].strip()
        ip = dns_ip_split_list[1].strip()
        if not utils.is_ip(ip):
            return False, ''
        return_dns_address = '/' + domain + '/' + ip
        return True, return_dns_address

    def check_one_dns_server(self, dns_server):
        dns_server = dns_server.strip('/')
        dns_server_split_list = dns_server.split('/')
        if len(dns_server_split_list) != 2:
            return False, ''
        domain = dns_server_split_list[0].strip()
        ip_port_dev = dns_server_split_list[1].strip()
        ip = ip_port_dev.replace("@", "#").split("#")[0]
        if not utils.is_ip(ip):
            return False, ''
        return_dns_address = '/' + domain + '/' + ip_port_dev
        return True, return_dns_address

    def input_global_domain_url(self):
        port = ""
        while 1:
            try:
                inputstr = "Please set domain global_s3 for uds such as 'url:port': "
                domain_url = raw_input(inputstr)
                if domain_url == "":
                    print "Please set the correct domain."
                    continue
                url, port = self.get_url_port_by_domain(domain_url)
                if url:
                    return domain_url
                else:
                    print "Please set the correct domain ."
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please set the correct domain."
                LOG.error("input_global_domain_url port %s" % port)
                continue

    def input_global_external_ip(self):
        while 1:
            try:
                inputstr = "Please set the global_s3 external network ip that uds used to provide http request: "
                external_ip = raw_input(inputstr)
                if external_ip == "":
                    print "Please input correct ip address!"
                    continue
                elif utils.is_ip(external_ip):
                    return external_ip
                else:
                    print "Please input correct ip address!"
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please input correct ip address!"
                continue

    def input_global_uds_port(self):
        while 1:
            try:
                inputstr = "Please set the global_s3 port that uds used to provide http request : "
                uds_port = raw_input(inputstr)
                if uds_port == "":
                    print 'You must input correct port number,please input again.'
                    continue
                uds_port = int(uds_port)
                if 0 <= uds_port <= 65535:
                    return str(uds_port)
                else:
                    print 'you must input correct port number,please input again.'
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print 'you must input correct port number,please input again.'
                continue

    def input_domain_url(self):
        while 1:
            try:
                inputstr = "Please set domain for uds such as 'url:port'  : "
                domain_url = raw_input(inputstr)
                if domain_url == "":
                    print "Please set the correct domain."
                    continue
                url, port = self.get_url_port_by_domain(domain_url)
                if url:
                    return domain_url
                else:
                    print "Please set the correct domain."
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please set the correct domain url."
                continue

    def get_url_port_by_domain(self, domain):
        try:
            if ':' in domain:
                port = domain.split(':')[-1]
                port_int = int(port)
                if port_int < 1 or port_int > 65535:
                    LOG.error("port is not right.")
                    return None, None
                url = domain[0:(len(domain) - len(port) - 1)]
                return url, port
            else:
                LOG.error("there is no : in")
                return None, None
        except:
            LOG.error(traceback.format_exc())
            return None, None

    def input_external_ip(self):
        while 1:
            try:
                inputstr = "Please set the external network ip that uds used to provide http request: "
                external_ip = raw_input(inputstr)
                if external_ip == "":
                    print "Please input correct ip address!"
                    continue
                elif utils.is_ip(external_ip):
                    return external_ip
                else:
                    print "Please input correct ip address!"
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please input correct ip address!"
                continue

    def input_uds_port(self):
        while 1:
            try:
                inputstr = "Please set the port that uds used to provide http request : "
                uds_port = raw_input(inputstr)
                if uds_port == "":
                    print 'You must input correct port number,please input again.'
                    continue
                uds_port = int(uds_port)
                if 0 <= uds_port <= 65535:
                    return str(uds_port)
                else:
                    print 'You must input correct port number,please input again.'
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print 'You must input correct port number,please input again.'
                continue

    def input_uds_flag(self):
        while 1:
            try:
                default_uds_flag = "n"
                inputstr = "Does uds will be used as backend store for glance and log in this az [y|n][%s] :" % default_uds_flag
                uds_flag = raw_input(inputstr)
                if uds_flag == "":
                    return default_uds_flag
                elif uds_flag == 'y' or uds_flag == 'n':
                    return uds_flag
                else:
                    print "Please input correct character,only support \'y\',\'n\',\'\'!"
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please input correct character,only support \'y\',\'n\',\'\'!"
                continue

    def save_uds(self, s3_publicurl, s3_internalurl, s3_adminurl, s3_address):
        if s3_internalurl != '':
            fs_glance_server.glance_set_s3_internal_url(s3_internalurl)
        if s3_adminurl != '':
            fs_glance_server.glance_set_s3_admin_url(s3_adminurl)
        if s3_publicurl != '':
            fs_glance_server.glance_set_s3_public_url(s3_publicurl)
        if s3_address != '':
            fs_glance_server.glance_set_s3_address(s3_address)

    def getUsrid(self, username, def_cloud_admin_token, keystone_url):
        LOG.debug("enter into getUsrid")
        # get userid
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token}}
        kwargs['verify'] = False
        url = "%s/users" % keystone_url
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("getUsridrun request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), utils.get_safe_message(kwargs), utils.get_safe_message(res.text)))

            if res.status_code < 200 or res.status_code >= 300:
                LOG.error("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
                return None

            userid = None
            for user in json.loads(res.text)['users']:
                if user['name'] == username:
                    userid = user['id']
                    break

            if userid is None:
                LOG.error(
                    "run request :%s, method:%s, username: %s not exist" % (url, method, username))
                return None

            LOG.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return userid
        except Exception, e:
            LOG.error("run request :%s, method:%s, exception: %s" % (url, method, e))
            LOG.error("failed: %s" % str(traceback.format_exc()))
            return None


    def getTenantid(self, tenantname, def_cloud_admin_token, cpsurl):
        method = "GET"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token}}
        kwargs['verify'] = False
        url = "%s/tenants" % cpsurl
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), utils.get_safe_message(kwargs), utils.get_safe_message(res.text)))

            if (res.status_code < 200 or res.status_code >= 300):
                return None
            tenantid = None
            for tenant in json.loads(res.text)['tenants']:
                if tenant['name'] == tenantname:
                    tenantid = tenant['id']
                    break
            if tenantid == None:
                LOG.error(
                    "run request :%s, method:%s, username: %s not exist" % (url, method, tenantname))
                return None
            LOG.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return tenantid
        except Exception, e:
            LOG.error("run request :%s, method:%s, exception: %s" % (url, method, e))
            return None

    def getAkSk(self, userid, tenantid, def_cloud_admin_token, cpsurl):
        method = "POST"
        kwargs = {'headers': {"Content-type": "application/json", 'X-Auth-Token': def_cloud_admin_token}}
        kwargs['verify'] = False
        body = {'tenant_id': tenantid}
        kwargs['data'] = json.dumps(body)
        url = "%s/users/%s/credentials/OS-EC2" % (cpsurl, userid)
        try:
            res = requests.request(method, url, **kwargs)
            LOG.info("run request :%s, method:%s, res.status_code:%s, data:%s, the response info is :%s" % (
                url, method, str(res.status_code), utils.get_safe_message(kwargs), utils.get_safe_message(res.text)))

            if (res.status_code < 200 or res.status_code >= 300):
                return None

            result = json.loads(res.text)
            accesskey = result['credential']['access']
            secretkey = result['credential']['secret']

            LOG.info("run request :%s, method:%s, the response info is :%s" % (url, method, res.text))
            return accesskey, secretkey
        except Exception, e:
            LOG.error("run request :%s, method:%s, exception: %s" % (url, method, e))
            return None


    def update_uds_template(self, uds_domain_url, uds_external_ip, uds_port):
        cf = ConfigParser.ConfigParser()
        cf.read(fs_system_constant.SYSTEM_INI_PATH)
        glance_dc = fs_system_server.system_get_glance_dc()
        glance_az = fs_system_server.system_get_glance_az()
        local_dc, local_az = fs_system_util.get_local_dc_az()
        glance_flag = glance_dc == local_dc and glance_az == local_az
        LOG.info(
            "glance_flag is %s. glance_dc is %s;local_dc is %s , uds_external_ip %s, uds_port %s"
            "" % (str(glance_flag), str(glance_dc), str(local_dc), uds_external_ip, uds_port))
        fs_keystone_server.keystone_get_cloud_password()
        def_cloud_admin_token = fs_keystone_server.keystone_get_cloud_token()

        if def_cloud_admin_token == None:
            print '------update glance parameter to access uds,get token failed.'
            return False

        keystone_url = fs_keystone_server.keystone_get_endpoint("keystone")

        userid = self.getUsrid("cloud_admin", def_cloud_admin_token, keystone_url['keystone']['admin_url'])
        if userid == None:
            print '------update glance parameter to access uds,get user id  failed.'
            return False

        #get tenant id
        tenantid = self.getTenantid('service', def_cloud_admin_token, keystone_url['keystone']['admin_url'])
        if tenantid == None:
            print '------update glance parameter to access uds,get tenant id failed.'
            return False

        #get ak sk
        accesskey, secretkey = self.getAkSk(userid, tenantid, def_cloud_admin_token,
                                            keystone_url['keystone']['admin_url'])
        if accesskey is None or accesskey is None:
            print '------update glance parameter to access uds,get ak/sk failed.'
            return False
        if "https" in uds_domain_url:
            s3_host = uds_domain_url + ':' + '5443'
        else:
            s3_host = uds_domain_url + ':' + '5080'
        if glance_flag:
            params = {'s3_store_access_key': accesskey,
                      's3_store_secret_key': secretkey,
                      'default_store': 'uds+https',
                      's3_store_bucket': glance_dc + '.glance',
                      's3_store_host': s3_host}
            i = 0
            while i < 10:
                res = cps_server.update_template_params('glance', 'glance', params)
                if not res:
                    print '------update glance parameter to access uds failed,will try it again. %s times ' % str(i)
                    time.sleep(10)
                    i += 1
                    continue
                else:
                    break

        params = {'policy_s3_access_key': accesskey,
                  'policy_s3_secret_key': secretkey,
                  'policy_s3_operate_bucket': local_az + '.' + local_dc + 'operate.log.bucket',
                  'policy_s3_run_bucket': local_az + '.' + local_dc + 'run.log.bucket',
                  'policy_s3_host': s3_host,
                  'policy_s3_scheme': 's3+https',
                  'policy_s3_region': local_dc}
        i = 0
        while i < 10:
            res = cps_server.update_template_params('log', 'log-server', params)
            if not res:
                print '------update log parameter to access uds failed,will try it again.'
                time.sleep(10)
                i += 1
                continue
            else:
                break

        return True

    def save_global_uds(self, global_publicurl, global_internalurl, global_adminurl, global_s3_address):
        if global_publicurl != '':
            fs_glance_server.glance_set_global_s3_public_url(global_publicurl)
        if global_internalurl != '':
            fs_glance_server.glance_set_global_s3_internal_url(global_internalurl)
        if global_adminurl != '':
            fs_glance_server.glance_set_global_s3_admin_url(global_adminurl)
        if global_s3_address != '':
            fs_glance_server.glance_set_global_s3_address(global_s3_address)

    def config_uds(self):
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        uds_flag = self.input_uds_flag()
        if not config.has_section(fs_system_constant.SECTION_UDS_CONFIG):
            config.add_section(fs_system_constant.SECTION_UDS_CONFIG)
        config.set(fs_system_constant.SECTION_UDS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_IS_UDS, uds_flag)
        if uds_flag == 'y':
            uds_domain_url = self.input_domain_url()
            uds_external_ip = self.input_external_ip()
            config.set(fs_system_constant.SECTION_UDS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_UDS_DOMAIN_URL,
                       uds_domain_url)
            config.set(fs_system_constant.SECTION_UDS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_UDS_EXTERNAL_IP,
                       uds_external_ip)

            cf = ConfigParser.ConfigParser()
            cf.read(fs_system_constant.SYSTEM_INI_PATH)
            keystone_dc = fs_system_server.system_get_keystone_dc()
            keystone_az = fs_system_server.system_get_keystone_az()
            local_dc, local_az = fs_system_util.get_local_dc_az()
            if keystone_dc == local_dc and keystone_az == local_az:
                print 'Please set global s3'
                global_s3_url = self.input_global_domain_url()
                global_s3_ip = self.input_global_external_ip()
                config.set(fs_system_constant.SECTION_UDS_CONFIG,
                           fs_system_constant.SECTION_SYS_CONFIG_GLOBAL_UDS_DOMAIN_URL, global_s3_url)
                config.set(fs_system_constant.SECTION_UDS_CONFIG,
                           fs_system_constant.SECTION_SYS_CONFIG_GLOBAL_UDS_EXTERNAL_IP, global_s3_ip)
        with open(fs_system_constant.SYSTEM_INI_PATH, 'w') as fd:
            config.write(fd)

    def validate_uds(self):
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        if not config.has_option(fs_system_constant.SECTION_UDS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_IS_UDS):
            return
        uds_flag = config.get(fs_system_constant.SECTION_UDS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_IS_UDS)
        if uds_flag == 'y':
            if config.has_option(fs_system_constant.SECTION_UDS_CONFIG,
                                 fs_system_constant.SECTION_SYS_CONFIG_UDS_DOMAIN_URL) and config.has_option(
                    fs_system_constant.SECTION_UDS_CONFIG,
                    fs_system_constant.SECTION_SYS_CONFIG_UDS_EXTERNAL_IP):
                uds_domain_domain = config.get(fs_system_constant.SECTION_UDS_CONFIG,
                                               fs_system_constant.SECTION_SYS_CONFIG_UDS_DOMAIN_URL)
                uds_external_ip = config.get(fs_system_constant.SECTION_UDS_CONFIG,
                                             fs_system_constant.SECTION_SYS_CONFIG_UDS_EXTERNAL_IP)
                uds_domain_url, uds_port = self.get_url_port_by_domain(uds_domain_domain)

                cf = ConfigParser.ConfigParser()
                cf.read(fs_system_constant.SYSTEM_INI_PATH)
                keystone_dc = fs_system_server.system_get_keystone_dc()
                keystone_az = fs_system_server.system_get_keystone_az()
                local_dc, local_az = fs_system_util.get_local_dc_az()
                s3_address = "/%s/%s" % (uds_domain_url, uds_external_ip)
                s3_publicurl = "%s:%s" % (uds_domain_url, uds_port)
                s3_internalurl = "%s:%s" % (uds_domain_url, uds_port)
                s3_adminurl = "%s:%s" % (uds_domain_url, uds_port)
                self.save_uds(s3_publicurl, s3_internalurl, s3_adminurl, s3_address)
                if keystone_dc == local_dc and keystone_az == local_az:
                    if config.has_option(fs_system_constant.SECTION_UDS_CONFIG,
                                         fs_system_constant.SECTION_SYS_CONFIG_GLOBAL_UDS_DOMAIN_URL) \
                        and config.has_option(fs_system_constant.SECTION_UDS_CONFIG,
                                              fs_system_constant.SECTION_SYS_CONFIG_GLOBAL_UDS_EXTERNAL_IP):
                        global_s3_domain = config.get(fs_system_constant.SECTION_UDS_CONFIG,
                                                      fs_system_constant.SECTION_SYS_CONFIG_GLOBAL_UDS_DOMAIN_URL)
                        global_s3_ip = config.get(fs_system_constant.SECTION_UDS_CONFIG,
                                                  fs_system_constant.SECTION_SYS_CONFIG_GLOBAL_UDS_EXTERNAL_IP)
                        global_s3_url, global_s3_port = self.get_url_port_by_domain(global_s3_domain)
                        global_publicurl = "%s:%s" % (global_s3_url, global_s3_port)
                        global_internalurl = "%s:%s" % (global_s3_url, global_s3_port)
                        global_adminurl = "%s:%s" % (global_s3_url, global_s3_port)
                        global_s3_address = "/%s/%s" % (global_s3_url, global_s3_ip)
                        self.save_global_uds(global_publicurl, global_internalurl, global_adminurl, global_s3_address)
                    else:
                        print "File error when build global_s3"
                try:
                    LOG.info("start uds")
                    fs_keystone_cfg.Keystone().validate(utils.TYPE_ONLY_CONFIG, "uds")
                except:
                    LOG.error(traceback.format_exc())
                self.update_uds_template(uds_domain_url, uds_external_ip, uds_port)
            else:
                print "File error when build s3"

    def input_is_need_ntp(self):
        while 1:
            try:
                def_is_need_config_ntp = 'n'
                inputstr = "Do you need config external ntp [y|n][%s] : " % def_is_need_config_ntp
                is_need_config_ntp = raw_input(inputstr)
                if is_need_config_ntp == "":
                    is_need_config_ntp = def_is_need_config_ntp
                if is_need_config_ntp == 'y':
                    return True
                elif is_need_config_ntp == 'n':
                    return False
                else:
                    print "Please input correct character,only support [y|n]"
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please input correct character,only support [y|n]"
                continue

    def input_network_type(self):
        while 1:
            try:
                default = '1'
                print "[1] %s" % self.network_type_api
                print "[2] %s" % self.network_type_om
                inputstr = "Please set network [1|2][%s] : " % default
                network_type = raw_input(inputstr)
                if network_type == "":
                    network_type = '1'
                if network_type == '1':
                    return self.network_type_api
                elif network_type == '2':
                    return self.network_type_om
                else:
                    print "Please input correct character,only support [1|2]"
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please input correct character,only support [1|2]"
                continue

    def input_ntp_server(self):
        while 1:
            try:
                inputstr = "Please set ntp server: [ip1,domain@ip,domain@ip/mask...]"
                ntp_server = raw_input(inputstr)
                if ntp_server == "":
                    continue
                elif not self.ntp_server_format_is_correct(ntp_server.split(",")):
                    print "Please input correct ntp server."
                    continue
                else:
                    return ntp_server
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please input correct character,only support [ip1,domain@ip,...]"
                continue

    def ntp_server_format_is_correct(self,ipList ):
        for item in ipList:
            if "@" in item :
                itemList = item.split("@")
                if len(itemList) != 2:
                    return False
                ipAndMskList = itemList[1].split("/")
                if len(ipAndMskList) == 2 and not utils.is_ip_mask(itemList[1]):
                    return False
                elif len(ipAndMskList) == 1 and not utils.is_ip(ipAndMskList[0]):
                    return False
                elif len(ipAndMskList) != 1 and len(ipAndMskList) != 2:
                    return False
            else:
                if not utils.is_ip(item):
                    return False

        return True



    def input_api_ip(self):
        while 1:
            try:
                inputstr = "Please set ntp active_ip such as [ip/mask]:"
                ntp_server = raw_input(inputstr)
                if ntp_server == "":
                    print "Please set ntp active_ip such as 'ip/mask'."
                    continue
                elif not utils.is_ip_mask(ntp_server):
                    print "Please set ntp active_ip such as 'ip/mask'."
                    continue
                else:
                    break
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please set ntp active_ip such as 'ip/mask'."
                continue

        while 1:
            try:
                inputstr = "Please set ntp standby_ip such as [ip/mask]:"
                standby_ip = raw_input(inputstr)
                if standby_ip == "":
                    print "Please set ntp standby_ip such as [ip/mask]."
                    continue
                elif not utils.is_ip_mask(standby_ip):
                    print "Please set ntp standby_ip such as [ip/mask]."
                    continue
                else:
                    break
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please set ntp standby_ip such as [ip/mask]."
                continue

        gateway = self.get_ntp_gateway()

        return ntp_server, standby_ip, gateway

    def get_ntp_gateway(self):
        gateway = ""
        while 1:
            try:
                inputstr = "Please set ntp gateway []:"
                gateway = raw_input(inputstr)
                if gateway == "":
                    return gateway
                elif not utils.is_ip(gateway):
                    print "Please set correct gateway."
                    continue
                else:
                    break
            except KeyboardInterrupt:
                sys.exit(1)
            except:
                print "Please set correct gateway."
                continue
        return gateway


    def config_ntp(self):
        is_need_config_ntp = self.input_is_need_ntp()
        if is_need_config_ntp:
            network_type = self.input_network_type()
            ntp_server = self.input_ntp_server()
            active_ip = ""
            standby_ip = ""
            if network_type == self.network_type_api:
                active_ip, standby_ip, gateway  = self.input_api_ip()
            elif network_type == self.network_type_om:
                gateway = self.get_ntp_gateway()


            fs_system_util.save_one_option(fs_system_constant.SECTION_NTP_CONFIG,
                                           fs_system_constant.SECTION_SYS_CONFIG_NTP_NETWORK_TYPE,
                                           network_type)
            fs_system_util.save_one_option(fs_system_constant.SECTION_NTP_CONFIG,
                                           fs_system_constant.SECTION_SYS_CONFIG_NTP_SERVER, ntp_server)
            fs_system_util.save_one_option(fs_system_constant.SECTION_NTP_CONFIG,
                                           fs_system_constant.SECTION_SYS_CONFIG_NTP_ACTIVE_IP, active_ip)
            fs_system_util.save_one_option(fs_system_constant.SECTION_NTP_CONFIG,
                                           fs_system_constant.SECTION_SYS_CONFIG_NTP_STANDBY_IP, standby_ip)
            fs_system_util.save_one_option(fs_system_constant.SECTION_NTP_CONFIG,
                                           fs_system_constant.SECIONT_SYS_CONFIG_NTP_GATEWAY_TYPE, gateway)




    def config_dc_admin(self):
        fs_keystone_server.keystone_build_dc_admin()


    def config_safe_mode(self):
        """
        打开安全开关，即使用token
        @return:
        """
        cfg_mode = fs_system_util.get_one_option(fs_system_constant.SECTION_AUTH_MODE_CONFIG,
                                                 fs_system_constant.SECTION_SYS_OPEN_TOKEN)
        while 1:
            try:
                input_str = "Do you want to use authentication?[y/n] [%s]" % cfg_mode
                use_token = raw_input(input_str)
                if use_token == "":
                    LOG.info("input str is empty!")
                    return
                elif use_token.lower() == "n" or use_token.lower() == "y":
                    fs_system_util.save_one_option(fs_system_constant.SECTION_AUTH_MODE_CONFIG,
                                                   fs_system_constant.SECTION_SYS_OPEN_TOKEN, use_token.lower())
                    return
                else:
                    print "Please input correct character,only support [y,n]"
                    continue
            except KeyboardInterrupt:
                sys.exit(1)
            except Exception, e:
                LOG.error(e)
                continue

    def config_keystone_url(self):
        print "Config keystone url"
        while True:
            keystone_url = None
            keystone_url = fs_system_server.system_get_keystone_domain()
            if keystone_url is None:
                keystone_url = "https://identity.az1.dc1.domainname.com:443"
            input_str = "Please input keystone url[%s]" % keystone_url
            input_keystone_url = raw_input(input_str)
            if input_keystone_url == "":
                LOG.info("input str is empty!")
            else:
                keystone_url = input_keystone_url
                print keystone_url
            match = fs_system_util.check_domain(keystone_url)
            if not match:
                print "Please set the correct domain such as 'https://identify.az1.dc1.domainname.com:443'"
                continue
            else:
                fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                               "keystone_domain", keystone_url)
            break

    def config_glance_url(self):
        print "Config glance url"
        while True:
            glance_url = None
            glance_url = fs_system_server.system_get_glance_domain()
            if glance_url is None:
                glance_url = "https://image.az1.dc1.domainname.com:8500"
            input_str = "Please input glance url[%s]" % glance_url
            input_glance_url = raw_input(input_str)
            if input_glance_url == "":
                LOG.info("input str is empty!")
            else:
                glance_url = input_glance_url
                print glance_url
            match = fs_system_util.check_domain(glance_url)
            if not match:
                print "Please set the correct domain such as 'https://image.az1.dc1.domainname.com:8500'"
                continue
            else:
                fs_system_util.save_one_option(fs_system_constant.SECTION_SYS_CONFIG,
                                               "glance_domain", glance_url)
            break

    def config(self, type_name):
        LOG.info("type_name is %s."%type_name)
        while 1:
            print "[1] Uds"
            print "[2] Dns"
            print "[3] Ntp"
            print "[4] Dc admin"
            print "[5] Safe mode"
            print "[6] keystone url"
            print "[7] glance url"
            print "[s] Save&quit"
            default_choose = 's'
            inputstr = "Please choose [1-7|s][%s]" % default_choose
            input_num = raw_input(inputstr)
            if input_num == '':
                input_num = default_choose
            if input_num == '1':
                self.config_uds()
                continue
            elif input_num == '2':
                self.config_dns()
                continue
            elif input_num == '3':
                self.config_ntp()
                continue
            elif input_num == '4':
                self.config_dc_admin()
                continue
            elif input_num == '5':
                self.config_safe_mode()
                continue
            elif input_num == '6':
                self.config_keystone_url()
            elif input_num == '7':
                self.config_glance_url()
            elif input_num == 's':
                break
        return True

    def validate_keystone_url(self):
        print "validate keystone url"
        if fsinstall.update_component_cfg(True, False):
            print "succeed to validate keystone url."
        else:
            print "Fail to validate keystone url,please try again later."
        if not cps_server.cps_commit():
            print "Fail to validate keystone url,commit error.please try again later."

    def validate_glance_url(self):
        print "validate glance url"
        success_flag = False
        sleep_times = 0
        while sleep_times < 10:            
            if fsinstall.update_component_cfg(False, True):
                print "succeed to validate glance url."
                success_flag = True
                break
            time.sleep(6)
            sleep_times += 1                
        if success_flag == False :
            print "Fail to validate glance url,please try again later."
        if not cps_server.cps_commit():
            print "Fail to validate glance url,commit error.please try again later."

    def validate_dns(self):
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        if config.has_option(fs_system_constant.SECTION_DNS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_DNS_ADDRESS):
            dns_address = config.get(fs_system_constant.SECTION_DNS_CONFIG,
                                     fs_system_constant.SECTION_SYS_CONFIG_DNS_ADDRESS)
            if self.update_dns_address({'address': dns_address}):
                print "Update address success"
            else:
                print "Update address failed"
        if config.has_option(fs_system_constant.SECTION_DNS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_DNS_SERVER):
            dns_server = config.get(fs_system_constant.SECTION_DNS_CONFIG,
                                    fs_system_constant.SECTION_SYS_CONFIG_DNS_SERVER)
            if self.update_dns_address({'server': dns_server}):
                print "Update server success"
            else:
                print "Update server failed"
        if config.has_option(fs_system_constant.SECTION_DNS_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_DNS_NETWORK):
            network = config.get(fs_system_constant.SECTION_DNS_CONFIG,
                                 fs_system_constant.SECTION_SYS_CONFIG_DNS_NETWORK)
            if self.update_dns_address({'network': network}):
                print "Update network success"
            else:
                print "Update network failed"

    def validate_ntp(self):
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        if config.has_option(fs_system_constant.SECTION_NTP_CONFIG,
                             fs_system_constant.SECTION_SYS_CONFIG_NTP_NETWORK_TYPE) and config.has_option(
                fs_system_constant.SECTION_NTP_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_NTP_SERVER):
            network_type = config.get(fs_system_constant.SECTION_NTP_CONFIG,
                                      fs_system_constant.SECTION_SYS_CONFIG_NTP_NETWORK_TYPE)
            ntp_server = config.get(fs_system_constant.SECTION_NTP_CONFIG,
                                    fs_system_constant.SECTION_SYS_CONFIG_NTP_SERVER)
            active_ip = ""
            standby_ip = ""
            if network_type == self.network_type_api:
                if config.has_option(fs_system_constant.SECTION_NTP_CONFIG,
                                     fs_system_constant.SECTION_SYS_CONFIG_NTP_ACTIVE_IP) and config.has_option(
                        fs_system_constant.SECTION_NTP_CONFIG, fs_system_constant.SECTION_SYS_CONFIG_NTP_STANDBY_IP):
                    active_ip = config.get(fs_system_constant.SECTION_NTP_CONFIG,
                                           fs_system_constant.SECTION_SYS_CONFIG_NTP_ACTIVE_IP)
                    standby_ip = config.get(fs_system_constant.SECTION_NTP_CONFIG,
                                            fs_system_constant.SECTION_SYS_CONFIG_NTP_STANDBY_IP)
                else:
                    print "Update ntp failed, can not find active_ip or standby_ip"
                    return

            gateway = ""
            if config.has_option(fs_system_constant.SECTION_NTP_CONFIG,
                                     fs_system_constant.SECIONT_SYS_CONFIG_NTP_GATEWAY_TYPE):
                gateway = config.get(fs_system_constant.SECTION_NTP_CONFIG,
                                            fs_system_constant.SECIONT_SYS_CONFIG_NTP_GATEWAY_TYPE)


            if cps_server.update_template_params("ntp", "ntp-server", {'server': ntp_server, "active_ip": active_ip,
                                                                       "standby_ip": standby_ip,'network': network_type,
                                                                       "gateway":gateway}):
                print "Update ntp success"
            else:
                print "Update ntp failed,please check your data"


    def validate_auth_mode(self):
        cfg_mode = fs_system_util.get_one_option(fs_system_constant.SECTION_AUTH_MODE_CONFIG,
                                                 fs_system_constant.SECTION_SYS_OPEN_TOKEN)
        env_mode = change_auth_mode.ChangeAuthMode().is_auth_mode()
        if cfg_mode != env_mode:
            print "Begin to change auth mode,wait a few minutes."
            #配置的和实际的不符合，则修改
            if cfg_mode == "y":
                flag = change_auth_mode.ChangeAuthMode().open_close_token(True)
            else:
                token = fs_keystone_server.keystone_get_cloud_token()
                flag = change_auth_mode.ChangeAuthMode().open_close_token(False, token)
            if not flag:
                print "Fail to change auth mode!"
                
        sleep_time = 0
        while 1:
            time.sleep(10)
            sleep_time += 5
            if cps_server.Cps_work_bean().is_cps_work():
                time.sleep(10)
                if cps_server.Cps_work_bean().is_cps_work():
                    print "Succeed to change system service auth mode!"
                    break
            if sleep_time > 100:
                print "Fail to change auth mode!Cps cli can not use."
                break



    def get_section_list(self):
        return [fs_system_constant.SECTION_SYS_CONFIG]


    def get_file_path(self):
        return fs_system_constant.SYSTEM_INI_PATH

    def validate(self, type_name, phase):
        LOG.info("type_name is %s phase : %s.."%(type_name, phase))
        ret = False
        self.validate_uds()
        self.validate_dns()
        self.validate_ntp()
        cps_server.cps_commit()
        time.sleep(8)
        ret = fs_system_server.is_connection_work()
        if ret:
            self.validate_auth_mode()
            self.validate_glance_url()
            self.validate_keystone_url()
            fs_keystone_cfg.Keystone().validate(utils.TYPE_ONLY_CONFIG, "")
        else:
            print "Notice:network is not available,Safe mode/keystone/glance config may not take effect."


    def create_def_config(self, cfg):
        LOG.info("create_def_config :%s."%cfg)
        config = ConfigParser.RawConfigParser()
        config.read(fs_system_constant.SYSTEM_INI_PATH)
        if not config.has_section(fs_system_constant.SECTION_AUTH_MODE_CONFIG):
            config.add_section(fs_system_constant.SECTION_AUTH_MODE_CONFIG)
        config.set(fs_system_constant.SECTION_AUTH_MODE_CONFIG, fs_system_constant.SECTION_SYS_OPEN_TOKEN, "n")
        with open(fs_system_constant.SYSTEM_INI_PATH, 'w') as fd:
            config.write(fd)
        fs_glance_server.glance_set_global_s3_internal_url(self.def_global_internalurl)
        fs_glance_server.glance_set_global_s3_admin_url(self.def_global_adminurl)
        fs_glance_server.glance_set_global_s3_public_url(self.def_global_publicurl)
        fs_glance_server.glance_set_s3_internal_url(self.def_s3_internalurl)
        fs_glance_server.glance_set_s3_admin_url(self.def_s3_adminurl)
        fs_glance_server.glance_set_s3_public_url(self.def_s3_publicurl)


def print_uds_address():
    address = fs_glance_server.glance_get_s3_address()
    if address is not None and not address == '':
        print 'You can decide whether uds s3 address [%s] also add to the dns.  ' % address
    global_address = fs_glance_server.glance_get_global_s3_address()
    if global_address is not None and global_address == '':
        print 'You can decide whether uds global_s3 address [%s] also add to the dns.  ' % global_address



