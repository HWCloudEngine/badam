#!/usr/bin/python
# coding:utf-8
# Helper functions for the CPS client.
import re
import errno
import json
import sys
import uuid
import logging
import types
import exceptions as exc
import os
import string
from os.path import join
import traceback
import cps_server
import prettytable
from print_msg import PrintMessage as PrintUtil
import ConfigParser
import fs_log_util
import fs_system_server
import socket
import struct

if os.name == 'nt':
    import msvcrt
else:
    msvcrt = None

LOG = logging.getLogger(__name__)

#token有效期：1天
TOKEN_EXPIRATION = "86400"

FS_DEPLOY_MODE_ONE = 'AllInOne'
FS_DEPLOY_MODE_THREE = '3Controllers'
FS_DEPLOY_MODE_TWO = '2Controllers'

TRUE_STRINGS = ('1', 't', 'true', 'on', 'y', 'yes')
FALSE_STRINGS = ('0', 'f', 'false', 'off', 'n', 'no')
ALL_PATTERN = '*'
BASE_PATH = '/cps/v1'
CFG_PATH_SRV_IP = '/etc/huawei/fusionsphere/cfg/serverIp.ini'
ROLES = "roles"
HOSTS_STR = "hosts"
SERVICE_STR = 'services'
HOSTCFG_STR = 'hostcfg'
TEMPLATES_STR = "componenttemplates"
COMPONENT_TYPE_STR = 'componenttypes'
TYPES_STR = 'types'
ITEMS_STR = 'items'
PARTITION_NAME = 'partition-name'
DISK_NO = 'disk'
PARTITION_SIZE = 'partition-size'
MOUNT_PATH = 'mountpath'
FORMAT = 'format'
PHYSICAL_PARTITION = 'physicalpartition'
LV_NAME = 'lvname'
MOUNT = 'mount'
SIZE = 'size'
NAME = 'name'
PROVIDERS = "providers"
SYSINTERFACE = "sysinterfaces"

CMD_EXE_ERROR_MSG = 'cmd execute failed'
CMD_RESP_LACK_KEY = 'response lack key'
CMD_EXE_SUCCESS = 'commod extcute success'
CMD_EXE_FAILED = 'commod extcute failed'
RESPNOSE_SUCCESS = 200
LINE_WORD_NUM = 40

RESPONSE_ERROR_INFO_DETAILS = 'details'

#*************** security **************
CPSCLIENT_INI_FILE = '/usr/local/bin/cps-client/cps_client/cps_client.ini'
SECTION_CPSCLIENT = 'cpsclient'

#*************** https crt ***************
CLIENT_CRT = '/etc/FSSecurity/cacert/cps-client.crt'
SERVER_CRT = '/etc/FSSecurity/server-cert/cps-server.crt'
SERVER_KEY = '/etc/FSSecurity/server-cert/cps-server.key'

#*************deploy type********************
DEFAULT_FILE_NAME = join(os.path.dirname(os.path.abspath(__file__)), 'default_sys.ini')
TYPE_ONLY_DEPLOY = "deploy"
TYPE_DEPLOY_CONFIG = "deploy & config"
TYPE_ONLY_CONFIG = "config"
SECTION_ROLE_DEPLOY = "host_deploy"
SECTION_ROLE_DEPLOY_CTRL_HOST = "ctrl_hosts"

SECTION_GLANCE = "glance"
SECTION_GLANCE_GLANCE_STORE = 'glance_store'
SECTION_GLANCE_INTERNAL = "s3_internal_url"
SECTION_GLANCE_ADMIN = "s3_admin_url"
SECTION_GLANCE_PUBLIC = "s3_public_url"
SECTION_GLANCE_ADDRESS = "s3_address"
SECTION_GLANCE_GLOBAL_INTERNAL = "g_s3_internal_url"
SECTION_GLANCE_GLOBAL_ADMIN = "g_s3_admin_url"
SECTION_GLANCE_GLOBAL_PUBLIC = "g_s3_public_url"
SECTION_GLANCE_GLOBAL_ADDRESS = "g_s3_address"

SECTION_SYS_CONFIG = "domain"

SECTION_SYS_CONFIG_DC_ADMIN = "dc_admin"
SECTION_SYS_CONFIG_IS_UDS = "is_uds"
SECTION_SYS_CONFIG_UDS_DOMAIN_URL = "uds_domain_url"
SECTION_SYS_CONFIG_UDS_EXTERNAL_IP = "uds_external_ip"
SECTION_SYS_CONFIG_UDS_PORT = "uds_port"
SECTION_SYS_CONFIG_GLOBAL_UDS_DOMAIN_URL = "global_uds_domain_url"
SECTION_SYS_CONFIG_GLOBAL_UDS_EXTERNAL_IP = "global_uds_external_ip"
SECTION_SYS_CONFIG_GLOBAL_UDS_PORT = "global_uds_port"
SECTION_SYS_CONFIG_DNS_SERVER = "dns_server"
SECTION_SYS_CONFIG_DNS_ADDRESS = "dns_address"
SECTION_SYS_CONFIG_DNS_NETWORK = "dns_network"
SECTION_SYS_CONFIG_NTP_NETWORK_TYPE = "ntp_network_type"
SECTION_SYS_CONFIG_NTP_SERVER = "ntp_server"
SECTION_SYS_CONFIG_NTP_ACTIVE_IP = "ntp_active_ip"
SECTION_SYS_CONFIG_NTP_STANDBY_IP = "ntp_standby_ip"
SECTION_SYS_OPEN_TOKEN = "auth_mode"
SECTION_SYS_NETWORK = "network"
SECTION_SYS_NETWORK_CUR_PROVIDER_LIST = "cur_provider_list"
SECTION_SYS_NETWORK_CUR_SYSINTFNW_LIST = "cur_sysintfnw_list"

SECTION_DYNAMIC_ROLE = "dynamic_role"
SECTION_DYNAMIC_ROLE_LIST = "role_list"
ROLE_NAME_NETWORK = "router"
ROLE_NAME_LOADBALANCER = "loadbalancer"
ROLE_NAME_BLOCKSTORAGE = "blockstorage"
ROLE_NAME_BLOCKSTORAGE_DRIVER = "blockstorage-driver"

#以下是default.ini的配置信息
#DEFAULT_INI_PATH = "default.ini"
DEFAULT_INI_PATH = join(os.path.dirname(os.path.abspath(__file__)), 'default_sys.ini')
SECTION_SERVICE_PORT_CONFIG = "haproxy_port"
SECTION_NEUTRON_CONFIG = "neutron_cfg"
SECTION_NEUTRON_CONFIG_SECURITY = "security_group"
SECTION_NEUTRON_CONFIG_USE_VXLAN = "use_vxlan_flag"

SECTION_NOVA_CONFIG = "nova_cfg"
SECTION_NOVA_CONFIG_TENANT = "vm_boot_on_ctrl_host"

SECTION_IS_FINISHED = "is_finished"
PHASE_PRE = "precfg"
PHASE_INSTALL = "install"
PHASE_POST = "postcfg"
PHASE_USER_CONFIG = "user_config"

CLOUD_USER = "cloud_admin"
CLOUD_TENANT = "admin"
DOMAIN_INTERNAL = "localdomain.com"
DOMAIN_ADMIN = "admin.com"
FS_USED_PORT_LIST = ("8000","8001","8002","67","40000","40001","40002","40003","40004","40005","40006","40007","40008","40009","40010","69","8000","3881","4881","9880","8044","8773","8774","8775","123","123","6080","9191","8081","6010","6011","6012","8777","8776","8004","8003","8025","5432","19998","27017","11211","11211","9699","8235","8238","8236","8081","9882","9881","8230","8232","8231","60080","22","5672","4369","50000","50001","3260","16509","53","53","873","5900","15900","9696","35357","514","9292","8001","8777","8776","8002","8700","8701","8702","8008","8007","8020","8023","8500","8100","8021","8775","8011","8235","8383","8080","1","4789","8111","8112","8023","8500","8002","443")
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
FILE_NAME = join(CURRENT_PATH, 'deployEnv.ini')
logger = fs_log_util.localLog.get_logger(LOG_FILE)

SECTION_NAME = "name"
SECTION_INSTANCE = "instance"
SECTION_WORK_ITEMS = "work items"
SECTION_IMPORT = "import"
SECTION_CLASS = "class"
SECTION_SYS_PATH = "sys_path"
SECTION_NODES = "deploynodes"

VLAN_ID_CONFLICT = ["vlan id conflict with \"%s\", vlan id:\"%s\", input again",
                    "请重新输入，vlan号冲突，vlan号：[%s]"]

section_map = None


def get_file_bean():
    sys.path.append("/usr/bin/install_tool")
    module = __import__("default_file")
    instance = getattr(module, "DefaultFile")()
    return instance


def get_section_map():
    global section_map
    if section_map is None:
        section_map = build_map()
    return section_map


def get_new_section_map():
    global section_map
    section_map = build_map()
    return section_map


def build_map():
    config = ConfigParser.RawConfigParser()
    config.read(FILE_NAME)
    if not config.has_option(SECTION_NODES, SECTION_NODES):
        print "No data in deployEnv.ini .Please check"
        logger.error("No data in deployEnv.ini .Please check")
        sys.exit(1)
    deploynodes = str(config.get(SECTION_NODES, SECTION_NODES))
    logger.info("deploynodes %s" % deploynodes)
    nodes_map = json.loads(deploynodes)
    final_map = {}
    for key, value in nodes_map.iteritems():
        name = str(value[SECTION_NAME])
        import_value = str(value[SECTION_IMPORT])
        class_value = str(value[SECTION_CLASS])
        sys_path_value = str(value[SECTION_SYS_PATH])
        sys.path.append(sys_path_value)

        module = __import__(import_value)
        logger.info("file is %s" % module.__file__)
        instance = getattr(module, class_value)()

        final_map[key] = {SECTION_NAME: name, SECTION_INSTANCE: instance}
    logger.info(" map is %s" % final_map)
    return final_map


def get_safe_message(message):
    """
    打印日志，删除敏感信息。使用
    @param message:
    @return:
    """
    str_message = str(message)
    sensitive_list = ['password', 'Password', 'PASSWORD', 'key', 'token_id', 'MII', 'Token', 'X-Auth-Token', 'fc_pwd']
    for sensitive_word in sensitive_list:
        if sensitive_word in str_message:
            return "********"
    return str_message

def save_one_option(section, option, value):
    config = ConfigParser.RawConfigParser()
    config.read(DEFAULT_FILE_NAME)
    if not config.has_section(section):
        config.add_section(section)
    config.set(section, option, value)
    with open(DEFAULT_FILE_NAME, 'w') as fd:
        config.write(fd)

def get_one_option(section, option):
    config = ConfigParser.RawConfigParser()
    config.read(DEFAULT_FILE_NAME)
    if config.has_option(section, option):
        return config.get(section, option)
    return None

def is_glance_at_local():
    try:
        dcname, local_az, domainpostfix = fs_system_server.system_get_local_domain()
        glance_dc = fs_system_server.system_get_glance_dc()
        glance_az = fs_system_server.system_get_glance_az()
        return glance_dc == dcname and glance_az == local_az
    except:
        return False

def is_keystone_at_local():
    try:
        dcname, local_az, domainpostfix = fs_system_server.system_get_local_domain()
        keystone_dc = fs_system_server.system_get_keystone_dc()
        keystone_az = fs_system_server.system_get_keystone_az()
        return keystone_dc == dcname and keystone_az == local_az
    except:
        return False

def get_all_hosts():
    hosts, ips = cps_server.get_all_hosts()
    logger.debug("get_all_hosts hosts = %s, ips = %s" %(hosts, ips))
    return hosts


def get_local_dc_az():
    sysFile = "/etc/huawei/fusionsphere/cfg/sys.ini"
    sysconfig = ConfigParser.RawConfigParser()
    sysconfig.read(sysFile)
    sysSectionList = sysconfig.sections()
    for item in sysSectionList:
        if item.find("localaz") is not -1:
            conf = dict(sysconfig.items(item))
            return conf["localdc"], conf["localaz"]

def get_domain_fix():
    sysFile = "/etc/huawei/fusionsphere/cfg/sys.ini"
    sysconfig = ConfigParser.RawConfigParser()
    sysconfig.read(sysFile)
    sysSectionList = sysconfig.sections()
    for item in sysSectionList:
        if item.find("localaz") is not -1:
            conf = dict(sysconfig.items(item))
            return conf["domainprefix"], conf["domainpostfix"]

def set_finish_flag():
    config = ConfigParser.RawConfigParser()
    config.read(DEFAULT_FILE_NAME)
    if not config.has_section(SECTION_IS_FINISHED):
        config.add_section(SECTION_IS_FINISHED)
    config.set(SECTION_IS_FINISHED, SECTION_IS_FINISHED, 'finished')
    with open(DEFAULT_FILE_NAME, 'w') as fd:
        config.write(fd)

def is_finished():
    """
    判断是否部署，使用
    @return:
    """
    #如果配置文件不存在，则为第一次安装
    if not os.path.exists(DEFAULT_FILE_NAME):
        return False
    #如果配置文件中的SECTION_IS_FINISHED标志为finished表示已经部署成功
    try:
        config = ConfigParser.RawConfigParser()
        config.read(DEFAULT_FILE_NAME)
        return config.get(SECTION_IS_FINISHED, SECTION_IS_FINISHED) == 'finished'
    except KeyboardInterrupt:
        sys.exit(1)
    except:
        return False


def input_keystone_dc():
    def_keystone_dc = "dc1"
    keystone_dc = "dc1"
    while 1:
        try:
            input_str = PrintUtil.get_msg(
                ["Please set dc name that keystone installed on [%s] : " % def_keystone_dc,
                 "请输入keystone部署的dc名 [%s] : " % def_keystone_dc])
            keystone_dc = raw_input(input_str)
            if keystone_dc == "":
                keystone_dc = def_keystone_dc
                break
            else:
                #不应该全由空格组成
                if keystone_dc.rstrip() == "":
                    PrintUtil.print_msg(["please set the correct dc name.", "请输入一个dc名"])
                    continue

                keystone_dc = keystone_dc.rstrip()
                break
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            PrintUtil.print_msg(["please set the correct dc name.", "请输入一个dc名"])
            logger.error("failed: %s" % traceback.format_exc())
            continue
    return keystone_dc


def input_keystone_az():
    def_keystone_az = "az1"
    keystone_az = "az1"
    while 1:
        try:
            input_str = PrintUtil.get_msg(
                ["Please set az name that keystone installed on [%s] : " % def_keystone_az,
                 "请输入keystone部署的az名 [%s] : " % def_keystone_az])
            keystone_az = raw_input(input_str)
            if keystone_az == "":
                keystone_az = def_keystone_az
                break
            else:
                #不应该全由空格组成
                if keystone_az.rstrip() == "":
                    PrintUtil.print_msg(["please set the correct az name.", "请输入一个az名"])
                    continue

                keystone_az = keystone_az.rstrip()
                break
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            PrintUtil.print_msg(
                ["Please set the correct az name.", "请输入一个az名。"])
            logger.error("failed: %s" % traceback.format_exc())
            continue
    return keystone_az


def input_glance_dc():
    def_glance_dc = "dc1"
    glance_dc = "dc1"
    while 1:
        try:
            input_str = PrintUtil.get_msg(
                ["Please set dc name that glance installed on [%s] : " % def_glance_dc,
                 "请输入glance部署的dc名 [%s] : " % def_glance_dc])

            glance_dc = raw_input(input_str)
            if glance_dc == "":
                glance_dc = def_glance_dc
                break
            else:
                #不应该全由空格组成
                if glance_dc.rstrip() == "":
                    PrintUtil.print_msg(["please set the correct dc name.", "请输入一个dc名"])
                    continue
                glance_dc = glance_dc.rstrip()
                break
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            PrintUtil.print_msg(["Please set the correct dc name.", "请输入一个dc名。"])
            logger.error("failed: %s" % traceback.format_exc())
            continue
    return glance_dc


def input_glance_az():
    def_glance_az = 'az1'
    glance_az = 'az1'
    while 1:
        try:
            input_str = PrintUtil.get_msg(
                ["Please set az name that glance installed on [%s] : " % def_glance_az,
                 "请输入glance部署的az名 [%s] : " % def_glance_az])

            glance_az = raw_input(input_str)
            if glance_az == "":
                glance_az = def_glance_az
                break
            else:
                #不应该全由空格组成
                if glance_az.rstrip() == "":
                    PrintUtil.print_msg(["please set the correct az name.", "请输入一个az名"])
                    continue
                glance_az = glance_az.rstrip()
                break
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            PrintUtil.print_msg(["Please set the correct az name.", "请输入一个az名。"])
            logger.error("failed: %s" % traceback.format_exc())
            continue
    return glance_az



def int_from_bool_as_string(subject):
    """
    Interpret a string as a boolean and return either 1 or 0.

    Any string value in:

        ('True', 'true', 'On', 'on', '1')

    is interpreted as a boolean True.

    Useful for JSON-decoded stuff and config file parsing
    """
    return bool_from_string(subject) and 1 or 0


def bool_from_string(subject, strict=False):
    """
    Interpret a string as a boolean.

    A case-insensitive match is performed such that strings matching 't',
    'true', 'on', 'y', 'yes', or '1' are considered True and, when
    `strict=False`, anything else is considered False.

    Useful for JSON-decoded stuff and config file parsing.

    If `strict=True`, unrecognized values, including None, will raise a
    ValueError which is useful when parsing values passed in from an API call.
    Strings yielding False are 'f', 'false', 'off', 'n', 'no', or '0'.
    """
    if not isinstance(subject, basestring):
        subject = str(subject)

    lowered = subject.strip().lower()

    if lowered in TRUE_STRINGS:
        return True
    elif lowered in FALSE_STRINGS:
        return False
    elif strict:
        acceptable = ', '.join(
            "'%s'" % s for s in sorted(TRUE_STRINGS + FALSE_STRINGS))
        msg = _("Unrecognized value '%(val)s', acceptable values are:"
                " %(acceptable)s") % {'val': subject,
                                      'acceptable': acceptable}
        raise ValueError(msg)
    else:
        return False


def safe_decode(text, incoming=None, errors='strict'):
    """
    Decodes incoming str using `incoming` if they're
    not already unicode.

    :param incoming: Text's current encoding
    :param errors: Errors handling policy. See here for valid
        values http://docs.python.org/2/library/codecs.html
    :returns: text or a unicode `incoming` encoded
                representation of it.
    :raises TypeError: If text is not an isntance of basestring
    """
    if not isinstance(text, basestring):
        raise TypeError("%s can't be decoded" % type(text))

    if isinstance(text, unicode):
        return text

    if not incoming:
        incoming = (sys.stdin.encoding or
                    sys.getdefaultencoding())

    try:
        return text.decode(incoming, errors)
    except UnicodeDecodeError:
        # Note(flaper87) If we get here, it means that
        # sys.stdin.encoding / sys.getdefaultencoding
        # didn't return a suitable encoding to decode
        # text. This happens mostly when global LANG
        # var is not set correctly and there's no
        # default encoding. In this case, most likely
        # python will use ASCII or ANSI encoders as
        # default encodings but they won't be capable
        # of decoding non-ASCII characters.
        #
        # Also, UTF-8 is being used since it's an ASCII
        # extension.
        return text.decode('utf-8', errors)


def safe_encode(text, incoming=None,
                encoding='utf-8', errors='strict'):
    """
    Encodes incoming str/unicode using `encoding`. If
    incoming is not specified, text is expected to
    be encoded with current python's default encoding.
    (`sys.getdefaultencoding`)

    :param incoming: Text's current encoding
    :param encoding: Expected encoding for text (Default UTF-8)
    :param errors: Errors handling policy. See here for valid
        values http://docs.python.org/2/library/codecs.html
    :returns: text or a bytestring `encoding` encoded
                representation of it.
    :raises TypeError: If text is not an isntance of basestring
    """
    if not isinstance(text, basestring):
        raise TypeError("%s can't be encoded" % type(text))

    if not incoming:
        incoming = (sys.stdin.encoding or
                    sys.getdefaultencoding())

    if isinstance(text, unicode):
        return text.encode(encoding, errors)
    elif text and encoding != incoming:
        # Decode text before encoding it with `encoding`
        text = safe_decode(text, incoming, errors)
        return text.encode(encoding, errors)

    return text


# Decorator for cli-args
def arg(*args, **kwargs):
    def _decorator(func):
        # Because of the sematics of decorator composition if we just append
        # to the options list positional options will appear to be backwards.
        func.__dict__.setdefault('arguments', []).insert(0, (args, kwargs))
        return func
    return _decorator

# Decorator for custom cli-args - used when the arg decorator is not enough
# (e.g. when creating mutually exclusive groups)
def custom_arg_fn(argfunc):
    # argfunc should take a parser object and add suitable arguments to it.
    def _decorator(func):
        # Because of the sematics of decorator composition if we just append
        # to the options list positional options will appear to be backwards.
        func.__dict__.setdefault('arguments', []).insert(0, argfunc)
        return func
    return _decorator


def pretty_choice_list(l):
    return ', '.join("'%s'" % i for i in l)


def print_list(objs, fields, formatters={}, line_len=LINE_WORD_NUM):
    pt = prettytable.PrettyTable([f for f in fields], caching=False)
    pt.align = 'l'

    len_size = 0
    for o in objs:
        len_size = len_size + 1
        row = []
        for field in fields:
            if field in formatters:
                row.append(line_length_limit(formatters[field](o),line_len))
            else:
                field_name = field.lower().replace(' ', '_')
                if not o.has_key(field_name):
                    data = ''
                else:
                    data = o[field_name]
                #data = getattr(o, field_name, None) or ''
                row.append(line_length_limit(data,line_len))
        pt.add_row(row)
    if (len_size == 0):
        row = []
        for field in fields:
            data = ''
            row.append(line_length_limit(data))
        pt.add_row(row)
    print safe_encode(pt.get_string())

def is_ip_with_split(ip_str, split_str):
    if split_str in ip_str:
        templist = ip_str.split(split_str)
        for temp_str in templist:
            if not is_ip(temp_str):
                return False
    else:
        return is_ip(ip_str)
    return True

def is_ip(ip_str):
    ip = str(ip_str)
    pattern = r"^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$"
    p = re.compile(pattern)
    if p.match(ip):
        return True
    else:
        return False

def is_simple_str(ip_str):
    ip = str(ip_str)
    pattern = r"^[\w\-]+$"
    p = re.compile(pattern)
    if p.match(ip):
        return True
    else:
        return False

def is_domain_postfix_str(ip_str):
    ip = str(ip_str)
    pattern = r"^[\w\-.]+$"
    p = re.compile(pattern)
    if p.match(ip):
        return True
    else:
        return False

def is_port_valid(port_value):
    print port_value
    if port_value is not None and str(port_value).isdigit():
        port_num=string.atoi(port_value)
        if port_num == 443:
            return True
        elif(port_num >1 and port_num <1024) or port_num >65535:
            return False
        else:
            if FS_USED_PORT_LIST.count(port_value)==0 :
                return True 
            else:
                return False
    else:
        return False

def is_ip_mask(ip_mask):
    try:
        str_list = ip_mask.split('/')
        ip = str_list[0]
        mask = str_list[1]
        mask_num = int(mask)
        if mask_num < 1 or mask_num > 32:
            print "mask should be between [1,32]"
            return False
        return is_ip(ip)
    except:

        return False

def check_mask(mask_str):
    try:
        mask = int(mask_str)
    except:
        PrintUtil.print_msg(["mask should be an integer", "掩码值应为整数"])
        return False

    if mask < 1 or mask > 32:
        PrintUtil.print_msg(["mask should be between [1,32]", "掩码范围为[1,32]"])
        return False
    else:
        return True

def check_ip(ip_str):
    ip = str(ip_str)
    pattern = r"^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$"
    p = re.compile(pattern)
    if p.match(ip):
        return True
    else:
        PrintUtil.print_msg(["illegal IP address", "非法IP地址"])
        return False

def check_port(port_str):
    try:
        port = int(port_str)
    except:
        PrintUtil.print_msg(["port should be an integer", "端口值应为整数"])
        return False

    if 0 < port <= 65535:
        return True
    else:
        PrintUtil.print_msg(["port should be between [1, 65535]", "端口范围为[1, 65535]"])
        return False

def check_user_input(prompt, checkfunc, default_value=None):
    while 1:
        try:
            result = raw_input(prompt)
            if result == "":
                if default_value != None:
                    return default_value
            else:
                if checkfunc(result):
                    return result
        except KeyboardInterrupt:
            sys.exit(1)
        except Exception:
            PrintUtil.print_msg(["please input again", "请重新输入"])
            continue

def print_list_ext(objs, fields, formatters={},line_len=30):
    pt = prettytable.PrettyTable([f for f in fields], caching=False)
    pt.align = 'l'

    len_size = 0
    for o in objs:
        len_size = len_size + 1
        row = []
        for field in fields:
            if field in formatters:
                row.append(line_length_limit(formatters[field](o),line_len))
            else:
                data = o[field]
                row.append(line_length_limit(data,line_len))
        pt.add_row(row)
    if (len_size == 0):
        row = []
        for field in fields:
            data = ''
            row.append(line_length_limit(data))
        pt.add_row(row)
    print safe_encode(pt.get_string())

def print_one_entry(obj_dict, fields,line_len=LINE_WORD_NUM):
    pt = prettytable.PrettyTable([f for f in fields], caching=False)
    pt.align = 'l'

    row = []
    for field in fields:
        field_name = field.lower().replace(' ', '_')
        try:
            data = obj_dict[field_name] or ''
        except KeyError,e:
            logger.debug("print_one_entry exception %s" %e)
            data = ''
        row.append(line_length_limit(data,line_len))
    pt.add_row(row)

    print safe_encode(pt.get_string())

def line_length_limit(data,line_len=LINE_WORD_NUM):
    ret_data = ''
    if type(data) == types.ListType:
        for str_t in data:
            ret_data += line_length_limit_ext(str_t,line_len) + ',\n'
        ret_data = ret_data[:-2]
    elif type(data) == types.DictType:
        for str_key,str_value in data.items():
            ret_data += line_length_limit_ext(str(str_key),line_len)+':'+line_length_limit_ext(str(str_value),line_len) \
                        + ',\n'
        ret_data = ret_data[:-2]
    else:
        ret_data = line_length_limit_ext(str(data),line_len)
    return ret_data

def line_length_limit_dict2(data, line_len=LINE_WORD_NUM):
    ret_data = ''
    if type(data) == types.ListType:
        for str_t in data:
            ret_data += line_length_limit_dict_ext(str_t, line_len) + '\n'
        ret_data = ret_data.strip('\n') + '\n'
    elif type(data) == types.DictType:
        for str_key, str_value in data.items():
            ret_data += line_length_limit_ext(str(str_key),line_len) + ':' + line_length_limit_dict_ext(str_value,line_len) \
                        + ',\n'
        ret_data = (ret_data[:-2] + '\n').strip('\n') + '\n'
    else:
        ret_data = (line_length_limit_ext(str(data),line_len)).strip('\n')
    return ret_data


def line_length_limit_dict(data, line_len=LINE_WORD_NUM):
    ret_data = ''
    if type(data) == types.ListType:
        for str_t in data:
            ret_data += line_length_limit_dict_ext(str_t, line_len) + '\n'
        ret_data = ret_data.strip('\n') + '\n'
    elif type(data) == types.DictType:
        if 'name' in data.keys():
            ret_data += line_length_limit_ext('name',line_len) + ':' + line_length_limit_dict_ext(data['name'],line_len) \
                        + ',\n'
        for str_key, str_value in data.items():
            if str_key == 'name':
                continue
            ret_data += line_length_limit_ext(str(str_key),line_len) + ':' + line_length_limit_dict_ext(str_value,line_len) \
                        + ',\n'
        ret_data = (ret_data[:-2] + '\n').strip('\n') + '\n'
    else:
        ret_data = (line_length_limit_ext(str(data),line_len)).strip('\n')
    return ret_data



def line_length_limit_dict_ext1(data, line_len=LINE_WORD_NUM):
    ret_data = ''
    if type(data) == types.ListType:
        for str_t in data:
            ret_data += line_length_limit_ext(str_t, line_len) + '\n'
        ret_data = ret_data.strip('\n') + '\n'
    elif type(data) == types.DictType:
        for str_key, str_value in data.items():
            ret_data += line_length_limit_ext(str(str_key),line_len) + ':' + line_length_limit_ext(str_value,line_len) \
                        + ',\n'
        ret_data = (ret_data[:-2] + '\n').strip('\n') + '\n'
    else:
        ret_data = (line_length_limit_ext(str(data),line_len)).strip('\n')
    return ret_data

def line_length_limit_dict_ext(data, line_len=LINE_WORD_NUM):
    ret_data = ''
    if type(data) == types.ListType:
        for str_t in data:
            ret_data += line_length_limit_hostcfg(str_t, line_len) + '\n'
        ret_data = ret_data.strip('\n') + '\n'
    elif type(data) == types.DictType:
        if 'name' in data.keys():
            ret_data += line_length_limit_ext('name',line_len) + ':' + line_length_limit_hostcfg(data['name'],line_len) \
                        + ',\n'
        for str_key, str_value in data.items():
            if str_key == 'name':
                continue
            ret_data += line_length_limit_ext(str(str_key),line_len) + ':' + line_length_limit_hostcfg(str_value,line_len) \
                        + ',\n'
        ret_data = (ret_data[:-2] + '\n').strip('\n') + '\n'
    else:
        ret_data = (line_length_limit_ext(str(data),line_len)).strip('\n')
    return ret_data

def line_length_limit_hostcfg(data,line_len=LINE_WORD_NUM):
    ret_data = ''
    if type(data) == types.ListType:
        for str_t in data:
            ret_data += line_length_limit_hostcfg(str_t,line_len) + ', '
        ret_data = line_length_limit_ext(ret_data[:-2], line_len) + '\n'
    elif type(data) == types.DictType:
        for str_key, str_value in data.items():
            ret_data += line_length_limit_hostcfg(str(str_key), line_len)+': '+line_length_limit_hostcfg(str_value, line_len) \
                        + ',\n'
        ret_data = '{' + ret_data[:-2] + '}'
    else:
        ret_data = line_length_limit_ext(str(data),line_len)
    return ret_data


def line_length_limit_ext(data,line_len=LINE_WORD_NUM):
    data = str(data).encode('utf-8')
    ret_data = ''
    count = 0
    while True:
        tmp = len(data)-count
        if (tmp <= line_len):
            ret_data = ret_data + data[count:len(data)]+'\n'
            break
        else:
            ret_data += data[count:(count+line_len)] + '\n'
            count += line_len

    return  ret_data[:-1]

def print_error_msg(error_msg):
    fields=['result']
    pt = prettytable.PrettyTable([f for f in fields], caching=False)
    pt.align = 'l'
    row = [error_msg]

    pt.add_row(row)
    print safe_encode(pt.get_string())

def print_response_error(ret_body):
    LOG.debug("Response failed msg : " + str(ret_body))
    if not ret_body:
        print 'Response Content is Empty!'
        return
    body_list = ret_body.keys()
    if len(body_list) == 1:
        print ret_body[body_list[0]][RESPONSE_ERROR_INFO_DETAILS]
    else:
        print 'Response Content is Error!'

def print_dict(d):
    pt = prettytable.PrettyTable(['Property', 'Value'], caching=False)
    pt.align = 'l'
    row = []
    for r in d.iteritems():
        row = list(r)
        row = [line_length_limit(key) for key in row]
        pt.add_row(row)
    print safe_encode(pt.get_string(sortby='Property'))


def print_dict_ext(d, keys, formatters={}):
    pt = prettytable.PrettyTable(['Property', 'Value'], caching=False)
    pt.align = 'l'
    for field in keys:
        if field in d.keys():
            if field in formatters:
                pt.add_row([field, line_length_limit_dict(formatters[field](d[field]))])
            else:
                pt.add_row([field, line_length_limit_dict(d[field])])
    print safe_encode(pt.get_string())

def print_dict_by_fileds(d, fields):
    pt = prettytable.PrettyTable(['Property', 'Value'], caching=False)
    pt.align = 'l'
    row = []
    length = LINE_WORD_NUM
    for item in fields:
        if d.has_key(item):
            strItem = '%s'%d[item]
            if len(strItem) > 100:
                length = 80
                break
    for item in fields:
        if d.has_key(item):
            row = [line_length_limit(item), line_length_limit_for_host_show(d[item], length)]
            pt.add_row(row)
    print safe_encode(pt.get_string())

def line_length_limit_for_host_show(data,line_len=LINE_WORD_NUM):
    '''
    only for host-show
    '''
    ret_data = ''

    if type(data) == types.ListType:
        for str_t in data:
            if type(str_t) == types.DictType:
                ret_data += line_length_limit_ext_for_host_show(str_t,line_len) + ''
            else:
                ret_data += line_length_limit_ext_for_host_show(str_t,line_len) + ' \n'

        ret_data = ret_data[:-2]

    elif type(data) == types.DictType:
        for str_key,str_value in data.items():
            ret_data += line_length_limit_ext_for_host_show(str(str_key),line_len)+':'+line_length_limit_ext_for_host_show(str(str_value),line_len) \
                        + ' \n'
        ret_data = ret_data[:-2]
    else:
        ret_data = line_length_limit_ext_for_host_show(str(data),line_len)
    return ret_data

def line_length_limit_ext_for_host_show(data,line_len=LINE_WORD_NUM):
    ret_data = ''
    order = ['name', 'mac', 'pci', 'speed', 'description','allsize','freesize',
             'dev', 'pcislot', 'disk' , 'size', 'mount', 'format']
    if type(data) == types.DictType:
        for filed in order:
            if data.has_key(filed):
                ret_data += line_length_limit_ext_for_host_show(str(filed),line_len)+':'\
                            +line_length_limit_ext_for_host_show(str(data[filed]),line_len) + ' \n'
        ret_data += '\n\n'
        return ret_data[:-1]

    data = str(data).encode('utf-8')
    ret_data = ''
    count = 0
    while True:
        tmp = len(data)-count
        if (tmp <= line_len):
            ret_data = ret_data + data[count:len(data)]+'\n'
            break
        else:
            ret_data += data[count:(count+line_len)] + '\n'
            count += line_len

    return  ret_data[:-1]


def find_resource(manager, name_or_id):
    """Helper for the _find_* methods."""
    # first try to get entity as integer id
    try:
        if isinstance(name_or_id, int) or name_or_id.isdigit():
            return manager.get(int(name_or_id))
    except exc.NotFound:
        pass

    # now try to get entity as uuid
    try:
        uuid.UUID(safe_encode(name_or_id))
        return manager.get(name_or_id)
    except (ValueError, exc.NotFound):
        pass

    # finally try to find entity by name
    matches = list(manager.list(filters={'name': name_or_id}))
    num_matches = len(matches)
    if num_matches == 0:
        msg = "No %s with a name or ID of '%s' exists." % \
              (manager.resource_class.__name__.lower(), name_or_id)
        raise exc.CommandError(msg)
    elif num_matches > 1:
        msg = ("Multiple %s matches found for '%s', use an ID to be more"
               " specific." % (manager.resource_class.__name__.lower(),
                               name_or_id))
        raise exc.CommandError(msg)
    else:
        return matches[0]


def string_to_bool(arg_name):
    return arg_name.strip().lower() in ('t', 'true', 'yes', '1')


def env(*vars, **kwargs):
    """Search for the first defined of possibly many env vars

    Returns the first environment variable defined in vars, or
    returns the default defined in kwargs.
    """
    for v in vars:
        value = os.environ.get(v, None)
        if value:
            return value
    return kwargs.get('default', '')


def import_versioned_module(version, submodule=None):
    module = 'glanceclient.v%s' % version
    if submodule:
        module = '.'.join((module, submodule))
    return importutils.import_module(module)


def exit(msg=''):
    if msg:
        print >> sys.stderr, safe_encode(msg)
    sys.exit(1)


def save_image(data, path):
    """
    Save an image to the specified path.

    :param data: binary data of the image
    :param path: path to save the image to
    """
    if path is None:
        image = sys.stdout
    else:
        image = open(path, 'wb')
    try:
        for chunk in data:
            image.write(chunk)
    finally:
        if path is not None:
            image.close()


def make_size_human_readable(size):
    suffix = ['B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB']
    base = 1024.0

    index = 0
    while size >= base:
        index = index + 1
        size = size / base

    padded = '%.1f' % size
    stripped = padded.rstrip('0').rstrip('.')

    return '%s%s' % (stripped, suffix[index])


def getsockopt(self, *args, **kwargs):
    """
    A function which allows us to monkey patch eventlet's
    GreenSocket, adding a required 'getsockopt' method.
    TODO: (mclaren) we can remove this once the eventlet fix
    (https://bitbucket.org/eventlet/eventlet/commits/609f230)
    lands in mainstream packages.
    """
    return self.fd.getsockopt(*args, **kwargs)


def exception_to_str(exc_name):
    try:
        error = unicode(exc_name)
    except UnicodeError:
        try:
            error = str(exc_name)
        except UnicodeError:
            error = ("Caught '%(exception)s' exception." %
                     {"exception": exc_name.__class__.__name__})
    return safe_encode(error, errors='ignore')


def get_file_size(file_obj):
    """
    Analyze file-like object and attempt to determine its size.

    :param file_obj: file-like object.
    :retval The file's size or None if it cannot be determined.
    """
    if hasattr(file_obj, 'seek') and hasattr(file_obj, 'tell'):
        try:
            curr = file_obj.tell()
            file_obj.seek(0, os.SEEK_END)
            size = file_obj.tell()
            file_obj.seek(curr)
            return size
        except IOError as e:
            if e.errno == errno.ESPIPE:
                # Illegal seek. This means the file object
                # is a pipe (e.g the user is trying
                # to pipe image data to the client,
                # echo testdata | bin/glance add blah...), or
                # that file object is empty, or that a file-like
                # object which doesn't support 'seek/tell' has
                # been supplied.
                return
            else:
                raise


def get_data_file(args):
    if args.file:
        return open(args.file, 'rb')
    else:
        # distinguish cases where:
        # (1) stdin is not valid (as in cron jobs):
        #     glance ... <&-
        # (2) image data is provided through standard input:
        #     glance ... < /tmp/file or cat /tmp/file | glance ...
        # (3) no image data provided:
        #     glance ...
        try:
            os.fstat(0)
        except OSError:
            # (1) stdin is not valid (closed...)
            return None
        if not sys.stdin.isatty():
            # (2) image data is provided through standard input
            if msvcrt:
                msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
            return sys.stdin
        else:
            # (3) no image data provided
            return None


def split_str_to_list(input_name):
    ret_list=[]
    ret_list_tmp = input_name.split(',')
    for str_tmp in  ret_list_tmp:
        ret_list.append(str_tmp.strip())
    return ret_list

def read_cfg_file(file_path):
    try:
        file_cfg = None
        file_cfg = open(file_path)
        ret_str = ''
        while 1:
            line = file_cfg.readline()
            if not line:
                return ret_str
            ret_str = ret_str + line
    except IOError,e:
        raise exc.CfgPathError(str(e.message))
    finally:
        if file_cfg is not None:
            file_cfg.close()

#parse Parameters
def list_to_dict(in_list):

    try:
        ret_dict = {}
        for str_t in in_list:
            key_str = str_t[:str_t.index('=')].strip()
            value_str = str_t[str_t.index('=')+1:].strip()
            ret_dict[key_str] = value_str
        return ret_dict
    except ValueError,e:
        logger.error("exception = %s ." %e)
        raise exc.ResponseError, 'Parameters error!'

def list_to_dict_vm(in_list):

    try:
        ret_dict = {}
        for str_t in in_list:
            key_str = str_t[:str_t.index('=')].strip()
            value_str = str_t[str_t.index('=')+1:].strip()
            if(key_str == 'hosts'):
                value_list = split_str_to_list(value_str)
                ret_dict[key_str] = value_list
            else:
                ret_dict[key_str] = value_str
        return ret_dict
    except ValueError,e:
        logger.error("exception = %s ." %e)
        raise exc.ResponseError, 'Parameters error!'

#parse Parameters
def list_to_dict_ext(in_list):

    try:
        ret_dict = {}
        for str_t in in_list:
            key_str = str_t[:str_t.index('=')].strip()
            value_str = str_t[str_t.index('=')+1:].strip()
            ret_dict[key_str] = list(set(split_str_to_list(value_str)))
        return ret_dict
    except ValueError:
        raise exc.ResponseError, 'Parameters error!'

def list_to_dict_upg(in_list):
    try:
        ret_dict = {}
        for str_t in in_list:
            key_str = str_t[:str_t.index(',')].strip()
            if key_str in ret_dict.keys():
                raise exc.ResponseError, '%s is exist' % key_str
            value_str = str_t[str_t.index(',')+1:].strip()
            ret_dict[key_str] = value_str
        return ret_dict
    except ValueError:
        raise exc.ResponseError, 'Parameters error!'

def add_name_to_dict(in_dict, name=''):
    fields = ['name']
    try:
        ret_name = in_dict['name']
        if ret_name == name:
            raise KeyError,'error'
        else:
            param_keys = in_dict.keys()
            in_dict['old_name'] = name
            param_keys.append('old_name')
    except KeyError:
        in_dict['name'] = name
        param_keys = in_dict.keys()

    param_keys.remove('name')
    fields.extend(param_keys)

    return in_dict

def cpsclientJudge(strInfo, bIsList):
    if bIsList:
        if 'sys-client' in strInfo:
            strInfo.remove('sys-client')
            return True
    else:
        if 0 == cmp(strInfo, 'sys-client'):
            return True

    return False

def get_use_input(prompt):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                return None
            else:
                return result
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            PrintUtil.print_msg(["please input again", "请重新输入"])
            continue

def get_use_input_notempty(prompt):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                continue
            else:
                return result
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            PrintUtil.print_msg(["please input again", "请重新输入"])
            continue

def get_use_input_default(prompt, default_value):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                return str(default_value)
            else:
                return result
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            PrintUtil.print_msg(["please input again", "请重新输入"])
            continue

def check_conflict_vlan(input_str, assigned_vlan):
    input_vlan = input_str.lstrip('0')
    for nw_name in assigned_vlan:
        if input_vlan == assigned_vlan[nw_name]:
            PrintUtil.print_msg_ex(VLAN_ID_CONFLICT, (nw_name, input_vlan), error=True)
            return False
    return True

def get_user_input_default_vlan_check(prompt, default_value, assigned_vlan):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                return str(default_value)
            elif result.isdigit():
                if not ( int(result) >= 1 and int(result) <= 4094 ):
                    print "input illegal, input again"
                    continue
                if check_conflict_vlan(result, assigned_vlan):
                    return result
                else:
                    continue
            else:
                PrintUtil.print_msg(["input illegal, input again", "请重新输入"])
                continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            PrintUtil.print_msg(["please input again", "请重新输入"])
            continue

def get_user_input_default_check(prompt, default_value, checkfunc):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                return str(default_value)
            else:
                if checkfunc(result):
                    return result
                else:
                    PrintUtil.print_msg(["input illegal, input again", "请重新输入"])
                    continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            PrintUtil.print_msg(["please input again", "请重新输入"])
            continue

def get_user_input_check(prompt, checkfunc):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                PrintUtil.print_msg(["input none, input again", "输入空,请重新输入"])
                continue
            else:
                if checkfunc(result):
                    return result
                else:
                    PrintUtil.print_msg(["input illegal, input again", "请重新输入"])
                    continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            PrintUtil.print_msg(["illegal,please input again", "请重新输入"])
            continue

def get_user_input_check_param(prompt, checkfunc, param):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                PrintUtil.print_msg(["input none, input again", "输入空,请重新输入"])
                continue
            else:
                if checkfunc(result, param):
                    return result
                else:
                    PrintUtil.print_msg(["input illegal, input again", "请重新输入"])
                    continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            PrintUtil.print_msg(["please input again", "请重新输入"])
            continue

def get_use_input_check_2(prompt, default_value, expectValue):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                return str(default_value)
            elif result in expectValue:
                return result
            else:
                print PrintUtil.get_msg(["please input again,only support:", "请重新输入,只支持:"]) + str(expectValue)
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            print PrintUtil.get_msg(["please input again", "请重新输入"])
            continue

def get_use_input_check_expect(prompt, expectValue):
    while 1:
        try:
            result = raw_input(prompt).strip()
            if result == "":
                continue
            elif result in expectValue:
                return result
            else:
                PrintUtil.print_msg(["please input again", "请重新输入"])
                continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception:
            PrintUtil.print_msg(["please input again", "请重新输入"])
            continue

def is_subnet(subnet_str):
    if subnet_str.find("/") == -1:
        return False

    ip_str = subnet_str.split("/")[0]
    mask = subnet_str.split("/")[1]

    ip = str(ip_str)
    pattern = r"^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])$"
    p = re.compile(pattern)
    if p.match(ip) is None:
        return False

    # 检查mask
    try:
        num_mask = int(mask)
        if num_mask >= 32 or num_mask < 0:
            return False
        if not check_subnet_ip_mask(subnet_str):
            return False
        return True
    except:
        return False

def is_secondip_larger(firstip,secondip):
    firstip_int = socket.ntohl(struct.unpack('I',socket.inet_aton(firstip))[0])
    secondip_int = socket.ntohl(struct.unpack('I',socket.inet_aton(secondip))[0])
    if firstip_int < secondip_int:
        return True
    return False

def is_gateway_legal(gateway,subnet,ippool_start,ippool_end):
    if is_ip_in_subnet(gateway,subnet):
        if is_secondip_larger(ippool_end,gateway) or is_secondip_larger(gateway,ippool_start):
            return True
    return False

def ip_to_bin(ip_str):
    ip_list = ip_str.split(".")
    result = ""
    for k in range(4):
        result_tmp = ""
        x = ip_list[k]
        x = int(x)
        if 0 == x:
            result += "00000000"
            continue
        while x > 0:
            mod = x % 2
            x /= 2
            result_tmp = str(mod) + result_tmp
        if 8 == len(result_tmp):
            result += result_tmp
            continue
        if 8 > len(result_tmp):
            num = 8 - len(result_tmp)
            for i in range(num):
                result_tmp = '0' + result_tmp
        result += result_tmp
    return result

def is_ip_in_subnet(ip_str,subnet_str):
    ip_str_bin = ip_to_bin(ip_str)
    subnet_ip_str = subnet_str.split("/")[0]
    subnet_mask = subnet_str.split("/")[1]
    subnet_ip_str_bin = ip_to_bin(subnet_ip_str)

    for l in range(int(subnet_mask)):
        if ip_str_bin[l] != subnet_ip_str_bin[l]:
            return False
    host_num_str0 = ""
    host_num_str1 = ""
    host_num_ip_str = ""
    for m in range(32-int(subnet_mask)):
        host_num_str0 += '0'
        host_num_str1 += '1'
    for n in range(int(subnet_mask),32):
        host_num_ip_str += ip_str_bin[n]
    if ( host_num_ip_str == host_num_str0 ) or ( host_num_ip_str == host_num_str1 ):
        return False
    return True

def check_subnet_ip_mask(subnet_str):
    ip_str = subnet_str.split("/")[0]
    mask = subnet_str.split("/")[1]
    result = ""
    ip_list = ip_str.split(".")
    for k in range(4):
        result_tmp = ""
        x = ip_list[k]
        x = int(x)
        if 0 == x:
            result += "00000000"
            continue
        while x > 0:
            mod = x % 2
            x /= 2
            result_tmp = str(mod) + result_tmp
        if 8 == len(result_tmp):
            result += result_tmp
            continue
        if 8 > len(result_tmp):
            num = 8 - len(result_tmp)
            for i in range(num):
                result_tmp = '0' + result_tmp
        result += result_tmp
    for l in range(int(mask),32):
        if result[l] != '0':
            return False

    return True
