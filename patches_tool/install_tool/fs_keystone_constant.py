#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join

CLOUD_USER = "cloud_admin"
CLOUD_TENANT = "admin"

#ini文件中
KEYSTONE_INI_PATH = join(os.path.dirname(os.path.abspath(__file__)), 'default_sys.ini')
SECTION_KEYSTONE_CONFIG = "keystone"
SECTION_KEYSTONE_CONFIG_ENDPOINTS = "endpoints_https"
SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG_YES = "YES"
SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG_NO = "NO"
SECTION_KEYSTONE_CONFIG_DC_ADMIN_FLAG = "dc_admin_flag"
SECTION_KEYSTONE_CONFIG_DC_ADMIN = "dc_admin"

HAPROXY_CONFIG_SECTION = "reverse_proxy"
HAPROXY_EXTERNAL_API_IP = "external_api_ip"
HAPROXY_FRONTSSL = "frontssl"
HAPROXY_BACKENDSSL = "backendssl"

APACHEPROXY_CONFIG_SECTION = "forward_proxy"
APACHEPROXY_EXTERNAL_API_IP = "external_api_ip"
APACHEPROXY_PROXY_REMOTE_MATCH ="proxy_remote_match"

HTTP_MODE = "http_mode"
