#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join

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

GLANCE_INI_PATH = join(os.path.dirname(os.path.abspath(__file__)), 'fs_glance.ini')