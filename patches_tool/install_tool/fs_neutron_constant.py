#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join

NEUTRON_INI_PATH = join(os.path.dirname(os.path.abspath(__file__)), 'fs_neutron.ini')
SECTION_NEUTRON_CONFIG = "neutron"
SECTION_NEUTRON_CONFIG_SECURITY = "security_group"
SECTION_NEUTRON_CONFIG_USE_VXLAN = "use_vxlan_flag"