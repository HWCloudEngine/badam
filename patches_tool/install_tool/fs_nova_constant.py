#!/usr/bin/env python
#-*-coding:utf-8-*-
import os
from os.path import join

NOVA_INI_PATH = join(os.path.dirname(os.path.abspath(__file__)), 'fs_nova.ini')
SECTION_NOVA_CONFIG = "nova"
SECTION_NOVA_CONFIG_TENANT = "vm_boot_on_ctrl_host"
SECTION_NOVA_CONFIG_WDT_REBOOT_TIME = "wdt_reboot_time"
SECTION_NOVA_CONFIG_WDT_START_TIME = "wdt_start_time"
SECTION_NOVA_CONFIG_INSTANCE_WATCHDOG = "instance_vwatchdog"
SECTION_NOVA_CONFIG_INSTANCE_CONSOLE = "instance_console_log"
SECTION_NOVA_CONFIG_INSTANCE_MEMORY_QOS = "instance_memory_qos"
SECTION_NOVA_CONFIG_NIC_SUSPENSION = "nic_suspension"
SECTION_NOVA_CONFIG_IS_OPEN_K_BOX = "is_open_kbox"
SECTION_NOVA_CONFIG_USER_NONVOLATILE_RAM = "use_nonvolatile_ram"
SECTION_NOVA_CONFIG_CPU_ALLOCATION_RATIO = "cpu_allocation_ratio"
SECTION_NOVA_CONFIG_DISK_ALLOCATION_RATIO = "disk_allocation_ratio"
SECTION_NOVA_CONFIG_RAM_ALLOCATION_RATIO = "ram_allocation_ratio"
SECTION_NOVA_CONFIG_HA_FLAG = "ha_flag"
SECTION_NOVA_CONFIG_UPLOAD_VOLUME_TO_IMAGE = "upload_volume_to_image"
SECTION_NOVA_INSTANCE_NAME_TEMPLATE = "instance_name_template"