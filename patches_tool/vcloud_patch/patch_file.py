#!/usr/bin/env python
# -*-coding:utf-8-*-

__author__ = 'luqitao'

import sys
import os
import json
import socket
import traceback

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = "hybrid_patches_tool"

sys.path.extend([CURRENT_PATH + "/../../", "/usr/bin/"])

import utils
from install_tool import cps_server
from patches_tool.services import RefServices, RefCPSServiceExtent, RefCPSService, RefFsSystemUtils
from patches_tool import config
import log as LOG


def restart_component(service_name, template_name):
    """Stop an component, then start it."""

    ret = RefCPSServiceExtent.host_template_instance_operate(service_name, template_name, 'stop')
    if not ret:
        LOG.error("cps template_instance_action stop for %s failed." % template_name)
        return ret
    ret = RefCPSServiceExtent.host_template_instance_operate(service_name, template_name, 'start')
    if not ret:
        LOG.error("cps template_instance_action start for %s failed." % template_name)
        return ret


def config_cascaded_az():
    """Update parameter for neutron-server and cinder-volume, then restart them."""

    params = {'mechanism_drivers': 'openvswitch,l2populationcascaded,evs,sriovnicswitch,netmapnicswitch'}
    ret = cps_server.update_template_params('neutron', 'neutron-server', params)
    if not ret:
        LOG.error("cps update_template_params for neutron-server failed.")
        return ret

    params = {'volume_driver': 'cinder.volume.drivers.vcloud.driver.VMwareVcloudVolumeDriver'}
    ret = cps_server.update_template_params('cinder', 'cinder-volume', params)
    if not ret:
        LOG.error("cps update_template_params for neutron-server failed.")
        return ret
    cps_server.cps_commit()

    restart_component('neutron', 'neutron-openvswitch-agent')
    restart_component('cinder', 'cinder-volume')
    restart_component('nova', 'nova-compute')


def replace_config(conf_file_path, src_key, new_key, new_value):
    """Update the config file by a given dict."""

    with open(conf_file_path, "a+") as fp:
        content = json.load(fp)

        content[src_key].update(new_value[new_key])
        fp.truncate(0)
        fp.write(json.dumps(content, indent=4))


def replace_all_config():
    """Replace vcloud info for nova-compute and cinder-volume"""

    file_vcloud_config_json = os.path.join(CURRENT_PATH, "vcloud_config.json")

    with open(file_vcloud_config_json, "r") as fp:
        vcloud_config_content = json.load(fp)

    cur_path = os.path.split(os.path.realpath(__file__))[0]
    nova_compute_path = os.path.join(cur_path, "code", "etc", "nova", "others", "cfg_template", "nova-compute.json")
    replace_config(nova_compute_path, "nova.conf", "conf", vcloud_config_content)

    if "vcenter" in vcloud_config_content["conf"].keys():
        del vcloud_config_content["conf"]["vcenter"]
    cinder_volume_path = os.path.join(cur_path, "code", "etc", "cinder", "others", "cfg_template", "cinder-volume.json")
    replace_config(cinder_volume_path, "cinder.conf", "conf", vcloud_config_content)


def patch_hybridcloud_files():
    """Execute a shell script, do this things:
    1. replace python code
    2. update configuration files
    3. install some dependence packages
    4. restart component proc
    """

    utils.execute(['dos2unix', os.path.join(CURRENT_PATH, 'install.sh')])
    utils.execute(['sh', os.path.join(CURRENT_PATH, 'install.sh')])


def create_aggregate_in_cascaded_node():
    """
    nova aggregate-create az31.singapore--aws az31.singapore--aws
    nova host-list
    nova aggregate-add-host az31.singapore--aws 42114FD9-D446-9248-3A05-23CF474E3C68

    :return:
    """
    host_id = socket.gethostname()
    region = RefCPSService.get_local_domain()
    os_region_name = '.'.join([RefFsSystemUtils.get_az_by_domain(region), RefFsSystemUtils.get_dc_by_domain(region)])
    ref_service = RefServices()
    if not ref_service.nova_aggregate_exist(os_region_name, os_region_name):
        create_result = ref_service.nova_aggregate_create(os_region_name, os_region_name)
        if create_result is not None:
            ref_service.nova_aggregate_add_host(os_region_name, host_id)

if __name__ == '__main__':
    LOG.init('patches_tool_config')
    LOG.info('START to patch for VCLOUD...')
    config.export_env()
    try:
        LOG.info('start to replace all config file.')
        replace_all_config()

        LOG.info('Start to patch hyrbid-cloud files')
        patch_hybridcloud_files()

        LOG.info('Start to create ag in cascaded node')
        create_aggregate_in_cascaded_node()

        LOG.info('Start to config cascaded az')
        config_cascaded_az()
    except Exception, e:
        LOG.error('Exception when patch for vcloud cascaded. Exception: %s' % traceback.format_exc())

    LOG.info('END to patch for VCLOUD...')

