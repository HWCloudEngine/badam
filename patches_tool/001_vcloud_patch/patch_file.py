#!/usr/bin/env python
# -*-coding:utf-8-*-

__author__ = 'luqitao'

import sys
import os
import json
from os.path import join

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'hybrid_patches_tool.log')

sys.path.append(CURRENT_PATH + "/../")

import utils
from install_tool import cps_server
from install_tool import fs_log_util

LOG = fs_log_util.localLog.get_logger(LOG_FILE)
os.environ.setdefault("CPS_SERVER", "https://cps.az11.shenzhen--vcloud.huawei.com:443")
# os.environ.setdefault("CPS_SERVER", "https://cps.az1.dc1.domainname.com:443")


def restart_component(service_name, template_name):
    """Stop an component, then start it."""

    ret = cps_server.template_instance_action(service_name, template_name, 'stop')
    if not ret:
        LOG.error("cps template_instance_action stop for %s failed." % template_name)
        return ret
    ret = cps_server.template_instance_action(service_name, template_name, 'start')
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

    with open("vcloud_config.json", "r") as fp:
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

    utils.execute(['sh', 'install.sh'])


if __name__ == '__main__':
    replace_all_config()
    patch_hybridcloud_files()
    config_cascaded_az()

