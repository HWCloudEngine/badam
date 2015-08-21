# Copyright 2011 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
A network utils module to use vcloudapi
"""

import re
import contextlib

from oslo.config import cfg
from oslo.vmware import api
from oslo.vmware import vim
import suds

from nova.virt.vcloudapi import exceptions
from nova import utils
from nova.i18n import _, _LI, _LW
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.openstack.common import uuidutils
from nova.virt import driver
from nova.virt.vcloudapi import vcenter_utils
from nova.virt.vcloudapi import network_utils
from nova.network import linux_net
from nova.network import model as network_model

vcloudapi_opts = [

    cfg.StrOpt('vcloud_bridge_prefix',
               default='qvb',
               help='the vm arp port on br-int bridge prefix'),

]

CONF = cfg.CONF
CONF.register_opts(vcloudapi_opts, 'vcloud')

LOG = logging.getLogger(__name__)


def create_org_vdc_network(session, org_vdc_name, vif):
    """use the vif to create_org_vdc_network
    now we just use the vif id to create a port, so we
    can find it's properties like vlanid in vcenter
    """

    create_orgvdcnetwork_with_name(session, org_vdc_name, vif['id'])

    # return the network name we just use
    return vif['id']


def create_orgvdcnetwork_with_name(session, org_vdc_name, network_name):
    gateway_name = ''
    start_address = '192.168.0.1'
    end_address = '192.168.0.253'
    gateway_ip = '192.168.0.254'
    netmask = '255.255.255.0'
    result, task = session._call_method(session.vca,
                                        "create_isolated_vdc_network",
                                        org_vdc_name, network_name,
                                        gateway_name, start_address,
                                        end_address, gateway_ip,
                                        netmask)

    # check the task is success or not
    if not result:
        raise exceptions.VCloudDriverException(
            "Create_org_network error, task:" +
            task)

    session._wait_for_task(task)


def delete_org_vdc_network(session, org_vdc_name, vif):
    """use the vif to create_org_vdc_network

    now we just use the vif id to create a port, so we
    can find it's properties like vlanid in vcenter
    """

    delete_orgvdcnetwork_with_name(session, org_vdc_name, vif['id'])

    # return the network name we just delete
    return vif['id']


def delete_orgvdcnetwork_with_name(session, org_vdc_name, network_name):
    """delete the org vdc network with given name """
    result, task = session._call_method(session.vca, "delete_isolated_vdc_network",
                                        org_vdc_name, network_name)

    # check the task is success or not
    if not result:
        raise exceptions.VCloudDriverException(
            "Delete_org_network error, task:" +
            task)
    if task is None:
        LOG.debug("Delete_org_network finished, task is none, network_name:"
                  "%s", network_name)
        return

    session._wait_for_task(task)


def plug_vif(vcenter_api, instance, vif, ovsport_info):
    """link the pg which name contains the network_name to the
    compute node bridge"""

    vlan_id, dvs_name = vcenter_api.get_dvs_and_vlanid_with_pgname_alias(
        vif['id'][:network_model.NIC_NAME_LEN])

    # TODO(nkapotoxin) check the dvs_name is correct or not?

    plug_ovs_hybrid(instance, vif, ovsport_info, vlan_id)


def plug_ovs_hybrid(instance, vif, ovsport_info, vlan_id):
    """Plug using hybrid strategy

    Create a per-VIF linux bridge, then link that bridge to the OVS
    integration bridge via a veth device, setting up the other end
    of the veth device just like a normal OVS port.  Then boot the
    VIF on the linux bridge using standard libvirt mechanisms.
    """

    iface_id = get_ovs_interfaceid(vif)
    br_name = get_br_name(vif['id'])
    v1_name, v2_name = get_veth_pair_names(vif['id'])
    gbr_name = get_gbr_name(vif['id'])
    tap_name, taq_name = get_gveth_pair_names(vif['id'])
    ovs_nicport = ovsport_info['ovs_ethport']
    vlan_tag = str(vlan_id)
    nic_name = ovs_nicport + '.' + vlan_tag

    # add the first gbr to connect to the origin qbr
    if not linux_net.device_exists(gbr_name):
        utils.execute('brctl', 'addbr', gbr_name, run_as_root=True)
        utils.execute('brctl', 'setfd', gbr_name, 0, run_as_root=True)
        utils.execute('brctl', 'stp', gbr_name, 'off', run_as_root=True)
        utils.execute('tee',
                      ('/sys/class/net/%s/bridge/multicast_snooping' %
                       gbr_name),
                      process_input='0',
                      run_as_root=True,
                      check_exit_code=[0, 1])

        if linux_net.device_exists(nic_name):
            # try to delete the exists nic_name in whatever br
            utils.execute('vconfig', 'rem', nic_name, run_as_root=True)

    if not linux_net.device_exists(tap_name):
        linux_net._create_veth_pair(tap_name, taq_name)
        utils.execute(
            'ip',
            'link',
            'set',
            gbr_name,
            'up',
            run_as_root=True)
        utils.execute(
            'brctl',
            'addif',
            gbr_name,
            taq_name,
            run_as_root=True)

    # add the second qbr to connect to the origin ovs br-int
    if not linux_net.device_exists(br_name):
        utils.execute('brctl', 'addbr', br_name, run_as_root=True)
        utils.execute('brctl', 'setfd', br_name, 0, run_as_root=True)
        utils.execute('brctl', 'stp', br_name, 'off', run_as_root=True)
        utils.execute('tee',
                      ('/sys/class/net/%s/bridge/multicast_snooping' %
                       br_name),
                      process_input='0',
                      run_as_root=True,
                      check_exit_code=[0, 1])
        utils.execute(
            'brctl',
            'addif',
            br_name,
            tap_name,
            run_as_root=True)

    if not linux_net.device_exists(v2_name):
        linux_net._create_veth_pair(v1_name, v2_name)
        utils.execute('ip', 'link', 'set', br_name, 'up', run_as_root=True)
        utils.execute('brctl', 'addif', br_name, v1_name, run_as_root=True)
        linux_net.create_ovs_vif_port(get_bridge_name(vif),
                                      v2_name, iface_id, vif['address'],
                                      instance['uuid'])

    # connect qbrxxxx to nic
    if not linux_net.device_exists(nic_name):
        try:
            # ifup ovs_ethport
            utils.execute('ifconfig', ovs_nicport, 'up', run_as_root=True)

            # add brif
            utils.execute('vconfig', 'add', ovs_nicport, vlan_tag,
                          run_as_root=True)

            # up the if
            utils.execute('ifconfig', nic_name, 'up', run_as_root=True)

            connect_nic_to_br(instance, gbr_name, nic_name)
        except Exception as exc:
            LOG.exception(exc, instance=instance)
        LOG.debug(
            'Connect nic to br finished, vir:%s',
            vif,
            instance=instance)


def get_ovs_interfaceid(vif):
    return vif.get('ovs_interfaceid') or vif['id']


def get_br_name(iface_id):
    return ("qbr" + iface_id)[:network_model.NIC_NAME_LEN]


def get_gbr_name(iface_id):
    """generate the security supported br"""
    return ("qgr" + iface_id)[:network_model.NIC_NAME_LEN]


def get_gveth_pair_names(iface_id):
    """generate the security supported pair veth"""
    return (("tap%s" % iface_id)[:network_model.NIC_NAME_LEN],
            ("taq%s" % iface_id)[:network_model.NIC_NAME_LEN])


def get_veth_pair_names(iface_id):
    return (((CONF.vcloud.vcloud_bridge_prefix + "%s")
             % iface_id)[:network_model.NIC_NAME_LEN],
            ("qvo%s" % iface_id)[:network_model.NIC_NAME_LEN])


def connect_nic_to_br(instance, br_name, nic_name):
    utils.execute('brctl', 'addif', br_name, nic_name, run_as_root=True)


def get_bridge_name(vif):
    return vif['network']['bridge']


def unplug_vif(vcenter_api, instance, vif, ovsport_info):
    """link the pg which name contains the network_name to the
    compute node bridge"""

    vlan_id, dvs_name = vcenter_api.get_dvs_and_vlanid_with_pgname_alias(
        vif['id'][:network_model.NIC_NAME_LEN])

    # TODO(nkapotoxin) check the dvs_name is correct or not?
    if vlan_id is not None:
        unplug_ovs(instance, vif, ovsport_info, vlan_id)


def unplug_ovs(instance, vif, ovsport_info,
               vlan_id):
    unplug_ovs_hybrid(
        instance,
        vif,
        ovsport_info,
        vlan_id)


def unplug_ovs_hybrid(instance, vif, ovsport_info, vlan_id):
    """UnPlug using hybrid strategy

    Unhook port from OVS, unhook port from bridge, delete
    bridge, and delete both veth devices.
    """

    # now dirver use the configed nic eth0.100 instead
    ovs_nicport = ovsport_info['ovs_ethport']
    vlan_tag = str(vlan_id)
    nic_name = ovs_nicport + '.' + vlan_tag

    # remove the eth1 vlan config
    try:
        # try to delete the exists nic_name in whatever br
        utils.execute('vconfig', 'rem', nic_name, run_as_root=True)
    except Exception as exc:
        LOG.exception(exc, instance=instance)

    br_name = get_br_name(vif['id'])
    v1_name, v2_name = get_veth_pair_names(vif['id'])
    gbr_name = get_gbr_name(vif['id'])
    tap_name, taq_name = get_gveth_pair_names(vif['id'])

    if linux_net.device_exists(br_name):
        utils.execute('brctl', 'delif', br_name, v1_name,
                      run_as_root=True)
        utils.execute('brctl', 'delif', br_name, tap_name,
                      run_as_root=True)
        utils.execute('ip', 'link', 'set', br_name, 'down',
                      run_as_root=True)
        utils.execute('brctl', 'delbr', br_name,
                      run_as_root=True)

    linux_net.delete_ovs_vif_port(get_bridge_name(vif),
                                  v2_name)

    if linux_net.device_exists(gbr_name):
        utils.execute('brctl', 'delif', gbr_name, taq_name,
                      run_as_root=True)
        utils.execute('ip', 'link', 'set', gbr_name, 'down',
                      run_as_root=True)
        utils.execute('brctl', 'delbr', gbr_name,
                      run_as_root=True)

    # delete veth peer
    linux_net.delete_net_dev(v1_name)
    linux_net.delete_net_dev(v2_name)
    linux_net.delete_net_dev(tap_name)
    linux_net.delete_net_dev(taq_name)


def unplug_ovs_bridge(instance, vif):
    """No manual unplugging required."""
    pass
