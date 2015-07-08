#!/usr/bin/env python
# Copyright 2011 VMware, Inc.
# All Rights Reserved.
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

import hashlib
import re
import signal
import sys
import time
import random

import eventlet
eventlet.monkey_patch()

import netaddr
from neutron.plugins.openvswitch.agent import ovs_dvr_neutron_agent
from oslo.config import cfg
from six import moves
from oslo import messaging

from neutron.agent import l2population_rpc
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import polling
from neutron.agent.linux import utils
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.handlers import dvr_rpc
from neutron.common import config as common_config
from neutron.common import constants as q_const
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.extensions import qos
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.common import config  # noqa
from neutron.plugins.openvswitch.common import constants
from neutron.plugins.openvswitch.agent import neutron_bus_client
from neutron.services.qos.agents import qos_rpc

LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = str(q_const.MAX_VLAN_TAG + 1)
Agent_Start_Report_Retry_Interval = 2


class DeviceListRetrievalError(exceptions.NeutronException):
    message = _("Unable to retrieve port details for devices: %(devices)s "
                "because of error: %(error)s")


class AgentError(exceptions.NeutronException):
    msg_fmt = _('Error during following call to agent: %(method)s')


# A class to represent a VIF (i.e., a port that has 'iface-id' and 'vif-mac'
# attributes set).
class LocalVLANMapping:
    def __init__(self, vlan, network_type, physical_network, segmentation_id,
                 vif_ports=None):
        if vif_ports is None:
            vif_ports = {}
        self.vlan = vlan
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.vif_ports = vif_ports
        # set of tunnel ports on which packets should be flooded
        self.tun_ofports = set()

    def __str__(self):
        return ("lv-id = %s type = %s phys-net = %s phys-id = %s" %
                (self.vlan, self.network_type, self.physical_network,
                 self.segmentation_id))


class VmPort:
    def __init__(self, mac, ip_address=None):
        self.mac_address = mac
        if(not ip_address):
            self.ip_address = set()
        else:
            self.ip_address = set()
            self.ip_address.add(ip_address)



class VLANBridge(ovs_lib.OVSBridge):
    """Extends OVSBridge for Trunkport."""
    def __init__(self, br_name, int_br, root_helper):
        super(VLANBridge, self).__init__(br_name, root_helper)
        self.int_br = int_br
        self.vlan_port_name = "pvm" + br_name[3:]
        self.int_br_port_name = "pin" + br_name[3:]

    def configure(self):

        ports = self.get_port_name_list()

        if self.vlan_port_name not in ports:
            self.add_patch_port(
                self.vlan_port_name, self.int_br_port_name)

        self.vlan_ofport = self.get_port_ofport(self.vlan_port_name)

        ports = self.int_br.get_port_name_list()

        if self.int_br_port_name not in ports:
            self.int_br.add_patch_port(
                self.int_br_port_name, self.vlan_port_name)

        self.int_br_ofport = self.get_port_ofport(
            self.int_br_port_name)

        self.delete_flows(in_port=self.vlan_ofport)
        self.add_flow(priority=2,
                      in_port=self.vlan_ofport,
                      actions="drop")

        self.int_br.delete_flows(in_port=self.int_br_ofport)
        self.int_br.add_flow(priority=2,
                             in_port=self.int_br_ofport,
                             actions="drop")

    def cleanup_bridge(self):
        LOG.debug(_("Cleanup bridge br-int %s"), self.int_br_ofport)
        self.int_br.delete_flows(in_port=self.int_br_ofport)
        if self.bridge_exists(self.br_name):
            self.delete_flows(in_port=self.vlan_ofport)


    def _get_flows(self, br, of_port):
        flow_list = br.run_ofctl("dump-flows",
                                 ["in_port=%s" % of_port]).split("\n")[1:]

        p1 = re.compile('in_port=(\d+),dl_vlan=(\d+).*mod_vlan_vid:(\d+)')
        p2 = re.compile('in_port=(\d+),dl_vlan=(\d+).*strip_vlan')

        f = set()
        for l in flow_list:
            m = p1.search(l)
            if m:
                in_port = m.group(1)
                f_vid = int(m.group(2))
                t_vid = int(m.group(3))
                if(in_port == of_port):
                    f.add((f_vid, t_vid))
            m = p2.search(l)
            if m:
                in_port = m.group(1)
                f_vid = int(m.group(2))
                t_vid = "Untagged"
                if(in_port == of_port):
                    f.add((f_vid, t_vid))

        return f

    def init_flow_check(self):
        self.current_flows = self._get_flows(self,
                                             self.vlan_ofport)
        self.new_flows = set()

    def init_int_br_flow_check(self):
        self.current_int_br_flows = self._get_flows(self.int_br,
                                                    self.int_br_ofport)
        self.new_int_br_flows = set()

    def _set_mapping(self, vm_flow_vid, int_br_vid, record_vid, action):
        self.new_int_br_flows.add((record_vid, int_br_vid))
        if (record_vid, int_br_vid) not in self.current_int_br_flows:
            self.int_br.add_flow(
                priority=3, in_port=self.int_br_ofport,
                dl_vlan=vm_flow_vid,
                actions="mod_vlan_vid:%s,normal" % int_br_vid)
        else:
            LOG.debug(_("Flow already in place: %s"), (record_vid, int_br_vid))

        self.new_flows.add((int_br_vid, record_vid))
        if (int_br_vid, record_vid) not in self.current_flows:
            self.add_flow(priority=3,
                          in_port=self.vlan_ofport,
                          dl_vlan=int_br_vid,
                          actions=action)
        else:
            LOG.debug(_("Flow already in place: %s"), (int_br_vid, record_vid))

    def set_mapping(self, vm_vid, int_br_vid):
        if vm_vid is None:
            self._set_mapping(0xffff, int_br_vid, "Untagged",
                              "strip_vlan,normal")
        else:
            self._set_mapping(vm_vid, int_br_vid, vm_vid,
                              "mod_vlan_vid:%s,normal" % vm_vid)

    def remove_flows(self,vid, local_vlan):
        self.int_br.delete_flows(in_port=self.int_br_ofport,
                                 dl_vlan=vid)

        self.delete_flows(in_port=self.vlan_ofport,
                      dl_vlan=local_vlan)

    def remove_extra_flows(self):
        remove = self.current_flows - self.new_flows
        int_br_remove = self.current_int_br_flows - self.new_int_br_flows
        for f in remove:
            if f[0] == 'Untagged':
                pass
            else:
                self.delete_flows(in_port=self.vlan_ofport,
                                  dl_vlan=f[0])
        for f in int_br_remove:
            if f[0] == 'Untagged':
                pass
            else:
                self.int_br.delete_flows(in_port=self.int_br_ofport,
                                         dl_vlan=f[0])

    def set_trunk(self, int_br_vid):
        self.int_br.add_flow(
            priority=3, in_port=self.int_br_ofport,
            actions="push_vlan:0x8100,mod_vlan_vid:%s,normal" % int_br_vid)
        self.add_flow(priority=3,
                      in_port=self.vlan_ofport,
                      dl_vlan=int_br_vid,
                      actions="strip_vlan,normal")


class OVSPluginApi(agent_rpc.PluginApi,
                   dvr_rpc.DVRServerRpcApiMixin,
                   sg_rpc.SecurityGroupServerRpcApiMixin,
                   qos_rpc.QoSServerRpcApiMixin):
    pass


class OVSSecurityGroupAgent(sg_rpc.SecurityGroupAgentRpcMixin):
    def __init__(self, context, plugin_rpc, root_helper):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper
        self.init_firewall(defer_refresh_firewall=True)

class OVSQoSAgent(qos_rpc.QoSAgentRpcMixin):
    def __init__(self, context, plugin_rpc, root_helper):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper

class OVSNeutronAgent(n_rpc.RpcCallback,
                      sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                      l2population_rpc.L2populationRpcCallBackTunnelMixin,
                      dvr_rpc.DVRAgentRpcCallbackMixin,
                      qos_rpc.QoSAgentRpcCallbackMixin):
    '''Implements OVS-based tunneling, VLANs and flat networks.

    Two local bridges are created: an integration bridge (defaults to
    'br-int') and a tunneling bridge (defaults to 'br-tun'). An
    additional bridge is created for each physical network interface
    used for VLANs and/or flat networks.

    All VM VIFs are plugged into the integration bridge. VM VIFs on a
    given virtual network share a common "local" VLAN (i.e. not
    propagated externally). The VLAN id of this local VLAN is mapped
    to the physical networking details realizing that virtual network.

    For virtual networks realized as GRE tunnels, a Logical Switch
    (LS) identifier is used to differentiate tenant traffic on
    inter-HV tunnels. A mesh of tunnels is created to other
    Hypervisors in the cloud. These tunnels originate and terminate on
    the tunneling bridge of each hypervisor. Port patching is done to
    connect local VLANs on the integration bridge to inter-hypervisor
    tunnels on the tunnel bridge.

    For each virtual network realized as a VLAN or flat network, a
    veth or a pair of patch ports is used to connect the local VLAN on
    the integration bridge with the physical network bridge, with flow
    rules adding, modifying, or stripping VLAN tags as necessary.
    '''

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    #   1.2 Support DVR (Distributed Virtual Router) RPC
    RPC_API_VERSION = '1.2'

    def __init__(self, integ_br, tun_br, local_ip,
                 bridge_mappings, root_helper,
                 polling_interval, tunnel_types=None,
                 veth_mtu=None, l2_population=False,
                 enable_distributed_routing=False,
                 minimize_polling=False,
                 ovsdb_monitor_respawn_interval=(
                     constants.DEFAULT_OVSDBMON_RESPAWN),
                 arp_responder=False,
                 use_veth_interconnection=False,
                 enable_dscp_vlanpcp_mapping=False):
        '''Constructor.

        :param integ_br: name of the integration bridge.
        :param tun_br: name of the tunnel bridge.
        :param local_ip: local IP address of this hypervisor.
        :param bridge_mappings: mappings from physical network name to bridge.
        :param root_helper: utility to use when running shell cmds.
        :param polling_interval: interval (secs) to poll DB.
        :param tunnel_types: A list of tunnel types to enable support for in
               the agent. If set, will automatically set enable_tunneling to
               True.
        :param veth_mtu: MTU size for veth interfaces.
        :param l2_population: Optional, whether L2 population is turned on
        :param minimize_polling: Optional, whether to minimize polling by
               monitoring ovsdb for interface changes.
        :param ovsdb_monitor_respawn_interval: Optional, when using polling
               minimization, the number of seconds to wait before respawning
               the ovsdb monitor.
        :param arp_responder: Optional, enable local ARP responder if it is
               supported.
        :param use_veth_interconnection: use veths instead of patch ports to
               interconnect the integration bridge to physical bridges.
        '''
        super(OVSNeutronAgent, self).__init__()
        self.enable_dscp_vlanpcp_mapping = enable_dscp_vlanpcp_mapping
        self.use_veth_interconnection = use_veth_interconnection
        self.veth_mtu = veth_mtu
        self.root_helper = root_helper
        self.available_local_vlans = set(moves.xrange(q_const.MIN_VLAN_TAG,
                                                      q_const.MAX_VLAN_TAG))
        self.use_call = True
        self.tunnel_types = tunnel_types or []
        self.l2_pop = l2_population
        # TODO(ethuleau): Change ARP responder so it's not dependent on the
        #                 ML2 l2 population mechanism driver.
        self.enable_distributed_routing = enable_distributed_routing
        self.arp_responder_enabled = arp_responder and self.l2_pop
        l2pop_network_types = cfg.CONF.AGENT.l2pop_network_types or self.tunnel_types

        self.agent_state = {
            'binary': 'neutron-openvswitch-agent',
            'host': cfg.CONF.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'tunnel_types': self.tunnel_types,
                               'tunneling_ip': local_ip,
                               'l2_population': self.l2_pop,
                               'l2pop_network_types': l2pop_network_types,
                               'arp_responder_enabled':
                               self.arp_responder_enabled,
                               'enable_distributed_routing':
                               self.enable_distributed_routing},
            'agent_type': q_const.AGENT_TYPE_OVS,
            'start_flag': True}

        # Keep track of int_br's device count for use by _report_state()
        self.int_br_device_count = 0

        self.int_br = ovs_lib.OVSBridge(integ_br, self.root_helper)
        self.setup_integration_br()
        # Stores port update notifications for processing in main rpc loop
        self.updated_ports = set()
        self.updated_ancillary_ports = set()
        self.bridge_mappings = bridge_mappings
        self.setup_physical_bridges(self.bridge_mappings)
        self.setup_rpc()
        self.local_vlan_map = {}
        self.local_vlan_bridges = set()
        self.trunk_backlog = list()
        self.trunk_subports = {}
        self.tun_br_ofports = {p_const.TYPE_GRE: {},
                               p_const.TYPE_VXLAN: {}}
        self.dhcp_ports = dict()

        self.polling_interval = polling_interval
        self.minimize_polling = minimize_polling
        self.ovsdb_monitor_respawn_interval = ovsdb_monitor_respawn_interval

        if tunnel_types:
            self.enable_tunneling = True
        else:
            self.enable_tunneling = False
        self.local_ip = local_ip
        self.tunnel_count = 0
        self.vxlan_udp_port = cfg.CONF.AGENT.vxlan_udp_port
        self.dont_fragment = cfg.CONF.AGENT.dont_fragment
        self.tun_br = None
        self.patch_int_ofport = constants.OFPORT_INVALID
        self.patch_tun_ofport = constants.OFPORT_INVALID
        if self.enable_tunneling:
            # The patch_int_ofport and patch_tun_ofport are updated
            # here inside the call to reset_tunnel_br()
            self.reset_tunnel_br(tun_br)

        self.dvr_agent = ovs_dvr_neutron_agent.OVSDVRNeutronAgent(
            self.context,
            self.plugin_rpc,
            self.int_br,
            self.tun_br,
            self.patch_int_ofport,
            self.patch_tun_ofport,
            cfg.CONF.host,
            self.enable_tunneling,
            self.enable_distributed_routing)

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

        if self.enable_tunneling:
            self.setup_tunnel_br()

        self.dvr_agent.setup_dvr_flows_on_integ_tun_br()

        # Collect additional bridges to monitor
        self.ancillary_brs = self.setup_ancillary_bridges(integ_br, tun_br)

        # Security group agent support
        self.sg_agent = OVSSecurityGroupAgent(self.context,
                                              self.plugin_rpc,
                                              root_helper)

#       added by jiahaojie 00209498  ---begin
        self.vm_port = {}
        self.controlling_vm_base_network()
        self.get_user_port_from_server()
#       added by jiahaojie 00209498  ---end

        self.init_qos()
        self.init_ovs_bus()

        # Initialize iteration counter
        self.iter_num = 0
        self.run_daemon_loop = True
        self.is_distributed_dhcp = cfg.CONF.dhcp_distributed
        LOG.debug('myOVSNeutronAgent:%s', self.is_distributed_dhcp)

    def setup_interface_driver(self):
        if not cfg.CONF.OVS.user_interface_driver:
            msg = _('An interface driver must be specified')
            LOG.error(msg)
            raise SystemExit(1)
        try:
            self.driver = importutils.import_object(
                cfg.CONF.OVS.user_interface_driver)
        except Exception as e:
            msg = (_("Error importing interface driver '%(driver)s': "
                   "%(inner)s") % {'driver': cfg.CONF.OVS.user_interface_driver,
                                   'inner': e})
            LOG.error(msg)
            raise SystemExit(1)

    def get_vm_interface_mac(self):
        dev = cfg.CONF.OVS.vm_interface
        LOG.debug(_('HYBRID: Begin to get vm interface %s.'), dev)
        device = ip_lib.IPDevice(dev,
                                 self.root_helper)
        mac_address = device.link.address
        if(not mac_address):
            LOG.error('HYBRID: VM Interface %s can not get mac_address', dev)
            raise SystemExit(1)
        self.vm_port[mac_address] = VmPort(mac=mac_address)

    def controlling_vm_base_network(self):
        '''Maybe scan all interface and select one device to get vm mac,
        But now only get one interface mac_address from config file'''
        self.get_vm_interface_mac()

    def get_user_port_from_server(self):
        LOG.debug(_('HYBRID: Start call get_user_port_from_server.'
                    'all ports: %s.'), self.vm_port)
        for mac, vport in self.vm_port.items():
            if not vport:
                continue
            if len(vport.ip_address) > 0:
                ip_address = list(vport.ip_address)[0]
            else:
                ip_address = ''
            user_port = {}
            call_time = 0
            while(True):
                call_time = call_time + 1
                try:
                    LOG.debug(_('HYBRID: Call rpc get_user_address, mac:%s,'
                                'ip_address:%s at %s times, host: %s.'), mac,
                              ip_address, str(call_time), cfg.CONF.host)
                    user_port = self.plugin_rpc.get_user_address(self.context,
                                                                 mac,
                                                                 ip_address,
                                                                 cfg.CONF.host)
                except Exception:
                    continue
                if(user_port and not user_port.get('user_port', None)):
                    continue
                else:
                    break
            self.config_user_port(user_port)

    def config_user_port(self, user_port):
        LOG.debug(_('HYBRID: start config user port %s.'), user_port)
        if(user_port and not user_port.get('user_port', None)):
            return
        mac_address = user_port['user_port'].get('mac_address', None)
        ip_addresses = user_port['user_port'].get('ip_addresses', None)
        ip_cidr = user_port['user_port'].get('ip_cidr', None)
        port_id = user_port['user_port'].get('port_id', None)
        vm_port_id = user_port['user_port'].get('vm_port_id', None)
        if(mac_address and ip_addresses and port_id):
            dev = 'user_' + port_id[0:8]
            self.int_br.add_ovs_user_port(dev,
                                          port_id,
                                          mac_address,
                                          vm_port_id)
            self.set_device_mtu(dev)
            self.config_user_port_ip(dev, ip_addresses, ip_cidr)

    def set_device_mtu(self, dev, mtu=None):
        """Set the device MTU."""
        if not mtu:
            mtu = cfg.CONF.OVS.vm_device_mtu
        LOG.debug(_('HYBRID: start config mtu %s for user port %s.'),
                  dev, mtu)
        device = ip_lib.IPDevice(dev,
                                 self.root_helper)
        device.link.set_mtu(mtu)

    def config_user_port_ip(self, dev, ip_addresses, ip_cidr,
                            preserve_ips=[]):
        LOG.debug(_('HYBRID: start config ip %s for user port %s.'),
                  dev, ip_addresses)
        device = ip_lib.IPDevice(dev,
                                 self.root_helper)
        previous = {}
        gw_ip = None
        for address in device.addr.list(scope='global', filters=['permanent']):
            previous[address['cidr']] = address['ip_version']
        for ip_address in ip_addresses:
            ip_addr = ip_address[0]
            cidr = ip_address[1]
            gw_ip = ip_address[2]
            prefixlen = netaddr.IPNetwork(cidr).prefixlen
            ip_cidr = "%s/%s" % (ip_addr, prefixlen)
            net = netaddr.IPNetwork(ip_cidr)
            if net.version == 6:
                ip_cidr = str(net)
            if ip_cidr in previous:
                del previous[ip_cidr]
                continue

            device.addr.add(net.version, ip_cidr, str(net.broadcast))
 
        if gw_ip:
            device.route.add_gateway(gw_ip)

        # clean up any old addresses
        for ip_cidr_one, ip_version in previous.items():
            if ip_cidr_one not in preserve_ips:
                device.addr.delete(ip_version, ip_cidr_one)

    def init_ovs_bus(self):
        try:
            bus_client = neutron_bus_client.NeutronBusClient()
            bus_client.connect()
        except Exception as e:
            LOG.error(_("init_ovs_bus failed, exception by: %s"), e)

    def init_qos(self):
        # QoS agent support
        self.qos_agent = OVSQoSAgent(self.context,
                                     self.plugin_rpc,
                                     self.root_helper)
        if 'OpenflowQoSVlanDriver' in cfg.CONF.qos.qos_driver:
            # TODO(scollins) - Make this configurable, if there is
            # more than one physical bridge added to
            # bridge_mappings
            if self.phys_brs:
                external_bridge = self.phys_brs[self.phys_brs.keys()[0]]
                self.qos_agent.init_qos(ext_bridge=external_bridge,
                                        int_bridge=self.int_br,
                                        local_vlan_map=self.local_vlan_map,
                                        root_helper=self.root_helper
                                        )
            else:
                LOG.exception(_("Unable to activate QoS API."
                                "No bridge_mappings configured!"))
        elif 'MixingQoSVlanDriver' in cfg.CONF.qos.qos_driver:
            #need not depend with bridge_mappings
            self.qos_agent.init_qos(ext_bridge=None,
                                    int_bridge=self.int_br,
                                    local_vlan_map=self.local_vlan_map,
                                    root_helper=self.root_helper
                                    )
        else:
            self.qos_agent.init_qos()

    def _report_state(self):
        # How many devices are likely used by a VM
        self.agent_state.get('configurations')['devices'] = (
            self.int_br_device_count)
        self.agent_state.get('configurations')['in_distributed_mode'] = (
            self.dvr_agent.in_distributed_mode())

        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        self.use_call)
            self.use_call = False
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def setup_rpc(self):
        self.agent_id = 'ovs-agent-%s' % cfg.CONF.host
        self.topic = topics.AGENT
        self.plugin_rpc = OVSPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.TRUNKPORT, topics.UPDATE],
                     [topics.DVR, topics.UPDATE],
                     [topics.QOS, topics.UPDATE]]
        if self.l2_pop:
            consumers.append([topics.L2POPULATION,
                              topics.UPDATE, cfg.CONF.host])
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)

    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in self.local_vlan_map.iteritems():
            if vif_id in vlan_mapping.vif_ports:
                return network_id

    def trunkports_updated(self, context, **kwargs):
        LOG.debug(_("trunkports_updated message processed for ports %s"),
                  kwargs['trunkport_ids'])
        for port in kwargs['trunkport_ids']:
            self.updated_ancillary_ports.add(port)

    def network_delete(self, context, **kwargs):
        LOG.debug(_("network_delete received"))
        network_id = kwargs.get('network_id')
        LOG.debug(_("Delete %s"), network_id)
        # The network may not be defined on this agent
        lvm = self.local_vlan_map.get(network_id)
        if lvm:
            self.reclaim_local_vlan(network_id)
        else:
            LOG.debug(_("Network %s not used on agent."), network_id)

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        # Put the port identifier in the updated_ports set.
        # Even if full port details might be provided to this call,
        # they are not used since there is no guarantee the notifications
        # are processed in the same order as the relevant API requests
        if port.get('trunkport:type', None) == 'trunk':
            self.updated_ancillary_ports.add(port['id'])
        else:
            self.updated_ports.add(port['id'])
        LOG.debug(_("port_update message processed for port %s"), port['id'])
        if qos.QOS in port:
            self.qos_agent.port_qos_updated(self.context, port[qos.QOS], port['id'])

    def tunnel_update(self, context, **kwargs):
        LOG.debug(_("tunnel_update received"))
        if not self.enable_tunneling:
            return
        tunnel_ip = kwargs.get('tunnel_ip')
        tunnel_id = kwargs.get('tunnel_id', self.get_ip_in_hex(tunnel_ip))
        if not tunnel_id:
            return
        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            LOG.error(_("No tunnel_type specified, cannot create tunnels"))
            return
        if tunnel_type not in self.tunnel_types:
            LOG.error(_("tunnel_type %s not supported by agent"), tunnel_type)
            return
        if tunnel_ip == self.local_ip:
            return
        tun_name = '%s-%s' % (tunnel_type, tunnel_id)
        if not self.l2_pop:
            self._setup_tunnel_port(self.tun_br, tun_name, tunnel_ip,
                                    tunnel_type)

    def fdb_add(self, context, fdb_entries):
        LOG.debug("fdb_add received")
        for lvm, agent_ports in self.get_agent_ports(fdb_entries,
                                                     self.local_vlan_map):
            if lvm.network_type not in self.tunnel_types:
                continue

            agent_ports.pop(self.local_ip, None)
            if len(agent_ports):
                if not self.enable_distributed_routing:
                    with self.tun_br.deferred() as deferred_br:
                        self.fdb_add_tun(context, deferred_br, lvm,
                                         agent_ports, self.tun_br_ofports)
                else:
                    self.fdb_add_tun(context, self.tun_br, lvm,
                                     agent_ports, self.tun_br_ofports)

    def fdb_remove(self, context, fdb_entries):
        LOG.debug("fdb_remove received")
        for lvm, agent_ports in self.get_agent_ports(fdb_entries,
                                                     self.local_vlan_map):
            if lvm.network_type not in self.tunnel_types:
                continue

            agent_ports.pop(self.local_ip, None)
            if len(agent_ports):
                if not self.enable_distributed_routing:
                    with self.tun_br.deferred() as deferred_br:
                        self.fdb_remove_tun(context, deferred_br, lvm,
                                            agent_ports, self.tun_br_ofports)
                else:
                    self.fdb_remove_tun(context, self.tun_br, lvm,
                                        agent_ports, self.tun_br_ofports)

    def add_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        if port_info == q_const.FLOODING_ENTRY:
            lvm.tun_ofports.add(ofport)
            ofports = ','.join(lvm.tun_ofports)
            br.mod_flow(table=constants.FLOOD_TO_TUN,
                        dl_vlan=lvm.vlan,
                        actions="strip_vlan,set_tunnel:%s,output:%s" %
                        (lvm.segmentation_id, ofports))
        else:
            self.setup_entry_for_arp_reply(br, 'add', lvm.vlan, port_info[0],
                                           port_info[1])
            br.add_flow(table=constants.UCAST_TO_TUN,
                        priority=2,
                        dl_vlan=lvm.vlan,
                        dl_dst=port_info[0],
                        actions="strip_vlan,set_tunnel:%s,output:%s" %
                        (lvm.segmentation_id, ofport))

    def del_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        if port_info == q_const.FLOODING_ENTRY:
            lvm.tun_ofports.remove(ofport)
            if len(lvm.tun_ofports) > 0:
                ofports = ','.join(lvm.tun_ofports)
                br.mod_flow(table=constants.FLOOD_TO_TUN,
                            dl_vlan=lvm.vlan,
                            actions="strip_vlan,set_tunnel:%s,output:%s" %
                            (lvm.segmentation_id, ofports))
            else:
                # This local vlan doesn't require any more tunnelling
                br.delete_flows(table=constants.FLOOD_TO_TUN, dl_vlan=lvm.vlan)
        else:
            self.setup_entry_for_arp_reply(br, 'remove', lvm.vlan,
                                           port_info[0], port_info[1])
            br.delete_flows(table=constants.UCAST_TO_TUN,
                            dl_vlan=lvm.vlan,
                            dl_dst=port_info[0])

    def _fdb_chg_ip(self, context, fdb_entries):
        LOG.debug("update chg_ip received")
        with self.tun_br.deferred() as deferred_br:
            self.fdb_chg_ip_tun(context, deferred_br, fdb_entries,
                                self.local_ip, self.local_vlan_map)

    def setup_entry_for_arp_reply(self, br, action, local_vid, mac_address,
                                  ip_address):
        '''Set the ARP respond entry.

        When the l2 population mechanism driver and OVS supports to edit ARP
        fields, a table (ARP_RESPONDER) to resolve ARP locally is added to the
        tunnel bridge.
        '''
        if not self.arp_responder_enabled:
            return

        mac = netaddr.EUI(mac_address, dialect=netaddr.mac_unix)
        ip = netaddr.IPAddress(ip_address)

        if action == 'add':
            actions = constants.ARP_RESPONDER_ACTIONS % {'mac': mac, 'ip': ip}
            br.add_flow(table=constants.ARP_RESPONDER,
                        priority=1,
                        proto='arp',
                        dl_vlan=local_vid,
                        nw_dst='%s' % ip,
                        actions=actions)
        elif action == 'remove':
            br.delete_flows(table=constants.ARP_RESPONDER,
                            proto='arp',
                            dl_vlan=local_vid,
                            nw_dst='%s' % ip)
        else:
            LOG.warning(_('Action %s not supported'), action)

    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id, defer=False):
        '''Provisions a local VLAN.

        :param net_uuid: the uuid of the network associated with this vlan.
        :param network_type: the network type ('gre', 'vxlan', 'vlan', 'flat',
                                               'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        '''

        # On a restart or crash of OVS, the network associated with this VLAN
        # will already be assigned, so check for that here before assigning a
        # new one.
        bridges = set()
        lvm = self.local_vlan_map.get(net_uuid)
        if lvm:
            lvid = lvm.vlan
        else:
            if not self.available_local_vlans:
                LOG.error(_("No local VLAN available for net-id=%s"), net_uuid)
                return
            lvid = self.available_local_vlans.pop()
            self.local_vlan_map[net_uuid] = LocalVLANMapping(lvid,
                                                             network_type,
                                                             physical_network,
                                                             segmentation_id)

        LOG.info(_("Assigning %(vlan_id)s as local vlan for "
                   "net-id=%(net_uuid)s"),
                 {'vlan_id': lvid, 'net_uuid': net_uuid})

        if network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                # outbound broadcast/multicast
                ofports = ','.join(self.tun_br_ofports[network_type].values())
                if ofports:
                    self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                         dl_vlan=lvid,
                                         actions="strip_vlan,"
                                         "set_tunnel:%s,output:%s" %
                                         (segmentation_id, ofports))
                # inbound from tunnels: set lvid in the right table
                # and resubmit to Table LEARN_FROM_TUN for mac learning
                if self.enable_distributed_routing:
                    self.dvr_agent.process_tunneled_network(
                        network_type, lvid, segmentation_id)
                else:
                    self.tun_br.add_flow(
                        table=constants.TUN_TABLE[network_type],
                        priority=1,
                        tun_id=segmentation_id,
                        actions="mod_vlan_vid:%s,"
                        "resubmit(,%s)" %
                        (lvid, constants.LEARN_FROM_TUN))

            else:
                LOG.error(_("Cannot provision %(network_type)s network for "
                          "net-id=%(net_uuid)s - tunneling disabled"),
                          {'network_type': network_type,
                           'net_uuid': net_uuid})
        elif network_type == p_const.TYPE_FLAT:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="strip_vlan,normal")
                # inbound
                self.int_br.add_flow(
                    priority=3,
                    in_port=self.int_ofports[physical_network],
                    dl_vlan=0xffff,
                    actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error(_("Cannot provision flat network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_VLAN:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                bridges.add(br)
                if defer:
                    br.defer_apply_on()
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="mod_vlan_vid:%s,normal" % segmentation_id)
                if self.enable_dscp_vlanpcp_mapping:
                    br.add_flow(priority=5,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            dl_vlan_pcp=0,
                            dl_type=0x0800,
                            actions="mod_vlan_vid:%s,"
                            "move:NXM_OF_IP_TOS[5..7]->NXM_OF_VLAN_TCI[13..15],"
                            "normal" % segmentation_id)
                # inbound
                self.int_br.add_flow(priority=3,
                                     in_port=self.
                                     int_ofports[physical_network],
                                     dl_vlan=segmentation_id,
                                     actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error(_("Cannot provision VLAN network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_("Cannot provision unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': network_type,
                       'net_uuid': net_uuid})
        return bridges

    def reclaim_local_vlan(self, net_uuid):
        '''Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        :param lvm: a LocalVLANMapping object that tracks (vlan, lsw_id,
            vif_ids) mapping.
        '''
        lvm = self.local_vlan_map.pop(net_uuid, None)
        if lvm is None:
            LOG.debug(_("Network %s not used on agent."), net_uuid)
            return

        LOG.info(_("Reclaiming vlan = %(vlan_id)s from net-id = %(net_uuid)s"),
                 {'vlan_id': lvm.vlan,
                  'net_uuid': net_uuid})

        if lvm.network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                self.tun_br.delete_flows(
                    table=constants.TUN_TABLE[lvm.network_type],
                    tun_id=lvm.segmentation_id)
                self.tun_br.delete_flows(dl_vlan=lvm.vlan)
                if self.l2_pop:
                    # Try to remove tunnel ports if not used by other networks
                    for ofport in lvm.tun_ofports:
                        self.cleanup_tunnel_port(self.tun_br, ofport,
                                                 lvm.network_type)
        elif lvm.network_type == p_const.TYPE_FLAT:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.delete_flows(in_port=self.phys_ofports[lvm.
                                                          physical_network],
                                dl_vlan=lvm.vlan)
                # inbound
                br = self.int_br
                br.delete_flows(in_port=self.int_ofports[lvm.physical_network],
                                dl_vlan=0xffff)
        elif lvm.network_type == p_const.TYPE_VLAN:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.delete_flows(in_port=self.phys_ofports[lvm.
                                                          physical_network],
                                dl_vlan=lvm.vlan)
                # inbound
                br = self.int_br
                br.delete_flows(in_port=self.int_ofports[lvm.physical_network],
                                dl_vlan=lvm.segmentation_id)
        elif lvm.network_type == p_const.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_("Cannot reclaim unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': lvm.network_type,
                       'net_uuid': net_uuid})

        self.available_local_vlans.add(lvm.vlan)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   ovs_restarted):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.

        :param port: a ovslib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        :param fixed_ips: the ip addresses assigned to this port
        :param device_owner: the string indicative of owner of this port
        :param ovs_restarted: indicates if this is called for an OVS restart.
        '''
        if net_uuid not in self.local_vlan_map or ovs_restarted:
            self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port.vif_id] = port
        
        if uuidutils.is_uuid_like(port.vif_id):
            self.dvr_agent.bind_port_to_dvr(port, network_type, fixed_ips,
                                            device_owner,
                                            local_vlan_id=lvm.vlan)

        self.int_br.set_other_config(port.port_name,
                                     net_uuid,
                                     network_type,
                                     physical_network,
                                     segmentation_id)

        self._bound_dhcp_port(port, network_type, physical_network, device_owner, fixed_ips)

        # Do not bind a port if it's already bound
        cur_tag = self.int_br.db_get_val("Port", port.port_name, "tag")
        if cur_tag != str(lvm.vlan):
            self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                         str(lvm.vlan))
            if port.ofport != -1:
                self.int_br.delete_flows(in_port=port.ofport)

    def port_unbound(self, vif_id, net_uuid=None):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.
        '''
        if net_uuid is None:
            net_uuid = self.get_net_uuid(vif_id)

        if not self.local_vlan_map.get(net_uuid):
            LOG.info(_('port_unbound(): net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return

        lvm = self.local_vlan_map[net_uuid]

        if vif_id in lvm.vif_ports and \
                not self._check_port_multi_device(vif_id):
            vif_port = lvm.vif_ports[vif_id]
            self.dvr_agent.unbind_port_from_dvr(vif_port,
                                                local_vlan_id=lvm.vlan)
            self._unbound_dhcp_port(vif_id)

        lvm.vif_ports.pop(vif_id, None)

        if not lvm.vif_ports:
            self.reclaim_local_vlan(net_uuid)

    def port_dead(self, port):
        '''Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.
        '''
        # Don't kill a port if it's already dead
        cur_tag = self.int_br.db_get_val("Port", port.port_name, "tag")
        if cur_tag != DEAD_VLAN_TAG:
            self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                         DEAD_VLAN_TAG)
            self.int_br.add_flow(priority=2, in_port=port.ofport,
                                 actions="drop")

    def _check_port_multi_device(self, vif_id):
        '''
        Background: Port has multiple devices on bridge for XenServer,
        this feature just for pxe boot XenServer VM.
        Description: Check whether has the same mac of devices on the ovs bridge.
        if exist more then one device has the same mac,
        then return True, otherwise return False.
        '''
        if not cfg.CONF.AGENT.enable_port_multi_device:
            return False

        vif_ports = []
        for network_id, vlan_mapping in self.local_vlan_map.iteritems():
            if vif_id in vlan_mapping.vif_ports:
                lvm = self.local_vlan_map[network_id]
                vif_mac = lvm.vif_ports[vif_id].vif_mac
                vif_ports = [vif_port for vif_port in lvm.vif_ports.values()
                             if vif_port.vif_mac == vif_mac]
                break

        return (len(vif_ports) > 1)

    def setup_integration_br(self):
        '''Setup the integration bridge.

        Create patch ports and remove all existing flows.

        :param bridge_name: the name of the integration bridge.
        :returns: the integration bridge
        '''
        # Ensure the integration bridge is created.
        # ovs_lib.OVSBridge.create() will run
        #   ovs-vsctl -- --may-exist add-br BRIDGE_NAME
        # which does nothing if bridge already exists.
        self.int_br.create()
        self.int_br.set_secure_mode()

        self.int_br.delete_port(cfg.CONF.OVS.int_peer_patch_port)
        self.int_br.remove_all_flows()
        # Add a canary flow to int_br to track OVS restarts
        self.int_br.add_flow(table=constants.CANARY_TABLE, priority=0,
                             actions="drop")

    def setup_ancillary_bridges(self, integ_br, tun_br, reg_ancillary_bridges = []):
        '''Setup ancillary bridges - for example br-ex.'''
        LOG.info(_('Setting up ancillary bridges.'))
        ovs_bridges = set(ovs_lib.get_bridges(self.root_helper))
        # Remove all known bridges
        ovs_bridges.remove(integ_br)
        if self.enable_tunneling:
            ovs_bridges.remove(tun_br)
        br_names = [self.phys_brs[physical_network].br_name for
                    physical_network in self.phys_brs]
        ovs_bridges.difference_update(br_names)

        # collect regged ancillary bridges
        reg_br_names = []
        for reg_bridge in reg_ancillary_bridges:
            reg_br_names.append(reg_bridge.br_name)
        ovs_bridges.difference_update(reg_br_names)

        # Filter list of bridges to those that have external
        # bridge-id's configured
        br_names = []
        for bridge in ovs_bridges:
            id = ovs_lib.get_bridge_external_bridge_id(self.root_helper,
                                                       bridge)
            if id != bridge and bridge[0:3] != 'tbr':
                br_names.append(bridge)
        ovs_bridges.difference_update(br_names)
        ancillary_bridges = set()

        for bridge in ovs_bridges:
            if bridge[0:3] != 'tbr':
                br = ovs_lib.OVSBridge(bridge, self.root_helper)
            else:
                #phys_br = self.phys_brs['default']
                # FIX the hardcoded 'default' above!!!!!
                phys_br = self.int_br
                br = VLANBridge(bridge, phys_br, self.root_helper)
                if not br.get_vif_ports():
                    continue
                br.configure()
                self.local_vlan_bridges.add(br)

            LOG.info(_('Adding %s to list of bridges.'), bridge)

            ancillary_bridges.add(br)

        return ancillary_bridges

    def reset_ancillary_bridges(self):
        '''Reset ancillary bridges
        For now, only need to deal with Vlan bridges
        '''
        skipped_bridges = []
        for bridge in self.ancillary_brs:
            if (bridge.br_name[0:3] == 'tbr' and
                    bridge.bridge_exists(bridge.br_name)):
                bridge.configure()
            else:
                skipped_bridges.append(bridge)
        self.ancillary_brs.difference_update(skipped_bridges)
        self.local_vlan_bridges.difference_update(skipped_bridges)

        self.trunk_subports = {}

    def reset_tunnel_br(self, tun_br_name=None):
        '''(re)initialize the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br_name: the name of the tunnel bridge.
        '''
        if not self.tun_br:
            self.tun_br = ovs_lib.OVSBridge(tun_br_name, self.root_helper)

        self.tun_br.reset_bridge()
        self.patch_tun_ofport = self.int_br.add_patch_port(
            cfg.CONF.OVS.int_peer_patch_port, cfg.CONF.OVS.tun_peer_patch_port)
        self.patch_int_ofport = self.tun_br.add_patch_port(
            cfg.CONF.OVS.tun_peer_patch_port, cfg.CONF.OVS.int_peer_patch_port)
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error(_("Failed to create OVS patch port. Cannot have "
                        "tunneling enabled on this agent, since this version "
                        "of OVS does not support tunnels or patch ports. "
                        "Agent terminated!"))
            exit(1)
        self.tun_br.remove_all_flows()

    def setup_tunnel_br(self):
        '''Setup the tunnel bridge.

        Add all flows to the tunnel bridge.
        '''
        # Table 0 (default) will sort incoming traffic depending on in_port
        self.tun_br.add_flow(priority=1,
                             in_port=self.patch_int_ofport,
                             actions="resubmit(,%s)" %
                             constants.PATCH_LV_TO_TUN)
        self.tun_br.add_flow(priority=0, actions="drop")
        if self.arp_responder_enabled:
            # ARP broadcast-ed request go to the local ARP_RESPONDER table to
            # be locally resolved
            self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
                                 priority=1,
                                 proto='arp',
                                 dl_dst="ff:ff:ff:ff:ff:ff",
                                 actions=("resubmit(,%s)" %
                                          constants.ARP_RESPONDER))
        # PATCH_LV_TO_TUN table will handle packets coming from patch_int
        # unicasts go to table UCAST_TO_TUN where remote addresses are learnt
        self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
                             priority=0,
                             dl_dst="00:00:00:00:00:00/01:00:00:00:00:00",
                             actions="resubmit(,%s)" % constants.UCAST_TO_TUN)
        # Broadcasts/multicasts go to table FLOOD_TO_TUN that handles flooding
        self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
                             priority=0,
                             dl_dst="01:00:00:00:00:00/01:00:00:00:00:00",
                             actions="resubmit(,%s)" % constants.FLOOD_TO_TUN)
        # Tables [tunnel_type]_TUN_TO_LV will set lvid depending on tun_id
        # for each tunnel type, and resubmit to table LEARN_FROM_TUN where
        # remote mac addresses will be learnt
        for tunnel_type in constants.TUNNEL_NETWORK_TYPES:
            self.tun_br.add_flow(table=constants.TUN_TABLE[tunnel_type],
                                 priority=0,
                                 actions="drop")
        # LEARN_FROM_TUN table will have a single flow using a learn action to
        # dynamically set-up flows in UCAST_TO_TUN corresponding to remote mac
        # addresses (assumes that lvid has already been set by a previous flow)
        learned_flow = ("table=%s,"
                        "priority=1,"
                        "hard_timeout=300,"
                        "NXM_OF_VLAN_TCI[0..11],"
                        "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                        "load:0->NXM_OF_VLAN_TCI[],"
                        "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
                        "output:NXM_OF_IN_PORT[]" %
                        constants.UCAST_TO_TUN)
        # Once remote mac addresses are learnt, output packet to patch_int
        self.tun_br.add_flow(table=constants.LEARN_FROM_TUN,
                             priority=1,
                             actions="learn(%s),output:%s" %
                             (learned_flow, self.patch_int_ofport))
        # Egress unicast will be handled in table UCAST_TO_TUN, where remote
        # mac addresses will be learned. For now, just add a default flow that
        # will resubmit unknown unicasts to table FLOOD_TO_TUN to treat them
        # as broadcasts/multicasts
        self.tun_br.add_flow(table=constants.UCAST_TO_TUN,
                             priority=0,
                             actions="resubmit(,%s)" %
                             constants.FLOOD_TO_TUN)
        if self.arp_responder_enabled:
            # If none of the ARP entries correspond to the requested IP, the
            # broadcast-ed packet is resubmitted to the flooding table
            self.tun_br.add_flow(table=constants.ARP_RESPONDER,
                                 priority=0,
                                 actions="resubmit(,%s)" %
                                 constants.FLOOD_TO_TUN)
        # FLOOD_TO_TUN will handle flooding in tunnels based on lvid,
        # for now, add a default drop action
        self.tun_br.add_flow(table=constants.FLOOD_TO_TUN,
                             priority=0,
                             actions="drop")

    def get_peer_name(self, prefix, name):
        """Construct a peer name based on the prefix and name.

        The peer name can not exceed the maximum length allowed for a linux
        device. Longer names are hashed to help ensure uniqueness.
        """
        if len(prefix + name) <= q_const.DEVICE_NAME_MAX_LEN:
            return prefix + name
        # We can't just truncate because bridges may be distinguished
        # by an ident at the end. A hash over the name should be unique.
        # Leave part of the bridge name on for easier identification
        hashlen = 6
        namelen = q_const.DEVICE_NAME_MAX_LEN - len(prefix) - hashlen
        new_name = ('%(prefix)s%(truncated)s%(hash)s' %
                    {'prefix': prefix, 'truncated': name[0:namelen],
                     'hash': hashlib.sha1(name).hexdigest()[0:hashlen]})
        LOG.warning(_("Creating an interface named %(name)s exceeds the "
                      "%(limit)d character limitation. It was shortened to "
                      "%(new_name)s to fit."),
                    {'name': name, 'limit': q_const.DEVICE_NAME_MAX_LEN,
                     'new_name': new_name})
        return new_name

    def setup_physical_bridges(self, bridge_mappings):
        '''Setup the physical network bridges.

        Creates physical network bridges and links them to the
        integration bridge using veths.

        :param bridge_mappings: map physical network names to bridge names.
        '''
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ip_wrapper = ip_lib.IPWrapper(self.root_helper)
        ovs_bridges = ovs_lib.get_bridges(self.root_helper)
        for physical_network, bridge in bridge_mappings.iteritems():
            LOG.info(_("Mapping physical network %(physical_network)s to "
                       "bridge %(bridge)s"),
                     {'physical_network': physical_network,
                      'bridge': bridge})
            # setup physical bridge
            if bridge not in ovs_bridges:
                LOG.error(_("Bridge %(bridge)s for physical network "
                            "%(physical_network)s does not exist. Agent "
                            "terminated!"),
                          {'physical_network': physical_network,
                           'bridge': bridge})
                sys.exit(1)
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            br.remove_all_flows()
            br.add_flow(priority=1, actions="normal")
            self.phys_brs[physical_network] = br

            # interconnect physical and integration bridges using veth/patchs
            int_if_name = self.get_peer_name(constants.PEER_INTEGRATION_PREFIX,
                                             bridge)
            phys_if_name = self.get_peer_name(constants.PEER_PHYSICAL_PREFIX,
                                              bridge)
            self.int_br.delete_port(int_if_name)
            br.delete_port(phys_if_name)
            if self.use_veth_interconnection:
                if ip_lib.device_exists(int_if_name, self.root_helper):
                    ip_lib.IPDevice(int_if_name,
                                    self.root_helper).link.delete()
                    # Give udev a chance to process its rules here, to avoid
                    # race conditions between commands launched by udev rules
                    # and the subsequent call to ip_wrapper.add_veth
                    utils.execute(['/sbin/udevadm', 'settle', '--timeout=10'])
                int_veth, phys_veth = ip_wrapper.add_veth(int_if_name,
                                                          phys_if_name)
                int_ofport = self.int_br.add_port(int_veth)
                phys_ofport = br.add_port(phys_veth)
            else:
                # Create patch ports without associating them in order to block
                # untranslated traffic before association
                int_ofport = self.int_br.add_patch_port(
                    int_if_name, constants.NONEXISTENT_PEER)
                phys_ofport = br.add_patch_port(
                    phys_if_name, constants.NONEXISTENT_PEER)

            self.int_ofports[physical_network] = int_ofport
            self.phys_ofports[physical_network] = phys_ofport

            # block all untranslated traffic between bridges
            self.int_br.add_flow(priority=2, in_port=int_ofport,
                                 actions="drop")
            br.add_flow(priority=2, in_port=phys_ofport, actions="drop")

            if self.use_veth_interconnection:
                # enable veth to pass traffic
                int_veth.link.set_up()
                phys_veth.link.set_up()
                if self.veth_mtu:
                    # set up mtu size for veth interfaces
                    int_veth.link.set_mtu(self.veth_mtu)
                    phys_veth.link.set_mtu(self.veth_mtu)
            else:
                # associate patch ports to pass traffic
                self.int_br.set_db_attribute('Interface', int_if_name,
                                             'options:peer', phys_if_name)
                br.set_db_attribute('Interface', phys_if_name,
                                    'options:peer', int_if_name)

        self.int_br.add_flow(priority=1, actions="normal")

    def scan_ports(self, registered_ports, updated_ports=None):
        cur_ports = self.int_br.get_vif_port_set()
        self.int_br_device_count = len(cur_ports)
        port_info = {'current': cur_ports}
        if updated_ports is None:
            updated_ports = set()
        updated_ports.update(self.check_changed_vlans(registered_ports))
        if updated_ports:
            # Some updated ports might have been removed in the
            # meanwhile, and therefore should not be processed.
            # In this case the updated port won't be found among
            # current ports.
            updated_ports &= cur_ports
            if updated_ports:
                port_info['updated'] = updated_ports

        # FIXME(salv-orlando): It's not really necessary to return early
        # if nothing has changed.
        if cur_ports == registered_ports:
            # No added or removed ports to set, just return here
            return port_info

        port_info['added'] = cur_ports - registered_ports
        # Remove all the known ports not found on the integration bridge
        port_info['removed'] = registered_ports - cur_ports
        return port_info

    def check_changed_vlans(self, registered_ports):
        """Return ports which have lost their vlan tag.

        The returned value is a set of port ids of the ports concerned by a
        vlan tag loss.
        """
        port_tags = self.int_br.get_port_tag_dict()
        changed_ports = set()
        for lvm in self.local_vlan_map.values():
            for port in registered_ports:
                if (
                    port in lvm.vif_ports
                    and lvm.vif_ports[port].port_name in port_tags
                    and port_tags[lvm.vif_ports[port].port_name] != lvm.vlan
                ):
                    LOG.info(
                        _("Port '%(port_name)s' has lost "
                            "its vlan tag '%(vlan_tag)d'!"),
                        {'port_name': lvm.vif_ports[port].port_name,
                         'vlan_tag': lvm.vlan}
                    )
                    changed_ports.add(port)
        return changed_ports

    def update_ancillary_ports(self, registered_ports, updated_ports=None):
        if updated_ports is None:
            updated_ports = []
        ports = set()
        real_updated_ports = set()
        for bridge in self.ancillary_brs:
            if bridge.bridge_exists(bridge.br_name):
                tmp_ports = bridge.get_vif_port_set()
                for tmp_port in tmp_ports:
                    ports.add((tmp_port, bridge))
                    if tmp_port in updated_ports:
                        real_updated_ports.add((tmp_port, bridge))

        added = ports - registered_ports
        removed = registered_ports - ports
        port_info = {'current': ports,
                     'added': added,
                     'removed': removed,
                     'updated': real_updated_ports}

        return port_info

    def treat_vif_port(self, vif_port, port_id, network_id, network_type,
                       physical_network, segmentation_id, admin_state_up,
                       fixed_ips, device_owner, ovs_restarted):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware
        if not vif_port.ofport:
            LOG.warn(_("VIF port: %s has no ofport configured, and might not "
                       "be able to transmit"), vif_port.vif_id)
        if vif_port:
            if admin_state_up:
                self.port_bound(vif_port, network_id, network_type,
                                physical_network, segmentation_id,
                                fixed_ips, device_owner, ovs_restarted)
            else:
                self.port_dead(vif_port)
        else:
            LOG.debug(_("No VIF port for port %s defined on agent."), port_id)


    def _bound_dhcp_port(self, vif_port, network_type, physical_network, device_owner, fixed_ips):
        """distributed dhcp:drop l2 packets to dhcp port mac"""
        if cfg.CONF.dhcp_distributed and device_owner == q_const.DEVICE_OWNER_DHCP:
            dhcp_port = dict()
            dhcp_port['network_type'] = network_type
            dhcp_port['mac_address'] = vif_port.vif_mac
            dhcp_port['fixed_ips'] = fixed_ips
            if network_type == p_const.TYPE_FLAT or network_type == p_const.TYPE_VLAN:
                dhcp_port['physical_network'] = physical_network
                LOG.debug('dhcpbound,vif_id:%s', vif_port.vif_id)
                self.dhcp_ports[vif_port.vif_id] = dhcp_port
                br = self.phys_brs[physical_network]
                self._add_flow_for_br(br, vif_port.vif_mac, fixed_ips)
            elif network_type in constants.TUNNEL_NETWORK_TYPES:
                if self.tun_br:
                    self.dhcp_ports[vif_port.vif_id] = dhcp_port
                    self._add_flow_for_br(self.tun_br, vif_port.vif_mac, fixed_ips)

    def _add_flow_for_br(self, br, mac, fixed_ips):
        br.add_flow(priority = 10,
                    dl_src = mac,
                    actions = 'drop'
                    )
        br.add_flow(priority = 10,
                    dl_dst = mac,
                    actions = 'drop'
                    )

    def _del_flow_for_br(self, br, device, mac, fixed_ips):
        br.delete_flows(table = 0,
                        dl_src = mac
                        )
        br.delete_flows(table = 0,
                        dl_dst = mac
                        )
        del self.dhcp_ports[device]

    def _setup_tunnel_port(self, br, port_name, remote_ip, tunnel_type):
        ofport = br.add_tunnel_port(port_name,
                                    remote_ip,
                                    self.local_ip,
                                    tunnel_type,
                                    self.vxlan_udp_port,
                                    self.dont_fragment)
        ofport_int = -1
        try:
            ofport_int = int(ofport)
        except (TypeError, ValueError):
            LOG.exception(_("ofport should have a value that can be "
                            "interpreted as an integer"))
        if ofport_int < 0:
            LOG.error(_("Failed to set-up %(type)s tunnel port to %(ip)s"),
                      {'type': tunnel_type, 'ip': remote_ip})
            return 0

        self.tun_br_ofports[tunnel_type][remote_ip] = ofport
        # Add flow in default table to resubmit to the right
        # tunnelling table (lvid will be set in the latter)
        br.add_flow(priority=1,
                    in_port=ofport,
                    actions="resubmit(,%s)" %
                    constants.TUN_TABLE[tunnel_type])

        ofports = ','.join(self.tun_br_ofports[tunnel_type].values())
        if ofports and not self.l2_pop:
            # Update flooding flows to include the new tunnel
            for network_id, vlan_mapping in self.local_vlan_map.iteritems():
                if vlan_mapping.network_type == tunnel_type:
                    br.mod_flow(table=constants.FLOOD_TO_TUN,
                                dl_vlan=vlan_mapping.vlan,
                                actions="strip_vlan,set_tunnel:%s,output:%s" %
                                (vlan_mapping.segmentation_id, ofports))
        return ofport

    def setup_tunnel_port(self, br, remote_ip, network_type):
        remote_ip_hex = self.get_ip_in_hex(remote_ip)
        if not remote_ip_hex:
            return 0
        port_name = '%s-%s' % (network_type, remote_ip_hex)
        ofport = self._setup_tunnel_port(br,
                                         port_name,
                                         remote_ip,
                                         network_type)
        return ofport

    def cleanup_tunnel_port(self, br, tun_ofport, tunnel_type):
        # Check if this tunnel port is still used
        for lvm in self.local_vlan_map.values():
            if tun_ofport in lvm.tun_ofports:
                break
        # If not, remove it
        else:
            for remote_ip, ofport in self.tun_br_ofports[tunnel_type].items():
                if ofport == tun_ofport:
                    port_name = '%s-%s' % (tunnel_type,
                                           self.get_ip_in_hex(remote_ip))
                    br.delete_port(port_name)
                    br.delete_flows(in_port=ofport)
                    self.tun_br_ofports[tunnel_type].pop(remote_ip, None)

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        skipped_devices = []
        for device_id in devices:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                                                                            self.context,
                                                                            [device_id],
                                                                            self.agent_id,
                                                                            cfg.CONF.host)
            
            details = devices_details_list[0]
            device = details['device']
            LOG.debug("Processing port: %s", device)
            port = self.int_br.get_vif_port_by_id(device)
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_("Port %s was not found on the integration bridge "
                           "and will therefore not be processed"), device)
                skipped_devices.append(device)
                continue

            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                self.treat_vif_port(port, details['port_id'],
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'],
                                    details['fixed_ips'],
                                    details['device_owner'],
                                    ovs_restarted)
                # update plugin about port status
                # FIXME(salv-orlando): Failures while updating device status
                # must be handled appropriately. Otherwise this might prevent
                # neutron server from sending network-vif-* events to the nova
                # API server, thus possibly preventing instance spawn.
                #set qos when port has qos attribute
                if details['qos_policies']:
                    result = {'port':details}
                    self.qos_agent.qos.port_qos_updated(details['qos_policies'], details['port_id'], **result)

                if details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, cfg.CONF.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, cfg.CONF.host)
                LOG.info(_("Configuration for device %s completed."), device)
            else:
                LOG.warn(_("Device %s not defined on plugin"), device)
                if (port and port.ofport != -1):
                    self.port_dead(port)
        return skipped_devices

    def update_trunk_subports(self, reg_trunk_subports,
                              cur_trunk_subports):
        reg_subports = set(reg_trunk_subports.keys())
        cur_subports = set(cur_trunk_subports.keys())

        added = cur_subports - reg_subports
        removed = reg_subports - cur_subports

        port_info = {}
        if added:
            port_info['added'] = {}
            for port in added:
                port_info['added'][port] = cur_trunk_subports[port]

        if removed:
            port_info['removed'] = {}
            for port in removed:
                port_info['removed'][port] = reg_trunk_subports[port]

        return port_info

    def treat_trunk_port(self, port, details, vlan_bridge, ovs_restarted):
        '''Treat trunk type port.
        If trunk port is newly added, first set port trunk mode, and then
        put its subports info trunk_backlog for later.
        If trunk port is updated, just compute added or removed subports
        '''

        vlan_bridge.init_flow_check()
        vlan_bridge.init_int_br_flow_check()

        current_subports = details['trunk_networks']

        if port.vif_id not in self.trunk_subports:
            net_uuid = details['network_id']
            network_type = details['network_type']
            physical_network = details['physical_network']
            segmentation_id = details['segmentation_id']

            if net_uuid not in self.local_vlan_map or ovs_restarted:
                self.provision_local_vlan(net_uuid, network_type,
                                          physical_network, segmentation_id)
            lvm = self.local_vlan_map[net_uuid]
            lvm.vif_ports[port.vif_id] = port

            vlan_bridge.set_other_config(port.port_name,
                                         net_uuid,
                                         network_type,
                                         physical_network,
                                         segmentation_id)

            vlan_bridge.set_mapping(None, lvm.vlan)

            vlan_bridge.set_db_attribute("Port", port.port_name,
                                         "vlan_mode",
                                         'trunk')

        port_info = self.update_trunk_subports(
                                        self.trunk_subports.get(port.vif_id, {}),
                                        current_subports)

        self.trunk_subports[port.vif_id] = current_subports
        if port_info:
            port_info['port_id'] = port.vif_id
            port_info['br'] = vlan_bridge
            port_info['ovs_restarted'] = ovs_restarted
            self.trunk_backlog.append(port_info)

    def remove_trunk_port(self, port_id, vlan_bridge):
        LOG.debug(_("Remove trunk port %s."), port_id)
        if vlan_bridge in self.local_vlan_bridges:
            vlan_bridge.cleanup_bridge()
            self.local_vlan_bridges.remove(vlan_bridge)

        if self.trunk_subports.has_key(port_id):
            trunk_subports = self.trunk_subports.pop(port_id)
            port_info = self.update_trunk_subports(trunk_subports, {})
            if port_info:
                port_info['port_id'] = port_id
                port_info['br'] = vlan_bridge
                self.trunk_backlog.append(port_info)

    def treat_trunk_subports_added(self, port_id, trunk_subports,
                                   vlan_bridge, ovs_restarted):
        c = 0
        start = time.time()

        while trunk_subports and c != 20 :
            subport_id = trunk_subports.keys()[0]
            ext_net = trunk_subports.pop(subport_id)
            net_uuid = ext_net['net_id']

            if net_uuid not in self.local_vlan_map or ovs_restarted:
                self.provision_local_vlan(net_uuid,
                                          ext_net['network_type'],
                                          ext_net['physical_network'],
                                          ext_net['segmentation_id'], defer=False)
            try:
                lvm = self.local_vlan_map[net_uuid]
                lvm.vif_ports[subport_id] = ovs_lib.VifPort('',-1,
                                                    subport_id,'',vlan_bridge)

                if vlan_bridge.bridge_exists(vlan_bridge.br_name):
                    vlan_bridge.set_mapping(ext_net['vid'], lvm.vlan)
            except Exception:
                LOG.error(_("Treat subport %s failed"), subport_id)
                self.trunk_subports[port_id].pop(subport_id)
                self.updated_ancillary_ports.add(port_id)

            c += 1

        LOG.debug(_("treat_trunk_subports_added - iteration: %(iter_num)d"
                    "- %(num_current)d devices currently available. "
                    "Time elapsed: %(elapsed).3f"),
                  {'iter_num': self.iter_num,
                   'num_current': c,
                   'elapsed': time.time() - start})

    def treat_trunk_subports_removed(self, trunk_subports, vlan_bridge):
        c = 0
        start = time.time()

        while trunk_subports and c != 20 :
            subport_id = trunk_subports.keys()[0]
            ext_net = trunk_subports.pop(subport_id)
            net_uuid = ext_net['net_id']
            #delete flows
            if not self.local_vlan_map.get(net_uuid):
                LOG.error(_('delete subport_flows failed. Net_uuid %s'
                            ' not in local_vlan_map'),
                         net_uuid)
                continue

            lvm = self.local_vlan_map[net_uuid]
            if vlan_bridge.bridge_exists(vlan_bridge.br_name):
                vlan_bridge.remove_flows(ext_net['vid'], lvm.vlan)
            #reclaim local vlan
            self.port_unbound(subport_id, net_uuid)

            c += 1

        LOG.debug(_("treat_trunk_subports_removed - iteration: %(iter_num)d"
                    "- %(num_current)d devices currently available. "
                    "Time elapsed: %(elapsed).3f"),
                  {'iter_num': self.iter_num,
                   'num_current': c,
                   'elapsed': time.time() - start})

    def trunk_work(self):
        port_info = self.trunk_backlog[0]
        vlan_bridge = port_info['br']
        ovs_restarted = port_info.get('ovs_restarted', False)

        if port_info.get('added'):
            self.treat_trunk_subports_added(port_info['port_id'],
                                            port_info['added'],
                                            vlan_bridge, ovs_restarted)

        if port_info.get('removed'):
            self.treat_trunk_subports_removed(port_info['removed'], vlan_bridge)

        if not port_info.get('added') and not port_info.get('removed'):
            self.trunk_backlog.pop(0)

    def treat_ancillary_devices_added(self, devices, ovs_restarted):
        skipped_devices = []
        device_ids = list()
        brs = {}
        for d in devices:
            device_ids.append(d[0])
            brs[d[0]] = d[1]
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                device_ids,
                self.agent_id,
                cfg.CONF.host)

        except Exception as e:
            raise DeviceListRetrievalError(devices=devices, error=e)

        for details in devices_details_list:
            device = details['device']
            LOG.info(_("Ancillary Port %s added"), device)
            port = brs[device].get_vif_port_by_id(device)
            if not port:
                # The port has disappeared and should not be processed
                # There is no need to put the port DOWN in the plugin as
                # it never went up in the first place
                LOG.info(_("Port %s was not found on the integration bridge "
                           "and will therefore not be processed"), device)
                skipped_devices.append((device, brs[device]))
                continue

            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                if details.get('trunk_type') == 'trunk':
                    self.treat_trunk_port(port, details, brs[device],
                                          ovs_restarted)

                # update plugin about port status
                if details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, cfg.CONF.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, cfg.CONF.host)
                LOG.info(_("Configuration for device %s completed."),
                         device)
            else:
                LOG.warn(_("Device %s not defined on plugin"), device)
        return skipped_devices


    def treat_devices_removed(self, devices):
        resync = False
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            try:
                if not self._check_port_multi_device(device):
                    self.plugin_rpc.update_device_down(self.context,
                                                       device,
                                                       self.agent_id,
                                                       cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue
            #Remove qos from ovs if needed.
            self.qos_agent.port_qos_deleted(self.context, 0, device)
            self.port_unbound(device)

        return resync

    def _unbound_dhcp_port(self, device):
        # distributed dhcp:drop l2 packets to dhcp port mac
        if cfg.CONF.dhcp_distributed and self.dhcp_ports.has_key(device):
            LOG.debug('_unbound_dhcp_port_device:%s', device)
            dhcp_port = self.dhcp_ports[device]
            network_type = dhcp_port['network_type']
            mac_address = dhcp_port['mac_address']
            fixed_ips = dhcp_port['fixed_ips']
            if network_type == p_const.TYPE_FLAT or network_type == p_const.TYPE_VLAN:
                physical_network = dhcp_port['physical_network']
                br = self.phys_brs[physical_network]
                self._del_flow_for_br(br, device, mac_address, fixed_ips)
            elif network_type in constants.TUNNEL_NETWORK_TYPES:
                if self.tun_br:
                    self._del_flow_for_br(self.tun_br, device, mac_address, fixed_ips)

    def treat_ancillary_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Attachment %s removed"), device[0])
            self.ancillary_brs.discard(device[1])
            self.remove_trunk_port(device[0], device[1])
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device[0],
                                                             self.agent_id,
                                                             cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          {'device': device[0], 'e': e})
                resync = True
                continue
            if details['exists']:
                LOG.info(_("Port %s updated."), device[0])
                # Nothing to do regarding local networking
            else:
                LOG.debug(_("Device %s not defined on plugin"), device[0])

            self.port_unbound(device[0])

        return resync

    def clear_skipped_ancillary_devices(self, devices):
        for device in devices:
            LOG.info(_("Skipped ancillary device %s removed"), device[0])
            self.ancillary_brs.discard(device[1])
            self.remove_trunk_port(device[0], device[1])

            self.port_unbound(device[0])

    def process_network_ports(self, port_info, ovs_restarted):
        resync_a = False
        resync_b = False
        # TODO(salv-orlando): consider a solution for ensuring notifications
        # are processed exactly in the same order in which they were
        # received. This is tricky because there are two notification
        # sources: the neutron server, and the ovs db monitor process
        # If there is an exception while processing security groups ports
        # will not be wired anyway, and a resync will be triggered
        # TODO(salv-orlando): Optimize avoiding applying filters unnecessarily
        # (eg: when there are no IP address changes)
        self.sg_agent.setup_port_filters(port_info.get('added', set()),
                                         port_info.get('updated', set()))
        # VIF wiring needs to be performed always for 'new' devices.
        # For updated ports, re-wiring is not needed in most cases, but needs
        # to be performed anyway when the admin state of a device is changed.
        # A device might be both in the 'added' and 'updated'
        # list at the same time; avoid processing it twice.
        devices_added_updated = (port_info.get('added', set()) |
                                 port_info.get('updated', set()))
        if devices_added_updated:
            start = time.time()
            try:
                skipped_devices = self.treat_devices_added_or_updated(
                    devices_added_updated, ovs_restarted)
                LOG.debug(_("process_network_ports - iteration:%(iter_num)d -"
                            "treat_devices_added_or_updated completed. "
                            "Skipped %(num_skipped)d devices of "
                            "%(num_current)d devices currently available. "
                            "Time elapsed: %(elapsed).3f"),
                          {'iter_num': self.iter_num,
                           'num_skipped': len(skipped_devices),
                           'num_current': len(port_info['current']),
                           'elapsed': time.time() - start})
                # Update the list of current ports storing only those which
                # have been actually processed.
                port_info['current'] = (port_info['current'] -
                                        set(skipped_devices))
            except DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception(_("process_network_ports - iteration:%d - "
                                "failure while retrieving port details "
                                "from server"), self.iter_num)
                resync_a = True
        if 'removed' in port_info:
            start = time.time()
            resync_b = self.treat_devices_removed(port_info['removed'])
            LOG.debug(_("process_network_ports - iteration:%(iter_num)d -"
                        "treat_devices_removed completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def process_ancillary_network_ports(self, port_info, ovs_restarted):
        resync_a = False
        resync_b = False

        # A device might be both in the 'added' and 'updated'
        # list at the same time; avoid processing it twice.
        devices_added_updated = (port_info.get('added', set()) |
                                 port_info.get('updated', set()))
        if devices_added_updated:
            start = time.time()
            try:
                skipped_devices = self.treat_ancillary_devices_added(
                    devices_added_updated, ovs_restarted)
                LOG.debug(_("process_ancillary_network_ports - iteration: "
                            "%(iter_num)d - treat_ancillary_devices_added completed. "
                            "Skipped %(num_skipped)d devices of "
                            "%(num_current)d devices currently available. "
                            "Time elapsed: %(elapsed).3f"),
                        {'iter_num': self.iter_num,
                         'num_skipped': len(skipped_devices),
                         'num_current': len(port_info['current']),
                         'elapsed': time.time() - start})
                # Update the list of current ports storing only those which
                # have been actually processed.
                port_info['current'] = (port_info['current'] -
                                        set(skipped_devices))
            except DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception(_("process_ancillary_network_ports - "
                                "iteration:%d - failure while retrieving "
                                "port details from server"), self.iter_num)
                resync_a = True

            if skipped_devices:
                self.clear_skipped_ancillary_devices(skipped_devices)

        if 'removed' in port_info:
            start = time.time()
            resync_b = self.treat_ancillary_devices_removed(
                port_info['removed'])
            LOG.debug(_("process_ancillary_network_ports - iteration: "
                        "%(iter_num)d - treat_ancillary_devices_removed "
                        "completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})

        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def get_ip_in_hex(self, ip_address):
        try:
            return '%08x' % netaddr.IPAddress(ip_address, version=4)
        except Exception:
            LOG.warn(_("Unable to create tunnel port. Invalid remote IP: %s"),
                     ip_address)
            return

    def tunnel_sync(self):
        try:
            for tunnel_type in self.tunnel_types:
                details = self.plugin_rpc.tunnel_sync(self.context,
                                                      self.local_ip,
                                                      tunnel_type)
                if not self.l2_pop:
                    tunnels = details['tunnels']
                    for tunnel in tunnels:
                        if self.local_ip != tunnel['ip_address']:
                            tunnel_id = tunnel.get('id')
                            # Unlike the OVS plugin, ML2 doesn't return an id
                            # key. So use ip_address to form port name instead.
                            # Port name must be <=15 chars, so use shorter hex.
                            remote_ip = tunnel['ip_address']
                            remote_ip_hex = self.get_ip_in_hex(remote_ip)
                            if not tunnel_id and not remote_ip_hex:
                                continue
                            tun_name = '%s-%s' % (tunnel_type,
                                                  tunnel_id or remote_ip_hex)
                            self._setup_tunnel_port(self.tun_br,
                                                    tun_name,
                                                    tunnel['ip_address'],
                                                    tunnel_type)
        except Exception as e:
            LOG.debug(_("Unable to sync tunnel IP %(local_ip)s: %(e)s"),
                      {'local_ip': self.local_ip, 'e': e})
            return True
        return False

    def _agent_has_updates(self, polling_manager):
        return (polling_manager.is_polling_required or
                self.updated_ports or
                self.updated_ancillary_ports or
                self.sg_agent.firewall_refresh_needed())

    def _port_info_has_changes(self, port_info):
        return (port_info.get('added') or
                port_info.get('removed') or
                port_info.get('updated'))

    def check_ovs_restart(self):
        # Check for the canary flow
        canary_flow = self.int_br.dump_flows_for_table(constants.CANARY_TABLE)
        return not canary_flow

    def rpc_loop(self, polling_manager=None):
        if not polling_manager:
            polling_manager = polling.AlwaysPoll()

        sync = True
        ports = set()
        updated_ports_copy = set()
        updated_ancillary_ports_copy = set()
        ancillary_ports = set()
        tunnel_sync = True
        ovs_restarted = False
        sleep_time = 0
        while self.run_daemon_loop:
            if self.use_call == True:
                time.sleep(Agent_Start_Report_Retry_Interval)
                continue

            start = time.time()
            port_stats = {'regular': {'added': 0,
                                      'updated': 0,
                                      'removed': 0},
                          'ancillary': {'added': 0,
                                        'removed': 0,
                                        'updated': 0}}
            LOG.debug(_("Agent rpc_loop - iteration:%d started"),
                      self.iter_num)
            if sync:              
                LOG.info(_("Agent out of sync with plugin!"))
                ports.clear()
                ancillary_ports.clear()
                self.ancillary_brs.clear()
                self.local_vlan_bridges.clear()
                self.trunk_subports = {}
                sync = False
                polling_manager.force_polling()
            else:
                sleep_time = 0
            try:
                ovs_restarted = self.check_ovs_restart()
                if ovs_restarted:
                    self.setup_integration_br()
                    self.setup_physical_bridges(self.bridge_mappings)
                    if self.enable_tunneling:
                        self.reset_tunnel_br()
                        self.setup_tunnel_br()
                        tunnel_sync = True
                        if self.enable_distributed_routing:
                            self.dvr_agent.reset_ovs_parameters(self.int_br,
                                                         self.tun_br,
                                                         self.patch_int_ofport,
                                                         self.patch_tun_ofport)
                            self.dvr_agent.reset_dvr_parameters()
                            self.dvr_agent.setup_dvr_flows_on_integ_tun_br()
                    self.reset_ancillary_bridges()
            except Exception:
                LOG.exception(_("Error while reloading ovs-bridges"))
                sync = True
            # Notify the plugin of tunnel IP
            if self.enable_tunneling and tunnel_sync:
                LOG.info(_("Agent tunnel out of sync with plugin!"))
                try:
                    tunnel_sync = self.tunnel_sync()
                except Exception:
                    LOG.exception(_("Error while synchronizing tunnels"))
                    tunnel_sync = True
            if self._agent_has_updates(polling_manager) or ovs_restarted:
                try:
                    LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d - "
                                "starting polling. Elapsed:%(elapsed).3f"),
                              {'iter_num': self.iter_num,
                               'elapsed': time.time() - start})
                    # Save updated ports dict to perform rollback in
                    # case resync would be needed, and then clear
                    # self.updated_ports. As the greenthread should not yield
                    # between these two statements, this will be thread-safe
                    updated_ports_copy = self.updated_ports
                    self.updated_ports = set()
                    reg_ports = (set() if ovs_restarted else ports)
                    port_info = self.scan_ports(reg_ports, updated_ports_copy)
                    LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d - "
                                "port information retrieved. "
                                "Elapsed:%(elapsed).3f"),
                              {'iter_num': self.iter_num,
                               'elapsed': time.time() - start})
                    # Secure and wire/unwire VIFs and update their status
                    # on Neutron server
                    if (self._port_info_has_changes(port_info) or
                        self.sg_agent.firewall_refresh_needed() or
                        ovs_restarted):
                        LOG.debug(_("Starting to process devices in:%s"),
                                  port_info)
                        # If treat devices fails - must resync with plugin
                        sync = self.process_network_ports(port_info,
                                                          ovs_restarted)
                        LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d -"
                                    "ports processed. Elapsed:%(elapsed).3f"),
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})
                        port_stats['regular']['added'] = (
                            len(port_info.get('added', [])))
                        port_stats['regular']['updated'] = (
                            len(port_info.get('updated', [])))
                        port_stats['regular']['removed'] = (
                            len(port_info.get('removed', [])))
                    ports = port_info['current']

                    updated_ancillary_ports_copy = (
                            self.updated_ancillary_ports)
                    self.updated_ancillary_ports = set()
                    reg_ancillary_ports = (set() if ovs_restarted
                                           else ancillary_ports)
                    #scan ancillary bridges
                    self.ancillary_brs.update(self.setup_ancillary_bridges(
                                        self.int_br.br_name,
                                        self.tun_br and self.tun_br.br_name or None,
                                        self.ancillary_brs))

                    # Treat ancillary devices if they exist
                    if self.ancillary_brs:
                        port_info = self.update_ancillary_ports(
                            reg_ancillary_ports, updated_ancillary_ports_copy)
                        LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d -"
                                    "ancillary port info retrieved. "
                                    "Elapsed:%(elapsed).3f"),
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})

                        if port_info:
                            LOG.debug(_("Starting to process ancillary devices in:%s"),
                                  port_info)
                            rc = self.process_ancillary_network_ports(
                                port_info, ovs_restarted)
                            LOG.debug(_("Agent rpc_loop - iteration:"
                                        "%(iter_num)d - ancillary ports "
                                        "processed. Elapsed:%(elapsed).3f"),
                                      {'iter_num': self.iter_num,
                                       'elapsed': time.time() - start})
                            ancillary_ports = port_info['current']
                            port_stats['ancillary']['added'] = (
                                len(port_info.get('added', [])))
                            port_stats['ancillary']['removed'] = (
                                len(port_info.get('removed', [])))
                            port_stats['ancillary']['updated'] = (
                                len(port_info.get('updated', [])))
                            sync = sync | rc

                    polling_manager.polling_completed()
                except messaging.MessagingTimeout:
                    sleep_time += random.random()*cfg.CONF.rpc_response_timeout
                    LOG.exception(_("Agent waiting to sync with plugin, sleep %.3f seconds"), sleep_time)
                    time.sleep(sleep_time)
                    # Put the ports back in self.updated_port
                    self.updated_ports |= updated_ports_copy
                    self.updated_ancillary_ports |= updated_ancillary_ports_copy
                    sync = True                    
                except Exception:
                    LOG.exception(_("Error while processing VIF ports"))
                    # Put the ports back in self.updated_port
                    self.updated_ports |= updated_ports_copy
                    self.updated_ancillary_ports |= updated_ancillary_ports_copy
                    sync = True

            try:
                if self.trunk_backlog:
                    LOG.debug(_("Trunk backlog: %s"), self.trunk_backlog)
                    self.trunk_work()
            except Exception:
                LOG.exception(_("Error while processing backlog ports"))
                self.trunk_subports = {}
                sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d "
                        "completed. Processed ports statistics: "
                        "%(port_stats)s. Elapsed:%(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'port_stats': port_stats,
                       'elapsed': elapsed})
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})
            self.iter_num = self.iter_num + 1

    def daemon_loop(self):
        with polling.get_polling_manager(
            self.minimize_polling,
            self.root_helper,
            self.ovsdb_monitor_respawn_interval) as pm:

            self.rpc_loop(polling_manager=pm)

    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False


def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = q_utils.parse_mappings(config.OVS.bridge_mappings)
    except ValueError as e:
        raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

    kwargs = dict(
        integ_br=config.OVS.integration_bridge,
        tun_br=config.OVS.tunnel_bridge,
        local_ip=config.OVS.local_ip,
        bridge_mappings=bridge_mappings,
        root_helper=config.AGENT.root_helper,
        polling_interval=config.AGENT.polling_interval,
        minimize_polling=config.AGENT.minimize_polling,
        tunnel_types=config.AGENT.tunnel_types,
        veth_mtu=config.AGENT.veth_mtu,
        enable_distributed_routing=config.AGENT.enable_distributed_routing,
        l2_population=config.AGENT.l2_population,
        arp_responder=config.AGENT.arp_responder,
        use_veth_interconnection=config.OVS.use_veth_interconnection,
        enable_dscp_vlanpcp_mapping=config.qos.enable_dscp_vlanpcp_mapping,
    )

    # If enable_tunneling is TRUE, set tunnel_type to default to GRE
    if config.OVS.enable_tunneling and not kwargs['tunnel_types']:
        kwargs['tunnel_types'] = [p_const.TYPE_GRE]

    # Verify the tunnel_types specified are valid
    for tun in kwargs['tunnel_types']:
        if tun not in constants.TUNNEL_NETWORK_TYPES:
            msg = _('Invalid tunnel type specified: %s'), tun
            raise ValueError(msg)
        if not kwargs['local_ip']:
            msg = _('Tunneling cannot be enabled without a valid local_ip.')
            raise ValueError(msg)

    return kwargs


def main():
    cfg.CONF.register_opts(ip_lib.OPTS)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    q_utils.log_opt_values(LOG)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_('%s Agent terminated!'), e)
        sys.exit(1)

    is_xen_compute_host = 'rootwrap-xen-dom0' in agent_config['root_helper']
    if is_xen_compute_host:
        # Force ip_lib to always use the root helper to ensure that ip
        # commands target xen dom0 rather than domU.
        cfg.CONF.set_default('ip_lib_force_root', True)

    agent = OVSNeutronAgent(**agent_config)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_("Agent initialized successfully, now running... "))
    agent.daemon_loop()


if __name__ == "__main__":
    main()
