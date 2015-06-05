# Copyright 2012 Red Hat, Inc.
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

from oslo.config import cfg

from neutron.agent.common import config
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.common import constants


DEFAULT_BRIDGE_MAPPINGS = []
DEFAULT_VLAN_RANGES = []
DEFAULT_TUNNEL_RANGES = []
DEFAULT_TUNNEL_TYPES = []

ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use.")),
    cfg.BoolOpt('enable_tunneling', default=False,
                help=_("Enable tunneling support.")),
    cfg.StrOpt('tunnel_bridge', default='br-tun',
               help=_("Tunnel bridge to use.")),
    cfg.StrOpt('int_peer_patch_port', default='patch-tun',
               help=_("Peer patch port in integration bridge for tunnel "
                      "bridge.")),
    cfg.StrOpt('tun_peer_patch_port', default='patch-int',
               help=_("Peer patch port in tunnel bridge for integration "
                      "bridge.")),
    cfg.StrOpt('local_ip', default='',
               help=_("Local IP address of GRE tunnel endpoints.")),
    cfg.ListOpt('bridge_mappings',
                default=DEFAULT_BRIDGE_MAPPINGS,
                help=_("List of <physical_network>:<bridge>. "
                       "Deprecated for ofagent.")),
    cfg.StrOpt('tenant_network_type', default='local',
               help=_("Network type for tenant networks "
                      "(local, vlan, gre, vxlan, or none).")),
    cfg.ListOpt('network_vlan_ranges',
                default=DEFAULT_VLAN_RANGES,
                help=_("List of <physical_network>:<vlan_min>:<vlan_max> "
                       "or <physical_network>.")),
    cfg.ListOpt('tunnel_id_ranges',
                default=DEFAULT_TUNNEL_RANGES,
                help=_("List of <tun_min>:<tun_max>.")),
    cfg.StrOpt('tunnel_type', default='',
               help=_("The type of tunnels to use when utilizing tunnels, "
                      "either 'gre' or 'vxlan'.")),
    cfg.BoolOpt('use_veth_interconnection', default=False,
                help=_("Use veths instead of patch ports to interconnect the "
                       "integration bridge to physical bridges.")),

    #added by jiahaojie 00209498
    cfg.StrOpt('user_interface_driver',
               default='neutron.agent.linux.interface.OVSInterfaceDriver',
               help='Driver used to create user devices.'),
    cfg.StrOpt('vm_interface',
               default='eth0',
               help='Visual Machine Device used to get user port.'),
    cfg.IntOpt('vm_device_mtu', default=1350,
               help=_('MTU setting for device.')),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.BoolOpt('minimize_polling',
                default=True,
                help=_("Minimize polling by monitoring ovsdb for interface "
                       "changes.")),
    cfg.IntOpt('ovsdb_monitor_respawn_interval',
               default=constants.DEFAULT_OVSDBMON_RESPAWN,
               help=_("The number of seconds to wait before respawning the "
                      "ovsdb monitor after losing communication with it.")),
    cfg.ListOpt('tunnel_types', default=DEFAULT_TUNNEL_TYPES,
                help=_("Network types supported by the agent "
                       "(gre and/or vxlan).")),
    cfg.IntOpt('vxlan_udp_port', default=p_const.VXLAN_UDP_PORT,
               help=_("The UDP port to use for VXLAN tunnels.")),
    cfg.IntOpt('veth_mtu',
               help=_("MTU size of veth interfaces")),
    cfg.BoolOpt('l2_population', default=False,
                help=_("Use ML2 l2population mechanism driver to learn "
                       "remote MAC and IPs and improve tunnel scalability.")),
    cfg.BoolOpt('arp_responder', default=False,
                help=_("Enable local ARP responder if it is supported. "
                       "Requires OVS 2.1 and ML2 l2population driver. "
                       "Allows the switch (when supporting an overlay) "
                       "to respond to an ARP request locally without "
                       "performing a costly ARP broadcast into the overlay.")),
    cfg.BoolOpt('dont_fragment', default=True,
                help=_("Set or un-set the don't fragment (DF) bit on "
                       "outgoing IP packet carrying GRE/VXLAN tunnel.")),
    cfg.BoolOpt('enable_distributed_routing', default=False,
                help=_("Make the l2 agent run in DVR mode.")),
    cfg.ListOpt('l2pop_network_types', default=['flat', 'vlan', 'vxlan'],
                help=_("L2pop network types supported by the agent.")),
    cfg.BoolOpt('enable_port_multi_device', default=False,
                help=_("Port has multiple devices on bridge for XenServer.")),
]

qos_opts = [
    cfg.BoolOpt('enable_dscp_vlanpcp_mapping', default=False,
                help=_("Enable dscp map vlan pcp")),
]


cfg.CONF.register_opts(ovs_opts, "OVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
cfg.CONF.register_opts(qos_opts, "qos")
config.register_agent_state_opts_helper(cfg.CONF)
config.register_root_helper(cfg.CONF)
