# Copyright (c) 2013 OpenStack Foundation
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

from sqlalchemy.orm import exc

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.handlers import dvr_rpc
from neutron.common import constants as q_const
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron.db import api as db_api
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import log
from neutron.plugins.common import constants as service_constants
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import type_tunnel
from neutron.services.qos.agents import qos_rpc
from neutron.db import qos_rpc_base as qos_db_rpc
from neutron.db import qos_db
# REVISIT(kmestery): Allow the type and mechanism drivers to supply the
# mixins and eventually remove the direct dependencies on type_tunnel.

LOG = log.getLogger(__name__)


class RpcCallbacks(n_rpc.RpcCallback,
                   type_tunnel.TunnelRpcCallbackMixin,
                   qos_db_rpc.QoSServerRpcCallbackMixin):

    RPC_API_VERSION = '1.3'
    # history
    #   1.0 Initial version (from openvswitch/linuxbridge)
    #   1.1 Support Security Group RPC
    #   1.2 Support get_devices_details_list
    #   1.3 get_device_details rpc signature upgrade to obtain 'host' and
    #       return value to include fixed_ips and device_owner for
    #       the device port

    def __init__(self, notifier, type_manager):
        self.setup_tunnel_callback_mixin(notifier, type_manager)
        super(RpcCallbacks, self).__init__()

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        host = kwargs.get('host')
        LOG.debug("Device %(device)s details requested by agent "
                  "%(agent_id)s with host %(host)s",
                  {'device': device, 'agent_id': agent_id, 'host': host})

        plugin = manager.NeutronManager.get_plugin()
        port_id = plugin._device_to_port_id(device)
        port_context = plugin.get_bound_port_context(rpc_context,
                                                     port_id,
                                                     host)
        if not port_context:
            LOG.warning(_("Device %(device)s requested by agent "
                          "%(agent_id)s not found in database"),
                        {'device': device, 'agent_id': agent_id})
            return {'device': device}

        segment = port_context.bound_segment
        port = port_context.current

        if not segment:
            LOG.warning(_("Device %(device)s requested by agent "
                          "%(agent_id)s on network %(network_id)s not "
                          "bound, vif_type: %(vif_type)s"),
                        {'device': device,
                         'agent_id': agent_id,
                         'network_id': port['network_id'],
                         'vif_type': port[portbindings.VIF_TYPE]})
            return {'device': device}

        if 'trunkport:type' in port:
            trunk_type = port['trunkport:type']
        else:
            trunk_type = ""

        remote_nets = db.get_vlan_mappings(rpc_context, port)

        new_status = (q_const.PORT_STATUS_BUILD if port['admin_state_up']
                      else q_const.PORT_STATUS_DOWN)
        
        if port['status'] != new_status:
            plugin.update_port_status(rpc_context,
                                      port_id,
                                      new_status,
                                      host)
        #query qos policies, add to entry for qos-service
        session = db_api.get_session()
        policies = qos_db.get_policies_by_port(session, port_id)

        entry = {'device': device,
                 'network_id': port['network_id'],
                 'port_id': port_id,
                 'mac_address': port['mac_address'],
                 'admin_state_up': port['admin_state_up'],
                 'network_type': segment[api.NETWORK_TYPE],
                 'segmentation_id': segment[api.SEGMENTATION_ID],
                 'physical_network': segment[api.PHYSICAL_NETWORK],
                 'trunk_networks': remote_nets,
                 'trunk_type': trunk_type,
                 'fixed_ips': port['fixed_ips'],
                 'qos_policies': policies,
                 'device_owner': port['device_owner'],
                 'profile': port[portbindings.PROFILE]}
        LOG.debug(_("Returning: %s"), entry)
        return entry

    def get_devices_details_list(self, rpc_context, **kwargs):
        return [
            self.get_device_details(
                rpc_context,
                device=device,
                **kwargs
            )
            for device in kwargs.pop('devices', [])
        ]

    def get_port_detail(self, rpc_context, **kwargs):
        port_id = kwargs.get('port_id')
        agent_id = kwargs.get('agent_id')
        LOG.debug("Port %(port)s details requested by agent "
                  "%(agent_id)s",
                  {'port': port_id, 'agent_id': agent_id})

        plugin = manager.NeutronManager.get_plugin()
        port_info = plugin.get_port(rpc_context, port_id)
        return port_info

    def update_port(self, rpc_context, **kwargs):
        port_id = kwargs.get('port_id')
        agent_id = kwargs.get('agent_id')
        port = kwargs.get('port')
        LOG.debug("Update port %(port)s requested by agent "
                  "%(agent_id)s",
                  {'port': port_id, 'agent_id': agent_id})

        plugin = manager.NeutronManager.get_plugin()
        port_info = plugin.update_port(rpc_context, port_id, port)
        return port_info

    def get_ports(self, rpc_context, **kwargs):
        agent_id = kwargs.get('agent_id')
        host = kwargs.get('host')
        mac_address = kwargs.get('mac_address')
        device_owner = kwargs.get('device_owner')
        LOG.debug("Ports requested by agent "
                  "%(agent_id)s",
                  {'agent_id': agent_id})
        filters = {}
        if host != None:
            filters['binding:host_id'] = [host]
        if mac_address != None:
            filters['mac_address'] = [mac_address]
        if device_owner != None:
            filters['device_owner'] = [device_owner]
        plugin = manager.NeutronManager.get_plugin()
        ports_info = plugin.get_ports(rpc_context, filters=filters)
        return ports_info

    def get_networks(self, rpc_context, **kwargs):
        agent_id = kwargs.get('agent_id')
        network_id = kwargs.get('network_id')
        LOG.debug("Networks %(network_id)s requested by agent "
                  "%(agent_id)s",
                  {'network_id': network_id, 'agent_id': agent_id})
        filters = {}
        filters['id'] = [network_id]
        plugin = manager.NeutronManager.get_plugin()
        networks_info = plugin.get_networks(rpc_context, filters=filters)
        return networks_info

    def port_bound_to_router(self, rpc_context, **kwargs):
        agent_id = kwargs.get('agent_id')
        host = kwargs.get('host')
        port_id = kwargs.get('port_id')
        LOG.debug("Port %(port_id)s bound to router of host %(host)s requested by agent "
                  "%(agent_id)s",
                  {'port_id':port_id, 'host': host, 'agent_id': agent_id})
        plugin = manager.NeutronManager.get_plugin()
        port_bound = plugin.port_bound_to_router(rpc_context, port_id, host)
        return port_bound

    def port_bound_to_host(self, rpc_context, **kwargs):
        agent_id = kwargs.get('agent_id')
        host = kwargs.get('host')
        port_id = kwargs.get('port_id')
        LOG.debug("Port %(port_id)s bound to host %(host)s requested by agent "
                  "%(agent_id)s",
                  {'port_id':port_id, 'host': host, 'agent_id': agent_id})
        plugin = manager.NeutronManager.get_plugin()
        port_bound = plugin.port_bound_to_host(rpc_context, port_id, host)
        return port_bound

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent."""
        # TODO(garyk) - live migration and port status
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        host = kwargs.get('host')
        LOG.debug(_("Device %(device)s no longer exists at agent "
                    "%(agent_id)s"),
                  {'device': device, 'agent_id': agent_id})
        plugin = manager.NeutronManager.get_plugin()
        port_id = plugin._device_to_port_id(device)
        port_exists = True
        if (host and not plugin.port_bound_to_host(rpc_context,
                                                   port_id, host)):
            LOG.debug(_("Device %(device)s not bound to the"
                        " agent host %(host)s"),
                      {'device': device, 'host': host})
            return {'device': device,
                    'exists': port_exists}

        try:
            port_exists = bool(plugin.update_port_status(
                rpc_context, port_id, q_const.PORT_STATUS_DOWN, host))
        except exc.StaleDataError:
            port_exists = False
            LOG.debug("delete_port and update_device_down are being executed "
                      "concurrently. Ignoring StaleDataError.")

        return {'device': device,
                'exists': port_exists}

    def update_device_up(self, rpc_context, **kwargs):
        """Device is up on agent."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        host = kwargs.get('host')
        LOG.debug(_("Device %(device)s up at agent %(agent_id)s"),
                  {'device': device, 'agent_id': agent_id})
        plugin = manager.NeutronManager.get_plugin()
        port_id = plugin._device_to_port_id(device)
        if (host and not plugin.port_bound_to_host(rpc_context,
                                                   port_id, host)):
            LOG.debug(_("Device %(device)s not bound to the"
                        " agent host %(host)s"),
                      {'device': device, 'host': host})
            return

        port_id = plugin.update_port_status(rpc_context, port_id,
                                            q_const.PORT_STATUS_ACTIVE,
                                            host)
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if (l3plugin and
            utils.is_extension_supported(l3plugin,
                                         q_const.L3_DISTRIBUTED_EXT_ALIAS)):
            try:
                l3plugin.dvr_vmarp_table_update(rpc_context, port_id, "add")
            except exceptions.PortNotFound:
                LOG.debug('Port %s not found during ARP update', port_id)

    def get_subnet_dhcp_by_network_id(self, rpc_context, **kwargs):
        network_id = kwargs.get('network_id')
        plugin = manager.NeutronManager.get_plugin()
        subnets = plugin.get_subnets_by_network(rpc_context, network_id)
        filter = {'device_owner': ['network:dhcp'],
                  'network_id': [network_id]}
        dhcp_ports = plugin.get_ports(rpc_context, filter)
        return {'subnets': subnets,
                'dhcp_ports': dhcp_ports}
    def get_user_port_id_from_vm_port(self, vm_port):
        name = vm_port['name']
        n_list = name.split('@')
        if(len(n_list) > 1 and u'vm_port' == n_list[0] and len(n_list[1]) > 1):
            return n_list[1]
        else:
            return u''

    def get_cidr_and_gwip_by_subnet_id(self, context, subnet_id):
        plugin = manager.NeutronManager.get_plugin()
        subnet = plugin.get_subnet(context, subnet_id)
        if not subnet:
            LOG.debug(_('HYBRID: Subnet not found, subnet_id: %s.'
                        ), subnet_id)
            return ''
        return [subnet['cidr'], subnet['gateway_ip']]

    def get_ip_addresses_from_fixed_ips(self, context, fixed_ips):
        if(len(fixed_ips) <= 0):
            return None
        ip_list = []
        for fixed_ip in fixed_ips:
            ip_address = fixed_ip.get('ip_address')
            subnet_id = fixed_ip.get('subnet_id')
            ip_cidr_gwip = self.get_cidr_and_gwip_by_subnet_id(context,
                                                               subnet_id)
            ip_list.append([ip_address, ip_cidr_gwip[0], ip_cidr_gwip[1]])
        return ip_list
#         if(len(fixed_ips) > 0):
#             return fixed_ips[0].get('ip_address', '')

    def get_user_address(self, rpc_context, **kwargs):
        mac = kwargs.get('mac_address')
        ip = kwargs.get('ip_address')
        host = kwargs.get('host')
        LOG.debug("HYBRID: Agent requests user address of VM on host: %s, "
                  "ip_address: %s, mac_address: %s", host, ip, mac)
        plugin = manager.NeutronManager.get_plugin()
        vm_port_id = plugin._device_to_port_id(mac)
#         vm_port = plugin.get_port_from_device([vm_port_id])
        vm_port = plugin.get_port(rpc_context, vm_port_id)
        if not vm_port:
            LOG.debug(_('HYBRID: VM port not found, host: %s, ip_address: %s,'
                        'mac_address: %s.'), host, ip, mac)
            return {'user_port': {}}
        user_port_id = self.get_user_port_id_from_vm_port(vm_port)
        user_port = plugin.get_port(rpc_context, user_port_id)
#         user_port = plugin.get_port_from_device(user_port_id)
        if not user_port:
            LOG.debug(_('HYBRID: User port not found, host: %s, ip_address: '
                        '%s, mac_address: %s.'), host, ip, mac)
            return {'user_port': {}}
        ip_addresses = self.get_ip_addresses_from_fixed_ips(
                                        rpc_context, user_port['fixed_ips'])
        user_port['binding:host_id'] = host
        port = {'port': user_port}
        plugin.update_port(rpc_context, user_port_id, port)
        ret_msg = {'user_port': {
                   'mac_address': user_port['mac_address'],
                   'ip_addresses': ip_addresses,
                   'port_id': user_port['id'],
                   'vm_port_id': vm_port_id}}
        LOG.debug(_('HYBRID: Get user port, return msg %s.'), ret_msg)
        return ret_msg


class AgentNotifierApi(n_rpc.RpcProxy,
                       dvr_rpc.DVRAgentRpcApiMixin,
                       sg_rpc.SecurityGroupAgentRpcApiMixin,
                       type_tunnel.TunnelAgentRpcApiMixin,
                       qos_rpc.QoSAgentRpcApiMixin):
    """Agent side of the openvswitch rpc API.

    API version history:
        1.0 - Initial version.
        1.1 - Added get_active_networks_info, create_dhcp_port,
              update_dhcp_port, and removed get_dhcp_port methods.

    """

    BASE_RPC_API_VERSION = '1.1'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)

    def network_delete(self, context, network_id):
        self.fanout_cast(context,
                         self.make_msg('network_delete',
                                       network_id=network_id),
                         topic=self.topic_network_delete)

    def port_update(self, context, port, network_type=None, segmentation_id=None,
                    physical_network=None, host=None):
        if not host:
            self.fanout_cast(context,
                             self.make_msg('port_update',
                                           port=port,
                                           network_type=network_type,
                                           segmentation_id=segmentation_id,
                                           physical_network=physical_network),
                             topic=self.topic_port_update)
        else:
            self.cast(context,
                      self.make_msg('port_update',
                                    port=port,
                                    network_type=network_type,
                                    segmentation_id=segmentation_id,
                                    physical_network=physical_network),
                      topic='%s.%s' % (self.topic_port_update, host))