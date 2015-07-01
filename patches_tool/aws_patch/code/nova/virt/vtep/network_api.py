# Copyright 2012 OpenStack Foundation
# All Rights Reserved
# Copyright (c) 2012 NEC Corporation
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
#

import time
import uuid
from oslo.config import cfg

from nova import conductor
from nova import exception
from nova import objects
from nova.api.openstack import extensions
from nova.compute import flavors
from nova.compute import utils as compute_utils
from nova.network import model as network_model
from nova.network import base_api
from nova.network import neutronv2
from nova.network.neutronv2 import api
from nova.network.neutronv2 import constants
from nova.network.security_group import openstack_driver
from nova.i18n import _, _LE, _LW
from nova.openstack.common import excutils
from nova.openstack.common import lockutils
from nova.openstack.common import log as logging
from nova.openstack.common import uuidutils
from nova.pci import pci_manager
from nova.pci import pci_request
from nova.pci import pci_whitelist
from neutronclient.common import exceptions as neutron_client_exc

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

class API(api.API):

    """Extension API for interacting with the neutron 2.x API."""

    def __init__(self):
        super(API, self).__init__()

    def allocate_port_for_instance(self, context, instance, provider_port):
        neutron = neutronv2.get_client(context)
        LOG.debug('allocate_port_for_instance()', instance=instance)
        if not instance.project_id:
            msg = _('empty project id for instance %s')
            raise exception.InvalidInput(
                reason=msg % instance.uuid)

        nets = self._get_available_networks(context, instance.project_id,
                                            [provider_port.network_id, ])
        if not nets:
            LOG.warn(_LW("No network configured!"), instance=instance)
            return network_model.NetworkInfo([])

        if (not provider_port
                or provider_port.is_single_unspecified):
            # if no network is requested and more
            # than one is available then raise NetworkAmbiguous Exception
            if len(nets) > 1:
                msg = _("Multiple possible networks found, use a Network "
                        "ID to be more specific.")
                raise exception.NetworkAmbiguous(msg)

        zone = 'compute:%s' % instance.availability_zone
        port_req_body = {'port': {'device_id': instance.uuid,
                                  'device_owner': zone}}
        port_client = (neutron if not
                       self._has_port_binding_extension(context) else
                       neutronv2.get_client(context, admin=True))

        self._check_external_network_attach(context, nets)
        created_port = self._create_port(port_client, instance,
                                         provider_port.network_id,
                                         provider_port.port_name,
                                         port_req_body,
                                         provider_port.port_mac)
        nw_info = network_model.NetworkInfo()
        if created_port:
            vif_active = False
            if (created_port['admin_state_up'] is False
                    or created_port['status'] == 'ACTIVE'):
                vif_active = True

            client = neutronv2.get_client(context, admin=True)
            network_IPs = self._nw_info_get_ips(client, created_port)
            subnets = self._nw_info_get_subnets(context, created_port,
                                                network_IPs)

            devname = "tap" + created_port['id']
            devname = devname[:network_model.NIC_NAME_LEN]

            network, ovs_interfaceid = (
                self._nw_info_build_network(created_port,
                                            nets, subnets))

            nw_info.append(network_model.VIF(
                id=created_port['id'],
                address=created_port['mac_address'],
                network=network,
                vnic_type=created_port.get('binding:vnic_type',
                                           network_model.VNIC_TYPE_NORMAL),
                type=created_port.get('binding:vif_type'),
                profile=created_port.get('binding:profile'),
                details=created_port.get('binding:vif_details'),
                ovs_interfaceid=ovs_interfaceid,
                devname=devname,
                active=vif_active))

        return nw_info

    def _create_port(self, port_client, instance, network_id, port_name,
                     port_req_body, mac_address=None):
        """Attempts to create a port for the instance on the given network.

        :param port_client: The client to use to create the port.
        :param instance: Create the port for the given instance.
        :param network_id: Create the port on the given network.
        :param port_req_body: Pre-populated port request. Should have the
            device_id, device_owner, and any required neutron extension values.
        :returns: the created port.
        :raises PortLimitExceeded: If neutron fails with an OverQuota error.
        :raises NoMoreFixedIps: If neutron fails with
            IpAddressGenerationFailure error.
        """
        try:
            port_req_body['port']['network_id'] = network_id
            port_req_body['port']['admin_state_up'] = True
            port_req_body['port']['tenant_id'] = instance['project_id']
            if port_name:
                port_req_body['port']['name'] = port_name
            if mac_address:
                port_req_body['port']['mac_address'] = mac_address
            port_info = port_client.create_port(port_req_body)['port']
            LOG.debug('Successfully created port: %s', port_info['id'],
                      instance=instance)
            return port_info
        except neutron_client_exc.OverQuotaClient:
            LOG.warning(_LW(
                'Neutron error: Port quota exceeded in tenant: %s'),
                port_req_body['port']['tenant_id'], instance=instance)
            raise exception.PortLimitExceeded()
        except neutron_client_exc.IpAddressGenerationFailureClient:
            LOG.warning(_LW('Neutron error: No more fixed IPs in network: %s'),
                        network_id, instance=instance)
            raise exception.NoMoreFixedIps()
        except neutron_client_exc.MacAddressInUseClient:
            LOG.warning(_LW('Neutron error: MAC address %(mac)s is already '
                            'in use on network %(network)s.') %
                        {'mac': mac_address, 'network': network_id},
                        instance=instance)
            raise exception.PortInUse(port_id=mac_address)
        except neutron_client_exc.NeutronClientException:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE('Neutron error creating port on network %s'),
                              network_id, instance=instance)
