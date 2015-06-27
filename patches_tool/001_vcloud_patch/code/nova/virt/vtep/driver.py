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
Nova compute driver support fo vtep in vm through openvswitch
"""

from oslo.config import cfg

from nova import exception
from nova import network
from nova.i18n import _, _LI, _LW
from nova import exception
from nova.network import model as network_model
from nova.network import neutronv2
from nova.openstack.common import log as logging
from nova.virt import virtapi
from nova.virt import driver
from nova.virt.vtep import network_api


vtep_opts = [
    cfg.StrOpt('provider_api_network_id',
               help='The neutron net id which provider api network use.'),

    cfg.StrOpt('provider_api_network_name',
               help='The provider network name which api provider network use.'),

    cfg.StrOpt('provider_tunnel_network_id',
               help='The neutron net which provider tunnel network use.'),

    cfg.StrOpt('provider_tunnel_network_name',
               help='The provider network name which tunnel provider network use.'),
]

CONF = cfg.CONF
CONF.register_opts(vtep_opts, 'vtepdriver')
LOG = logging.getLogger(__name__)


class ProviderPort(object):
    # TODO(nkapotoxin): Use network name instead after

    def __init__(self, network_id, port_mac=None, port_name=None,
                 is_single_unspecified=False):
        super(ProviderPort, self).__init__()
        self.network_id = network_id
        self.port_name = port_name
        self.port_mac = port_mac
        self.is_single_unspecified = is_single_unspecified


class VtepDriver(driver.ComputeDriver):

    """ Base driver for vtepdriver, this implements mock
    vif interfaces
    """

    def __init__(self, virtapi):
        # NOTE(nkapotoxin): Vtep driver must use this to create provider port
        self.network_api = network_api.API()

        super(VtepDriver, self).__init__(virtapi)

    def _get_tunnel_network_name(self, network_info):
        """Get tunnel network_name
        this name is connect 'vm_port@' and vif['id'], this info can help
        vtep vm to find user port
        """
        provider_network_name = 'vm_port'
        if network_info is None or len(network_info) == 0:
            provider_network_name = '%s@%s' \
                % (provider_network_name, 'fakeprovider')
        else:
            for vif in network_info:
                provider_network_name = '%s@%s' \
                    % (provider_network_name, vif['id'])

        return provider_network_name

    def _allocate_provider_port(self, context, instance, network_info,
                                instance_mac=None):
        api_port_mac = None
        tunnel_port_mac = None
        if instance_mac:
            api_port_mac = \
                instance_mac[CONF.vtepdriver.provider_api_network_name]
            tunnel_port_mac = \
                instance_mac[CONF.vtepdriver.provider_tunnel_network_name]

        provider_api_port = ProviderPort(
            CONF.vtepdriver.provider_api_network_id, api_port_mac)

        provider_tunnel_port = ProviderPort(
            CONF.vtepdriver.provider_tunnel_network_id,
            tunnel_port_mac, self._get_tunnel_network_name(network_info))

        api_nwinfo = self._allocate_provider_port_for_instance(context,
                                                               instance,
                                                               provider_api_port)
        tunnel_nwinfo = self.\
            _allocate_provider_port_for_instance(context,
                                                 instance,
                                                 provider_tunnel_port)

        if api_nwinfo is None or len(api_nwinfo) != 1 or \
                tunnel_nwinfo is None or len(tunnel_nwinfo) != 1:
            raise exception.NovaException("Allocate provider port error ," +
                                          "driver allocate port return None")

        nwinfo = network_model.NetworkInfo()
        for vif in tunnel_nwinfo:
            nwinfo.append(vif)

        for vif in api_nwinfo:
            nwinfo.append(vif)

        return nwinfo

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        LOG.debug('plug vifs in vtepdriver networkinfo: |%s|', network_info,
                  instance=instance)
        pass

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        LOG.debug('unplug vifs in vtepdriver networkinfo: |%s|', network_info,
                  instance=instance)
        pass

    def _allocate_provider_port_for_instance(self, context, instance,
                                             provider_port):
        """ allocate provider network port in neutron, this port is used for
        vtep-vm to associate with user port
        """
        nwinfo = self.network_api.allocate_port_for_instance(
            context, instance, provider_port)
        LOG.debug('Instance network_info: |%s|', nwinfo, instance=instance)
        return nwinfo

    def _allocate_provider_vifs(self, vifid_list):
        """ allocate provider port vifs, this contain manage and tunnel port,
        two port with special id
        """
        nw_info = network_model.NetworkInfo()
        for vifid in vifid_list:
            nw_info.append(network_model.VIF(id=vifid))

        return nw_info
