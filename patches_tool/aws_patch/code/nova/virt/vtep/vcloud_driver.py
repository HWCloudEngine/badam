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
from nova.virt.vcloudapi.vcloudair import VCloudAPISession as VCASession
from nova.virt import driver
from nova.virt.vcloudapi import driver as vcloud_driver
from nova.virt.vcloudapi.vcenter_utils import BaseAPI
from nova.virt.vtep import network_api
from nova.virt.vtep import driver
from nova.virt.vtep.driver import ProviderPort, VtepDriver


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class VtepVCloudDriver(VtepDriver, vcloud_driver.VMwareVcloudDriver):

    """ The VtepVCloud connection object."""

    def __init__(self, virtapi):
        super(VtepVCloudDriver, self).__init__(virtapi)

    def init_vcenterapi(self):
        # NOTE(nkapotoxin): Cause original vCloud driver must use oslo
        # vmware and vcenterapi to query the dvPortGroup infos which
        # VCloudapi created, and to support trunk port vlan create, but
        # this process is changed in the vtepdriver, all vtep agent is
        # is now installed in every vm, and it can connect vm to neutron
        # server.
        LOG.info("Mock init vcenterapi in vtep vcloud driver")
        self._vcenterapi = BaseAPI()

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        # NOTE(nkapotoxin): Vtep driver must generate provider port, and
        # the original driver use it to create vtep-vm, vtep agent help to
        # link this port to user vm port, every vtep driver can do spawn
        # like this.

        # Generate two provider port
        nwinfo = self._allocate_provider_port(context,
                                              instance,
                                              network_info)

        if nwinfo is not None and len(nwinfo) == 2:
            nwinfo[0]['id'] = CONF.vtepdriver.provider_tunnel_network_name
            nwinfo[1]['id'] = CONF.vtepdriver.provider_api_network_name

        vcloud_driver.VMwareVcloudDriver.spawn(self, context, instance,
                                               image_meta, injected_files,
                                               admin_password, nwinfo,
                                               block_device_info)

    def create_networks(self, network_info):
        """create cloud networks"""
        LOG.debug(
            'create_network in vtepdriver networkinfo: |%s|',
            network_info)
        pass
