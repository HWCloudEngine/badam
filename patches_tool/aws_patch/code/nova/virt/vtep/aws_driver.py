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
from nova.virt.vtep import driver
from nova.virt.vtep.driver import ProviderPort, VtepDriver
from nova.virt.vtep import network_api
from nova.virt.aws import driver as aws_driver


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class VtepAWSDriver(VtepDriver, aws_driver.AwsEc2Driver):

    """ The VtepAWSVCloud connection object."""

    def __init__(self, virtapi):
        super(VtepAWSDriver, self).__init__(virtapi)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        # NOTE(nkapotoxin): Vtep driver must generate provider port, and
        # the original driver use it to create vtep-vm, vtep agent help to
        # link this port to user vm port, every vtep driver can do spawn
        # like this.

        # NOTE(nkapotoxin): Generate nwinfo with fixed network, cause vcloud
        # driver create vm instance with vdc network id is vif.id in network_info,
        # so just set it to network_id
        nwinfo = self._allocate_provider_vifs([
            CONF.vtepdriver.provider_tunnel_network_name,
            CONF.vtepdriver.provider_api_network_name])

        aws_driver.AwsEc2Driver.spawn(self, context, instance, image_meta,
                                      injected_files, admin_password,
                                      nwinfo, block_device_info)

        # Check provider network port use vm mac, change
        # mac and name of nwinfo
        instance_mac = None
        try:
            instance_mac = self.get_instance_macs(instance)
        except Exception:
            LOG.error(
                "Get mac from aws error, instance:%s" %
                instance,
                exc_info=True)
            raise exception.NovaException(
                "Get mac error from instance:%s" % instance)

        # Generate provider_network port
        self._allocate_provider_port(context, instance, network_info,
                                     instance_mac)
