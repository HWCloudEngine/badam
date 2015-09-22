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

from oslo import messaging
from oslo.config import cfg

from nova import rpc
from nova import context
from nova.objects import base as objects_base
from nova.openstack.common import log as logging
from hypernode_installer import HyperNodeInstaller
from oslo.messaging.exceptions import MessagingTimeout
from oslo.messaging.rpc.client import RemoteError
from oslo.messaging.exceptions import MessageDeliveryFailure
from nova.virt.aws.hypernode_installer import HyperNodeAPIException

LOG = logging.getLogger(__name__)

hypernode_api_opts = [  
    cfg.IntOpt('plug_retry_timeout',
               default=15,
               help='timeout for each connect retry for a new VM'),
    cfg.IntOpt('plug_retries_max',
               default=8,
               help='Maximal number of connect retries before giving up'),
    cfg.StrOpt('cidr_hns',
               help='The provider CIDR block for the HyperNode subnet',
               required=True),
    cfg.StrOpt('ip_vpngw',
               help='IP address of the VPN gateway on the cascading node',
               required=True),
    cfg.StrOpt('subnet_tunnel_bearing',
               help='The provider subnet ID of the Tunnel Bearing subnet',
               required=True),
    cfg.StrOpt('subnet_internal_base',
               help='The provider subnet ID of the Internal Base subnet',
               required=True),
]

cfg.CONF.register_opts(hypernode_api_opts, 'hypernode_api')


class HyperNodeAPI(object):
    """Client side of the Hyper Node RPC API
    """
    plug_retries_max = cfg.CONF.hypernode_api.plug_retries_max
    plug_retry_timeout = cfg.CONF.hypernode_api.plug_retry_timeout

    def __init__(self):
        super(HyperNodeAPI, self).__init__()
        target = messaging.Target(topic='hypernode-hypernode-update',
                                  version='1.0',
                                  exchange='hypernode')
        serializer = objects_base.NovaObjectSerializer()
        self.client = rpc.get_client(target, serializer=serializer)
        self.client.timeout = HyperNodeAPI.plug_retry_timeout
        self.context = context.get_admin_context()
        self.hn_installer = HyperNodeInstaller()

    def choose_hn(self):
        """
        selects the HyperNode to be used

        :rtype: :class:`HyperNodeInstallerState`
        """

        hn_state = self.hn_installer.start_install(
            hn_cidr_block=cfg.CONF.hypernode_api.cidr_hns,
            tunnel_bearing_subnet_id=cfg.CONF.hypernode_api.subnet_tunnel_bearing,
            vpngw_ip=cfg.CONF.hypernode_api.ip_vpngw,
            internal_base_subnet_id=cfg.CONF.hypernode_api.subnet_internal_base,
            tenant_id=None)

        return hn_state

    def plug(self, instance_id, vif, provider_ip):
        """
        waits for the HyperNode to be ready and connects the instance

        :param instance_id: 
        :type instance_id: ``str``
        :param vif: 
        :type vif: ``str``
        :param provider_ip: 
        :type provider_ip: ``str``
        :rtype: ``bool``
        :raises: MessagingTimeout, RemoteError, MessageDeliveryFailure
        """
        count = 1
        LOG.debug('HyperNodeAPI:plug - plug %s, %s, %s' %
                  (str(instance_id), str(vif), str(provider_ip)))
        while True:
            try:
                self.client.call(self.context, 'plug',
                                 instance_id=instance_id,
                                 vif=vif,
                                 provider_ip=provider_ip)
                LOG.debug('HyperNodeAPI:plug - plug returned')
                return True
            except (MessagingTimeout, RemoteError, MessageDeliveryFailure) as e:
                LOG.debug('HyperNodeAPI:plug - encountered an exception: %s' %
                          (str(e),))
                count += 1
                if count > HyperNodeAPI.plug_retries_max:
                    LOG.debug('HyperNodeAPI:plug - Max retries exceeded,'
                              'raising exception')
                    if e is MessagingTimeout:
                        raise HyperNodeAPIException(
                            'Timeout occured while communicating with '
                            'the new HyperNode')
                    else:
                        raise HyperNodeAPIException(
                            'Unknown error while communicating with '
                            'the new HyperNode')
        
    def unplug(self, vif):
        """
        Disconnects an instance

        :param vif: 
        :type vif: ``str``
        :rtype: ``bool``
        """
        try:
            return self.client.call(self.context,
                                    'unplug',
                                    vif=vif)
        except Exception as e:
            LOG.error('Unplug return error:%s' % (str(e),))
            return None
        
