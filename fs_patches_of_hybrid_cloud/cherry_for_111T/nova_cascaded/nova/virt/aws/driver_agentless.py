

from oslo.config import cfg
from nova.openstack.common import log as logging
from driver import AwsEc2Driver
from nova.network import neutronv2
import base64

# from nova.virt import hardware
import hypernode_api
import adapter
from driver import NodeState
# from nova.compute import power_state
from nova import exception as exception

LOG = logging.getLogger(__name__)

hn_opts = [
    cfg.StrOpt('hypernode_name',
               help='hypernode name for ovs'),
    ]

cfg.CONF.register_opts(hn_opts, 'provider_opts')


class AwsAgentlessDriver(AwsEc2Driver):

    def __init__(self, virtapi, read_only=False):
        super(AwsAgentlessDriver, self).__init__(virtapi)
        # the configuration
        self.hn_api = hypernode_api.HyperNodeAPI()
        self.provider_security_group_id = None

    @staticmethod
    def _binding_host(context, network_info, host_id):
        neutron = neutronv2.get_client(context, admin=True)
        port_req_body = {'port': {'binding:host_id': host_id}}
        for vif in network_info:
            neutron.update_port(vif.get('id'), port_req_body)

    def _generate_user_data(self, instance):
        encoded_data = instance.get('user_data')
        if encoded_data and len(encoded_data)>0:
            return base64.b64decode(encoded_data)
        else:
            return ''

    def detach_interface(self, instance, vif):
        LOG.debug("unplug_vifs %s" % (vif,))
        self.hn_api.unplug(vif)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        LOG.debug("spawn %s" % instance)
        LOG.debug("network_info %s" % network_info)
        # import pdb
        # pdb.set_trace()
        #

        # todo: get provider subnet id
        # p_subnet_id = self.hn_api.get_subnet_id()
        # p_subnet_id = self.provider_interfaces[0].subnet_id
        # hypernode_name = cfg.CONF.provider_opts.hypernode_name

        # get hybernode info, include:
        #   hypernode_name, provider_subnet_id, security_group_id, etc
        hn_task = self.hn_api.choose_hn()
        hypernode_name = hn_task.hypernode_name
        p_subnet_id = hn_task.vm_subnet.id
        self.provider_security_group_id = hn_task.vm_security_group_id
        self._binding_host(context, network_info, hypernode_name)

        p_vif = adapter.NetworkInterface(name='eth_agls',
                                         subnet_id=p_subnet_id,
                                         device_index=0)
        self.provider_interfaces = []
        self.provider_interfaces.append(p_vif)

        # create ec2 vm on aws
        super(AwsAgentlessDriver, self).spawn(
            context, instance, image_meta, injected_files,
            admin_password, network_info=network_info,
            block_device_info=block_device_info)

        # wait for choosing hn
        # import pdb
        # pdb.set_trace()
        # We can add a timeout argument here so we do not block for too long
        hn_task.wait()

        # if choosing hn succeed
        if not hn_task.exception:
            # plug vifs
            if network_info:
                self.plug_vifs(instance, network_info)

            # update port's binding-host
            self._binding_host(context, network_info, hypernode_name)
        else:
            raise exception.InstanceDeployFailure(str(hn_task.exception))

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        LOG.debug("destroy")
        # import pdb
        # pdb.set_trace()

        # unplug vifs. this should be done before or after vm deletion?
        if network_info:
            self.unplug_vifs(instance, network_info)

        # destroy ec2 vm on aws
        super(AwsAgentlessDriver, self).destroy(
            context, instance, network_info,
            block_device_info=block_device_info,
            destroy_disks=destroy_disks, migrate_data=migrate_data)

    def _get_provider_private_ip(self, instance, nic_idx=0):

        try:
            p_node = self._get_provider_node(instance)
            if not p_node:
                error = 'Failed to find any matching object'
                raise Exception(error)
            if p_node.state == NodeState.TERMINATED:
                strerror = 'Instance is terminated, no need to hassle with it'
                LOG.error(strerror)
                raise exception.InstanceNotRunning(instance_id=p_node.id)
            p_nics = p_node.extra.get('network_interfaces')
            p_ip_objs = p_nics[nic_idx].extra.get('private_ips')
            p_ip = p_ip_objs[0].get('private_ip')
            return p_ip
        except Exception as e:
            LOG.error(e.message)
            raise e

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        LOG.debug("plug_vifs %s" % network_info)
        LOG.debug("instance %s" % instance)

        # get provider ip of ec2 vm
        provider_ip = self._get_provider_private_ip(instance, 0)

        # rpc call hypernode to plug port
        for vif in network_info:
            self.hn_api.plug(instance.uuid, vif, provider_ip)

    def unplug_vifs(self, instance, network_info):
        """unplug VIFs into networks."""
        LOG.debug("plug_vifs %s" % network_info)

        for vif in network_info:
            self.hn_api.unplug(vif)
