import contextlib
import distutils.version as dist_version  # pylint: disable=E0611
import os
import tempfile
import shutil
import subprocess
import pdb
import urllib2

import cinder.compute.nova as nova
from cinder.image import image_utils
from oslo.config import cfg
from cinder import exception
from cinder.i18n import _
from cinder.openstack.common import excutils as excutils
from cinder.openstack.common import fileutils as fileutils
from cinder.openstack.common import log as logging
from cinder.openstack.common import units
from cinder.openstack.common import uuidutils
from cinder.volume import driver
from cinder.volume import volume_types
from cinder.volume.drivers.vcloud import util
from cinder.volume.drivers.vcloud.vcloudair import *
from cinder.volume.drivers.vcloud import vcloud_task_states

vcloudapi_opts = [

    cfg.StrOpt('vcloud_node_name',
               default='vcloud_node_01',
               help='node name,which a node is a vcloud vcd '
               'host.'),
    cfg.StrOpt('vcloud_host_ip',
               default='162.3.110.103',
               help='Hostname or IP address for connection to VMware VCD '
               'host.'),
    cfg.IntOpt('vcloud_host_port',
               default=443,
               help='Host port for cnnection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_host_username',
               default='nkapotoxin',
               help='Host username for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_host_password',
               default='Galax0088',
               help='Host password for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_org',
               default='nkapotoxin-org',
               help='User org for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_vdc',
               default='nkapotoxin-hybrid-org',
               help='Vdc for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_version',
               default='5.5',
               help='Version for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_service',
               default='85-719',
               help='Service for connection to VMware VCD '
               'host.'),
    cfg.BoolOpt('vcloud_verify',
                default=False,
                help='Verify for connection to VMware VCD '
                'host.'),
    cfg.StrOpt('vcloud_service_type',
               default='vcd',
               help='Service type for connection to VMware VCD '
               'host.'),
    cfg.IntOpt('vcloud_api_retry_count',
               default=2,
               help='Api retry count for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_ovs_ethport',
               default='eth1',
               help='The eth port of ovs-vm use '
               'to connect vm openstack create '),

    cfg.StrOpt('vcloud_conversion_dir',
               default='/vcloud/convert_tmp',
               help='the directory where images are converted in '),

    cfg.StrOpt('vcloud_volumes_dir',
               default='/vcloud/volumes',
               help='the directory of volume files'),

    cfg.StrOpt('vcloud_vm_naming_rule',
            default = 'openstack_vm_id',
            help = 'the rule to name vcloud VMs, valid options: openstack_vm_id, openstack_vm_name, cascaded_openstack_rule'),
]

CONF = cfg.CONF
CONF.register_opts(vcloudapi_opts, 'vcloud')
LOG = logging.getLogger(__name__)

IMAGE_TRANSFER_TIMEOUT_SECS = 300
INSTANCE_STATUS_SHUTOFF = 'SHUTOFF'

class VCloudNode(object):
    def __init__(self, name, **args):
        self.name = name
        for key in args.keys():
            self.__setattr__(key, args.get(key))


class VMwareVcloudVolumeDriver(driver.VolumeDriver):
    VERSION = "1.0"
    def __init__(self, *args, **kwargs):
        self._stats = None
        self._nova_api = nova.API()

        self._node_name = CONF.vcloud.vcloud_node_name
        self._session = VCloudAPISession(host_ip=CONF.vcloud.vcloud_host_ip,
                 host_port=CONF.vcloud.vcloud_host_port,
                 server_username=CONF.vcloud.vcloud_host_username,
                 server_password=CONF.vcloud.vcloud_host_password,
                 org=CONF.vcloud.vcloud_org,
                 vdc=CONF.vcloud.vcloud_vdc,
                 version=CONF.vcloud.vcloud_version,
                 service=CONF.vcloud.vcloud_service,
                 verify=CONF.vcloud.vcloud_verify,
                 service_type=CONF.vcloud.vcloud_service_type,
                 retry_count=CONF.vcloud.vcloud_api_retry_count,
                 create_session=True,
                 scheme='https')

        super(VMwareVcloudVolumeDriver, self).__init__(*args, **kwargs)

    


    def do_setup(self, context):
        """Instantiate common class and log in storage system."""
        pass

    def check_for_setup_error(self):
        """Check configuration file."""
        pass

    def create_volume(self, volume):
        """Create a volume."""
        # xxx(wangfeng)
        # volume_size = long(volume['size']) * 1024 * 1024 * 1024
        # volume_arn = self.aws_sg.createVolume(volume['name'], volume_size)
        # LOG.info("volume:%s, volume arn:%s" % (volume['name'], volume_arn))
        # return {'provider_location': volume_arn}
        pass

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot."""
        pass
    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume."""
        pass

    def extend_volume(self, volume, new_size):
        """Extend a volume."""
        pass

    def delete_volume(self, volume):
        """Delete a volume."""
        # xxx(wangfeng)
        #pdb.set_trace()
        volume_id = volume['id']
        volume_file_name = '%s/%s.vmdk' %(CONF.vcloud.vcloud_volumes_dir,volume_id)

        fileutils.delete_if_exists(volume_file_name)
        # self.aws_sg.deleteVolume(volume['provider_location'])

    def _update_vm_task_state(self, context, vm_uuid, task_state):
        nova_client = nova.novaclient(context)
        instance = nova_client.servers.get(vm_uuid)
        if not task_state:
            nova_client.servers.set_meta(instance,{'task_state':''})
        else:
            nova_client.servers.set_meta(instance,{'task_state':task_state})
            

        return instance.__getattr__('OS-EXT-STS:task_state')


    def _get_vcloud_vapp_name(self, context, volume):
        vapp_name = self.db.volume_metadata_get(context,volume['id']).get('vcloud_vapp_name')

        if not vapp_name:
            nova_client = nova.novaclient(context)
            instance_uuid = self._get_instance_uuid(volume)
            instance = nova_client.servers.get(instance_uuid)

            if CONF.vcloud.vcloud_vm_naming_rule == 'openstack_vm_id':
                return instance.uuid
            elif CONF.vcloud.vcloud_vm_naming_rule == 'openstack_vm_name':
                return instance.uuid
            elif CONF.vcloud.vcloud_vm_naming_rule == 'cascaded_openstack_rule':
                return instance.name
            else:
                return instance.uuid
        else:
            return vapp_name

    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        # todo(wangfeng)
        
        # volume_name = snapshot.get('volume_id')
        # snapshot_arn = self.aws_sg.createSnapshot(volume_name)
        # return {'provider_location': snapshot_arn}
        context = snapshot['context']
        volume_id = snapshot['volume_id']
        #create_info = {'snapshot_id':snapshot['id'],
         #               'type':'vmdk',
          #              'new_file':'snapshot_file'}

        # self._nova_api.create_volume_snapshot(ctx,volume_id,create_info)

        volume = snapshot.volume
        if volume['attach_status']=='attached':
            vapp_name = self._get_vcloud_vapp_name(context, volume)
            the_vapp = self._get_vcloud_vapp(vapp_name)
            vmdk_url = self._query_vmdk_url(the_vapp)
            local_file_name = '%s/%s.vmdk' % (CONF.vcloud.vcloud_conversion_dir, volume_id)
            self._download_vmdk_from_vcloud(context, vmdk_url,local_file_name)

        else:
            local_file_name = '%s/%s.vmdk' % (CONF.vcloud.vcloud_volumes_dir, volume_id)
            if not os.path.exists(local_file_name):
                LOG.error('volume file %s do not exist' % local_file_name)


    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        # todo(wangfeng)
        pass

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        vdc = self._get_vcloud_vdc()
        if not self._stats:
            backend_name = self.configuration.safe_get('volume_backend_name')
            if not backend_name:
                backend_name = self.__class__.__name__
            data = {'volume_backend_name': backend_name,
                    'vendor_name': 'Huawei',
                    'driver_version': self.VERSION,
                    'storage_protocol': 'LSI Logic SCSI',
                    # xxx(wangfeng): get from vcloud
                    'reserved_percentage': 0,
                    'total_capacity_gb': 1000,
                    'free_capacity_gb': 1000}
            self._stats = data
        return self._stats

    def create_export(self, context, volume):
        """Export the volume."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    def remove_export(self, context, volume):
        """Remove an export for a volume."""
        pass

    # def _power_off_vapp(self, the_vapp):
        # task_stop = self._session._call_method(the_vapp,"undeploy")
        # if not task_stop:
        #     raise exception.NovaException(
        #         "undeploy vapp failed, task" )
        # self._session._wait_for_task(task_stop)
        # return self._get_vcloud_vapp(the_vapp.name)

    def _get_vcloud_vdc(self):
        return  self._session._call_method(self._session.vca,
                                   "get_vdc",
                                    self._session.vdc)

    def _get_vcloud_vapp(self, vapp_name):

        the_vdc = self._session._call_method(self._session.vca,
                                   "get_vdc",
                                    self._session.vdc)

        return  self._session._call_method(self._session.vca,
                                   "get_vapp",
                                   the_vdc,
                                   vapp_name)


    def _query_vmdk_url(self, the_vapp):
        """
        get the referenced file url of a vapp. The vapp must be stopped.

        :param the_vapp:
        :return: the referenced file url. None if failed
        """

        # 0. shut down the app first
        # try:
        #     the_vapp = self._power_off_vapp(the_vapp)
        # except:
        #     LOG.debug('power off failed')

        # 0. check if the vapp was shuted down
        vapp_status = the_vapp.me.status
        if vapp_status != VCLOUD_STATUS.POWERED_OFF:
            LOG.error('query_vmdk_url failed: vapp %s status is not powered off') % the_vapp.name
            return None

        # 1.enable download.
        task = self._session._call_method(the_vapp, 'enableDownload')
        if not task:
            raise exception.CinderException(
                "enable vmdk file download failed, task:")
        self._session._wait_for_task(task)


        # 2.get vapp info and ovf descriptor
        the_vapp = self._get_vcloud_vapp(the_vapp.name)
        # the_vapp = self._session._call_method(the_vapp, 'get_updated_vapp')

        ovf = self._session._call_method(the_vapp, 'get_ovf_descriptor')

        # 3.get referenced file url
        referenced_file_url = self._session._call_method(the_vapp, 'get_referenced_file_url',ovf)
        if not referenced_file_url:
            raise exception.CinderException(
                "get vmdk file url failed")
        return referenced_file_url

    def _download_vmdk_from_vcloud(self,context, src_url,dst_file_name):
        local_file_handle = fileutils.file_open(dst_file_name, "wb")
        remote_file_handle = urllib2.urlopen(src_url)
        file_size = remote_file_handle.headers['content-length']
        util.start_transfer(context, IMAGE_TRANSFER_TIMEOUT_SECS,remote_file_handle, file_size,
                             write_file_handle=local_file_handle)

    def _get_instance_uuid(self, volume):
        if hasattr(volume, 'instance_uuid'):
		    instance_uuid = volume.instance_uuid
        else:
            instance_uuid = volume.volume_attachment[0].instance_uuid
        return instance_uuid

    def _stop_instance_sync(self, context, instance_uuid):
        """
        stop instance through nova api.
        The method doesn't return until the instance's status is shutoff
        :param context:
        :param instance_uuid:
        :return:
        """
        nova_client = nova.novaclient(context)

        instance = nova_client.servers.get(instance_uuid)
        if instance.status == INSTANCE_STATUS_SHUTOFF:
            LOG.info('the instance is already powered off')
            return

        try:
            nova_client.servers.stop(instance_uuid)
        except:
            LOG.info('stop instance failed for some reason. maybe it is already powered off')

        instance = nova_client.servers.get(instance_uuid)
        retry_time = 20
        while instance.status != INSTANCE_STATUS_SHUTOFF \
                and retry_time > 0:
            retry_time = retry_time-1
            time.sleep(3)
            instance = nova_client.servers.get(instance_uuid)

        if retry_time == 0:
            raise exception.CinderException('stop_instance_sync failed: '
                                            'instance did not shut down after 60s ')


    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        """Creates glance image from volume."""
        # todo(wangfeng)
        #pdb.set_trace()
        LOG.debug('[vcloud cinder driver] copy_volume_to_image: %s' % volume['id'])

         # 1. get the vmdk file.
        instance_uuid = self._get_instance_uuid(volume)
        #CONF.nova_api_insecure = insec
        volume_id = volume['id']
        if volume['attach_status']=='attached':
            # nova_client = nova.novaclient(context)
            # node_name = nova_client.servers.get(instance_id)._info['OS-EXT-SRV-ATTR:hypervisor_hostname']
            self._stop_instance_sync(context,instance_uuid)

            old_task_state = self._update_vm_task_state(context, instance_uuid, vcloud_task_states.PROVIDER_PREPARING)
            vapp_name = self._get_vcloud_vapp_name(context,volume)
            the_vapp = self._get_vcloud_vapp(vapp_name)
            vmdk_url = self._query_vmdk_url(the_vapp)

            self._update_vm_task_state(context, instance_uuid, vcloud_task_states.EXPORTING)
            local_file_name = '%s/%s.vmdk' % (CONF.vcloud.vcloud_conversion_dir, volume_id)
            self._download_vmdk_from_vcloud(context, vmdk_url,local_file_name)

        else:
            local_file_name = '%s/%s.vmdk' % (CONF.vcloud.vcloud_volumes_dir, volume_id)
            if not os.path.exists(local_file_name):
                LOG.error('volume file %s do not exist' % local_file_name)
                return

        if instance_uuid:
            self._update_vm_task_state(context,instance_uuid, vcloud_task_states.UPLOADING)
			
        util.upload_volume(context,image_service,image_meta,local_file_name,'vmdk')

        if instance_uuid:
            self._update_vm_task_state(context, instance_uuid, old_task_state)

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        """Creates volume from image."""
        # xxx(wangfeng)
        LOG.debug('[vcloud cinder driver] copy_image_to_volume: %s' % volume['id'])
        self.db.volume_metadata_update(context,volume['id'],{'image_id':image_id},False)

    def initialize_connection(self, volume, connector):
        """Allow connection to connector and return connection info."""
        LOG.debug('vCloud Driver: initialize_connection')

        driver_volume_type = 'vcloud_volume'
        data = {}
        data['backend'] = 'vcloud'
        data['volume_id'] = volume['id']

        return {'driver_volume_type': driver_volume_type,
                 'data': data}

    def terminate_connection(self, volume, connector, **kwargs):
        """Disallow connection from connector"""
        LOG.debug('vCloud Driver: terminate_connection')
        pass

    def validate_connector(self, connector):
        """Fail if connector doesn't contain all the data needed by driver."""
        LOG.debug('vCloud Driver: validate_connector')
        pass
