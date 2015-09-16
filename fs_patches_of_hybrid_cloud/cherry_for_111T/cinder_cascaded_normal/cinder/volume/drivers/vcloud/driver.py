import contextlib
import distutils.version as dist_version  # pylint: disable=E0611
import os
import tempfile
import shutil
import subprocess
import pdb
import urllib2
import traceback

import cinder.compute.nova as nova
from cinder.image import image_utils
from oslo.config import cfg
from cinder import exception
from cinder import utils
from cinder.i18n import _
# from cinder.openstack.common import excutils
from cinder.openstack.common import fileutils
from cinder.openstack.common import log as logging
# from cinder.openstack.common import units
# from cinder.openstack.common import uuidutils
from cinder.volume import driver
from cinder.volume import volume_types
from cinder.volume.drivers.vcloud import util
from cinder.volume.drivers.vcloud.vcloudair import *
from cinder.volume.drivers.vcloud.vcloudair import VCloudAPISession as VCASession
from oslo.utils import units
from cinder.volume.drivers.vcloud import sshutils as sshclient
from keystoneclient.v2_0 import client as kc
# from cinder.volume.drivers.vmware import api
# from cinder.volume.drivers.vmware import datastore as hub
# from cinder.volume.drivers.vmware import error_util
# from cinder.volume.drivers.vmware import vim
# from cinder.volume.drivers.vmware import vim_util
# from cinder.volume.drivers.vmware import vmware_images
# from cinder.volume.drivers.vmware import volumeops

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
]

vcloudvgw_opts = [
    cfg.StrOpt('vcloud_vgw_host',
               default='',
               help='the ip or host of vcloud vgw host.'),
    cfg.StrOpt('vcloud_vgw_name',
               default='vcloud_vgw',
               help='the name of vcloud vgw host.'),
    cfg.StrOpt('vcloud_vgw_username',
               default='root',
               help='user name of vcloud vgw host.'),
    cfg.StrOpt('vcloud_vgw_password',
               default='',
               help='password of vcloud vgw host.'),
    cfg.StrOpt('store_file_dir',
               default='/home/upload',
               help='Directory used for temporary storage '
                    'during migrate volume'),
    # cfg.DictOpt('vcloud_vgw_url',
    #             default={
    #                 'fs_vgw_url': 'http://162.3.114.62:8090/',
    #                 'vcloud_vgw_url': 'http://162.3.114.108:8090/',
    #                 'aws_vgw_url': 'http://172.27.12.245:8090/'
    #             },
    #             help="These values will be used for upload/download image "
    #                  "from vgw host."),
    ]

keystone_opts =[
    cfg.StrOpt('tenant_name',
               default='admin',
               help='tenant name for connecting to keystone in admin context'),
    cfg.StrOpt('user_name',
               default='cloud_admin',
               help='username for connecting to cinder in admin context'),
    cfg.StrOpt('keystone_auth_url',
               default='https://identity.cascading.hybrid.huawei.com:443/identity-admin/v2.0',
               help='value of keystone url'),
]

keystone_auth_group = cfg.OptGroup(name='keystone_authtoken',
                               title='keystone_auth_group')

CONF = cfg.CONF
CONF.register_opts(vcloudapi_opts, 'vcloud')
CONF.register_opts(vcloudvgw_opts, 'vgw')

CONF.register_group(keystone_auth_group)
CONF.register_opts(keystone_opts,'keystone_authtoken')

LOG = logging.getLogger(__name__)
# VOLUME_FILE_DIR = '/hc_volumes'
# CONVERT_DIR = '/hctemp'
IMAGE_TRANSFER_TIMEOUT_SECS = 300
VGW_URLS = ['vgw_url']


class VCloudNode(object):
    def __init__(self, name, **args):
        self.name = name
        for key in args.keys():
            self.__setattr__(key, args.get(key))

class VCloudAPISession(VCASession):

    """Sets up a session with the vcd and handles all
    the calls made to the host.
    """

    def __init__(self, host_ip=CONF.vcloud.vcloud_host_ip,
                 host_port=CONF.vcloud.vcloud_host_port,
                 host_username=CONF.vcloud.vcloud_host_username,
                 host_password=CONF.vcloud.vcloud_host_password,
                 org=CONF.vcloud.vcloud_org,
                 vdc=CONF.vcloud.vcloud_vdc,
                 version=CONF.vcloud.vcloud_version,
                 service=CONF.vcloud.vcloud_service,
                 verify=CONF.vcloud.vcloud_verify,
                 service_type=CONF.vcloud.vcloud_service_type,
                 retry_count=CONF.vcloud.vcloud_api_retry_count,
                 create_session=True,
                 scheme="https"):
        super(VCloudAPISession, self).__init__(host_ip=host_ip,
                                               host_port=host_port,
                                               server_username=host_username,
                                               server_password=host_password,
                                               org=org, vdc=vdc,
                                               version=version,
                                               service=service,
                                               verify=verify,
                                               service_type=service_type,
                                               retry_count=retry_count,
                                               create_session=create_session,
                                               scheme=scheme
                                               )

    def _call_method(self, module, method, *args, **kwargs):
        """Calls a method within the module specified with
        args provided.
        """
        return self.invoke_api(module, method, *args, **kwargs)

    def _wait_for_task(self, task_ref):
        """Return a Deferred that will give the result of the given task.
        The task is polled until it completes.
        """
        return self.wait_for_task(task_ref)

class VMwareVcloudVolumeDriver(driver.VolumeDriver):
    VERSION = "1.0"

    def __init__(self, scheme="https", *args, **kwargs):
        super(VMwareVcloudVolumeDriver, self).__init__( *args, **kwargs)
        self._stats = None
        self._nova_api = nova.API()
        self._node_name = CONF.vcloud.vcloud_node_name
        self._session = VCloudAPISession(scheme=scheme)

        self._vgw_host = CONF.vgw.vcloud_vgw_host
        self._vgw_name = CONF.vgw.vcloud_vgw_name
        self._vgw_username = CONF.vgw.vcloud_vgw_username
        self._vgw_password = CONF.vgw.vcloud_vgw_password
        #self._vgw_url = CONF.vgw.vcloud_vgw_url
        self._vgw_store_file_dir = CONF.vgw.store_file_dir

       

    def _create_volume(self, name, size):
        return self._session._call_method(self._session.vca,
                                          "add_disk",
                                          self._session.vdc, name, size)

    def _delete_volume(self, name):
        return self._session._call_method(self._session.vca,
                                          "delete_disk",
                                          self._session.vdc, name)

    def _get_vcloud_volume_name(self, volume_id, volume_name):
        prefix = 'volume@'
        if volume_name.startswith(prefix):
            vcloud_volume_name = volume_name[len(prefix):]
        else:
            vcloud_volume_name = volume_id

        return vcloud_volume_name

    def _get_vcloud_vdc(self):
        return self._session._call_method(self._session.vca,
                                          "get_vdc",
                                          self._session.vdc)

    def _get_vcloud_vapp(self, vapp_name):

        the_vdc = self._session._call_method(self._session.vca,
                                             "get_vdc",
                                             self._session.vdc)

        the_vapp = self._session._call_method(self._session.vca,
                                              "get_vapp",
                                              the_vdc,
                                              vapp_name)

        if not the_vapp:
            #raise exception.NovaException("can't find the vapp")
            LOG.info("can't find the vapp %s" % vapp_name)
            return None
        else:
            return the_vapp

    def _power_off_vapp(self, the_vapp):
        task_stop = self._session._call_method(the_vapp,
                                               "undeploy")
        if not task_stop:
            raise exception.CinderException(
                "undeploy vapp failed, task")
        self._session._wait_for_task(task_stop)
        return self._get_vcloud_vapp(the_vapp.name)

    def _power_on_vapp(self, the_vapp):
        task = self._session._call_method(the_vapp, "poweron")
        if not task:
            raise exception.CinderException(
                "deploy vapp failed, task")
        self._session._wait_for_task(task)
        return self._get_vcloud_vapp(the_vapp.name)

    def _get_disk_ref(self, disk_name):
        vdc_ref = self._get_vcloud_vdc()
        disk_refs = self._session._call_method(self._session.vca,
                                               'get_diskRefs',
                                               vdc_ref)
        link = filter(lambda link: link.get_name() == disk_name, disk_refs)
        if len(link) == 1:
            return True, link[0]
        elif len(link) == 0:
            return False, 'disk not found'
        elif len(link) > 1:
            return False, 'more than one disks found with that name.'

    def _get_disks(self):
        disks = self._session._call_method(self._session.vca,
                                           'get_disks',
                                           self._session.vdc)
        return disks

    def _get_disk_attached_vm(self, disk_name):
        disks = self._get_disks()
        for disk, vms in disks:
            if disk.get_name() == disk_name:
                return vms

    def _attach_disk_to_vm(self, the_vapp, disk_ref):
        task = the_vapp.attach_disk_to_vm(the_vapp.name, disk_ref)
        if not task:
            raise exception.CinderException(
                "Unable to attach disk to vm %s" % the_vapp.name)
        else:
            self._session._wait_for_task(task)
            return True

    def _detach_disk_from_vm(self, the_vapp, disk_ref):
        task = the_vapp.detach_disk_from_vm(the_vapp.name, disk_ref)
        if not task:
            raise exception.CinderException(
                "Unable to detach disk from vm %s" % the_vapp.name)
        else:
            self._session._wait_for_task(task)
            return True

    def do_setup(self, context):
        """Instantiate common class and log in storage system."""
        pass

    def check_for_setup_error(self):
        """Check configuration file."""
        pass

    def create_volume(self, volume):
        """Create a volume."""
        volume_name = volume['display_name']
        volume_size = int(volume['size']) * units.Gi
        # use volume_name as vcloud disk name, remove prefix str `volume@`
        # if volume_name does not start with volume@, then use volume id instead

        vcloud_volume_name = self._get_vcloud_volume_name(volume['id'],
                                                          volume_name)

        LOG.debug('Creating volume %(name)s of size %(size)s',
                  {'name': vcloud_volume_name, 'size': volume_size})

        result, resp = self._create_volume(vcloud_volume_name, volume_size)
        if result:
            self._session.wait_for_task(resp)
            LOG.info('Created volume : %(name)s',
                     {'name': vcloud_volume_name})
        else:
            err_msg = 'Unable to create volume, reason: %s' % resp
            LOG.error(err_msg)
            raise exception.VolumeBackendAPIException(
                            err_msg)

    def delete_volume(self, volume):
        """Delete a volume."""
        volume_name = volume['display_name']

        vcloud_volume_name = self._get_vcloud_volume_name(volume['id'],
                                                          volume_name)
        LOG.debug('Deleting volume %s', vcloud_volume_name)

        result, resp = self._delete_volume(vcloud_volume_name)
        if result:
            self._session.wait_for_task(resp)
            LOG.info('Deleted volume : %(name)s',
                     {'name': vcloud_volume_name})
        else:
            if resp == 'disk not found':
                LOG.warning('delete_volume: unable to find volume %(name)s',
                    {'name': vcloud_volume_name})
                # If we can't find the volume then it is effectively gone.
                return True
            else:
                err_msg = _('Unable to delete volume, reason: %s' % resp)
                LOG.error(err_msg)
                raise exception.VolumeBackendAPIException(err_msg)

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot."""
        pass

    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume."""
        pass

    def extend_volume(self, volume, new_size):
        """Extend a volume."""
        pass

    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        # todo(wangfeng)
        
        # volume_name = snapshot.get('volume_id')
        # snapshot_arn = self.aws_sg.createSnapshot(volume_name)
        # return {'provider_location': snapshot_arn}
        # pdb.set_trace()
        context = snapshot['context']
        volume_id = snapshot['volume_id']
        # create_info = {'snapshot_id':snapshot['id'],
        #               'type':'vmdk',
        #              'new_file':'snapshot_file'}

        # self._nova_api.create_volume_snapshot(ctx,volume_id,create_info)

        volume = snapshot.volume
        if volume['attach_status']=='attached':
            the_vapp = self._get_vcloud_vapp(volume['instance_uuid'])
            vmdk_url = self._query_vmdk_url(the_vapp)
            local_file_name = '%s/%s.vmdk' % (CONF.vcloud.vcloud_conversion_dir, volume_id)
            self._download_vmdk_from_vcloud(context, vmdk_url,local_file_name)

        else:
            local_file_name = '%s/%s.vmdk' % (CONF.vcloud.vcloud_volumes_dir, volume_id)
            if not os.path.exists(local_file_name):
                LOG.error('volume file %s do not exist' % local_file_name)

        # image_utils.upload_volume(context,image_service,image_meta,local_file_name,'vmdk')

    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        # todo(wangfeng)
        pass

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        vdc = self._get_vcloud_vdc()
        # pdb.set_trace()
        if not self._stats:
            backend_name = self.configuration.safe_get('volume_backend_name')
            LOG.debug('*******backend_name is %s' %backend_name)
            if not backend_name:
                backend_name = 'HC_vcloud'
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

    def _query_vmdk_url(self, the_vapp):

        # pdb.set_trace()
        # node_name = instance.node

        # 0. shut down the app first
        # pdb.set_trace()
        # node_name = instance.node

        # 0. shut down the app first
        try:
            the_vapp = self._power_off_vapp(the_vapp)
        except:
            LOG.error('power off failed')

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
        local_file_handle = open(dst_file_name, "wb")
        remote_file_handle = urllib2.urlopen(src_url)
        file_size = remote_file_handle.headers['content-length']
        util.start_transfer(context, IMAGE_TRANSFER_TIMEOUT_SECS,remote_file_handle, file_size,
                             write_file_handle=local_file_handle)

    def _attach_volume_to_vgw(self, volume):
        volume_name = volume['display_name']
        vcloud_volume_name = self._get_vcloud_volume_name(volume['id'],
                                                          volume_name)
        # get the provider_volume at provider cloud
        # find volume reference by it's name
        result, disk_ref = self._get_disk_ref(vcloud_volume_name)
        if result:
            LOG.debug("Find volume successful, disk name is: %(disk_name)s "
                      "disk ref's href is: %(disk_href)s.",
                      {'disk_name': vcloud_volume_name,
                       'disk_href': disk_ref.href})
        else:
            LOG.error(_('Unable to find volume %s'),
                      vcloud_volume_name)
            raise exception.VolumeNotFound(volume_id=vcloud_volume_name)
        # Check whether the volume is attached to vm or not,
        # Make sure the volume is available
        vms = self._get_disk_attached_vm(vcloud_volume_name)
        if len(vms) > 0:
            vm_name = vms[0].get_name()
            the_vapp = self._get_vcloud_vapp(vm_name)
            if the_vapp:
                self._detach_disk_from_vm(the_vapp, disk_ref)
        # get the vgw host
        vapp_name = self._vgw_name
        the_vapp = self._get_vcloud_vapp(vapp_name)
        # attach volume to vgw when the vgw is in stopped status
        if self._attach_disk_to_vm(the_vapp, disk_ref):
            LOG.info("Volume %(volume_name)s attached to "
                     "vgw host: %(instance_name)s",
                     {'volume_name': vcloud_volume_name,
                      'instance_name': vapp_name})
        return disk_ref, the_vapp

    def _get_management_url(self, kc, image_name, **kwargs):
        endpoint_info= kc.service_catalog.get_endpoints(**kwargs)
        endpoint_list = endpoint_info.get(kwargs.get('service_type'),None)
        region_name = image_name.split('_')[-1]
        if endpoint_list:
            for endpoint in endpoint_list:
                if region_name == endpoint.get('region'):
                    return endpoint.get('publicURL')

    @RetryDecorator(max_retry_count=CONF.vcloud.vcloud_api_retry_count,
                    exceptions=(sshclient.SSHError,
                                sshclient.SSHTimeout))
    def _copy_volume_to_file_to_vgw(self, image_meta):
        try:
            image_id = image_meta.get('id')
            image_name = image_meta.get('name')
            container_format = image_meta.get('container_format')
            dest_file_path = os.path.join('/tmp', image_id)

            ssh_client = sshclient.SSH(user=self._vgw_username,
                                           host=self._vgw_host,
                                           password=self._vgw_password)

            cmd = '/usr/bin/rescan-scsi-bus.sh -a -r'
            ssh_client.run(cmd)

            # convert volume to image
            cmd = 'qemu-img convert -c -O qcow2 %s %s' %\
                  ('/dev/sdb', dest_file_path)
            LOG.error('begin time of %s is %s' %
                      (cmd, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()
                                          )))
            ssh_client.run(cmd)
            LOG.debug("Finished running cmd : %s" % cmd)
            LOG.error('end time of %s is %s' %
                      (cmd, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()
                                          )))
            # push the converted image to remote vgw host
            # vgw_url = CONF.vgw.vcloud_vgw_url[container_format]
            kwargs = {'auth_url': CONF.keystone_authtoken.keystone_auth_url,
                      'tenant_name': CONF.keystone_authtoken.tenant_name,
                      'username': CONF.keystone_authtoken.user_name,
                      'password': CONF.keystone_authtoken.admin_password,
                      'insecure': True}
            keystoneclient = kc.Client(**kwargs)
            vgw_url = ''
            vgw_url = self._get_management_url(keystoneclient, image_name,
                                               service_type='v2v')

            LOG.debug('The remote vgw url is %(vgw_url)s',
                      {'vgw_url': vgw_url})
            # eg: curl -X POST --http1.0 -T
            # /tmp/467bd6e1-5a6e-4daa-b8bc-356b718834f2
            # http://172.27.12.245:8090/467bd6e1-5a6e-4daa-b8bc-356b718834f2
            cmd = 'curl -X POST --http1.0 -T %s ' % dest_file_path
            cmd += vgw_url
            if cmd.endswith('/'):
                cmd += image_id
            else:
                cmd += '/' + image_id
            LOG.error('begin time of %s is %s' %
                      (cmd, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()
                                          )))
            ssh_client.run(cmd)
            LOG.error('end time of %s is %s' %
                      (cmd, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()
                                          )))

            LOG.debug("Finished running cmd : %s" % cmd)
        except Exception as e:
            LOG.error('Failed to copy volume to image by vgw.'
                      'traceback: %s', traceback.format_exc())
            raise e
        finally:
            if ssh_client:
                # delete the temp file which is used for convert volume to image
                ssh_client.run('rm -f %s' % dest_file_path)
                ssh_client.close()

    @utils.synchronized("vcloud_volume_copy_lock", external=True)
    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        """Creates glance image from volume."""
        LOG.debug('Copying volume %(volume_name)s to image %(image_name)s.',
                  {'volume_name': volume['display_name'],
                   'image_name': image_meta.get('name')})

        LOG.error('begin time of copy_volume_to_image is %s' %
                  (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))

        container_format = image_meta.get('container_format')
        if container_format in VGW_URLS:
            # attach the volume to vgw vm
            disk_ref, the_vapp = self._attach_volume_to_vgw(volume)

            try:
                # use ssh client connect to vgw_host and
                # copy image file to volume
                self._copy_volume_to_file_to_vgw(image_meta)
            finally:
                # detach volume from vgw and
                self._detach_disk_from_vm(the_vapp, disk_ref)
            # create an empty file to glance
            with image_utils.temporary_file() as tmp:
                image_utils.upload_volume(context,
                                          image_service,
                                          image_meta,
                                          tmp)

            LOG.error('end time of copy_volume_to_image is %s' %
                      (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))

        else:
            def _unused():
                # todo(wangfeng)
                # pdb.set_trace()
                # 1. get the vmdk file.

                volume_id = volume['id']
                if volume['attach_status']=='attached':
                    # nova_client = nova.novaclient(context)
                    # node_name = nova_client.servers.get(instance_id)._
                    # info['OS-EXT-SRV-ATTR:hypervisor_hostname']
                    the_vapp = self._get_vcloud_vapp(volume['instance_uuid'])
                    vmdk_url = self._query_vmdk_url(the_vapp)
                    local_file_name = '%s/%s.vmdk' % (CONF.vcloud.vcloud_conversion_dir, volume_id)
                    self._download_vmdk_from_vcloud(context, vmdk_url,local_file_name)

                    # volume_id = volume['id']
                    # create_info = {'snapshot_id':volume['snapshot_id'],
                    #              'type':'qcow2',
                    #             'new_file':'snapshot_file'}

                    # self._nova_api.create_volume_snapshot(context,volume_id,create_info)
                    # local_file_name = '%s/%s.vmdk' % (CONVERT_DIR, volume_id)
                else:
                    local_file_name = '%s/%s.vmdk' % (CONF.vcloud.vcloud_volumes_dir, volume_id)
                    if not os.path.exists(local_file_name):
                        LOG.error('volume file %s do not exist' % local_file_name)
                        return

                # 1. the file is vmdk, convert it to qcow2
                # converted_file_name = '%s/converted-file.qcow2' %
                # CONF.vcloud.vcloud_conversion_dir
                # convert_commond = "qemu-img convert -f %s -O %s %s %s" % \
                #                      ('vmdk',
                #                     'qcow2',
                #                    local_file_name,
                #                   converted_file_name)
                # convert_result = subprocess.call([convert_commond],shell=True)
                # if convert_result != 0:
                # do something, change metadata
                # LOG.error('converting file failed')

                # 2. upload to glance

                # file_size = os.path.getsize(converted_file_name)

                # The properties and other fields that we need to set for the image.
                # image_meta['disk_format'] = 'qcow2'
                # image_meta['status'] = 'active'
                # image_meta['size'] = file_size
                # image_meta['properties'] = {'owner_id': volume['project_id']}

                # image_utils.upload_volume(context,image_service,image_meta,converted_file_name,'qcow2')

                image_utils.upload_volume(context,image_service,image_meta,local_file_name,'vmdk')

                # timeout = IMAGE_TRANSFER_TIMEOUT_SECS
                # util.start_transfer(context, timeout, read_file_handle, file_size,
                #          image_service=image_service, image_id=image_meta['id'],
                #         image_meta=image_meta)
            _unused()

    @RetryDecorator(max_retry_count=CONF.vcloud.vcloud_api_retry_count,
                    exceptions=(sshclient.SSHError,
                                sshclient.SSHTimeout))
    def _copy_file_to_volume_from_vgw(self, image_id):
        try:
            dest_file_path = os.path.join(self._vgw_store_file_dir, image_id)
            ssh_client = sshclient.SSH(user=self._vgw_username,
                                       host=self._vgw_host,
                                       password=self._vgw_password)
 
            cmd = '/usr/bin/rescan-scsi-bus.sh -a -r'
            ssh_client.run(cmd)

            # copy data to volume
            # TODO(luqitao): need to get device name, does not use sdb.
            # TODO(luqitao): check the dest_file does exist or not?
            cmd = 'qemu-img convert %s %s' %\
                  (dest_file_path, '/dev/sdb')
            ssh_client.run(cmd)
            LOG.debug("Finished running cmd : %s" % cmd)

            cmd = 'rm -rf %s' % dest_file_path
            ssh_client.run(cmd)

        except Exception as e:
            LOG.error('Failed to copy data to volume from vgw. '
                      'traceback: %s', traceback.format_exc())
            raise e
        finally:
            if ssh_client:
                ssh_client.close()

    @utils.synchronized("vcloud_volume_copy_lock", external=True)
    def copy_image_to_volume(self, context, volume, image_service, image_id):
        """Creates volume from image."""
        LOG.error('begin time of copy_image_to_volume is %s' % (time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime())))

        image_meta = image_service.show(context, image_id)
        LOG.debug('Copying image %(image_name)s to volume %(volume_name)s.',
                  {'volume_name': volume['display_name'],
                   'image_name': image_meta.get('name')})

        container_format = image_meta.get('container_format')
        if container_format in VGW_URLS:
            disk_ref, the_vapp = self._attach_volume_to_vgw(volume)
            # start the vgw, so it can recognize the volume
            #   (vcloud does not support online attach or detach volume)
            # self._power_on_vapp(the_vapp)

            try:
                # use ssh client connect to vgw_host and
                # copy image file to volume
                LOG.error('begin time of _copy_file_to_volume_from_vgw is %s' %
                          (time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.localtime())))
                self._copy_file_to_volume_from_vgw(image_id)
                LOG.error('end time of _copy_file_to_volume_from_vgw is %s' %
                          (time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.localtime())))
            finally:
                # detach volume from vgw and
                self._detach_disk_from_vm(the_vapp, disk_ref)

            # shutdown the vgw, do some clean env work
            # self._power_off_vapp(the_vapp)
            LOG.info('Finished copy image %(image_name)s '
                     'to volume %(volume_name)s.',
                     {'volume_name': volume['display_name'],
                      'image_name': image_meta.get('name')})
            LOG.error('end time of copy_image_to_volume is %s' % (time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime())))
        else:
            pass
            # xxx(wangfeng)
            # pdb.set_trace()
            # self.db.volume_metadata_update(context,volume['id'],
            #                                {'image_id':image_id}, False)

    def initialize_connection(self, volume, connector):
        """Allow connection to connector and return connection info."""
        LOG.debug('vCloud Driver: initialize_connection')

        driver_volume_type = 'vcloud_volume'
        data = {}
        data['backend'] = 'vcloud'
        data['volume_id'] = volume['id']
        data['display_name'] = volume['display_name']

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
