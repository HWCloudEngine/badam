__author__ = 'wangfeng'

import time
import os
import shutil

from oslo.config import cfg
from libcloud.compute.types import StorageVolumeState,NodeState
from libcloud.compute.base import NodeSize, NodeImage
from libcloud.storage.types import ObjectDoesNotExistError


from nova import utils
from nova import exception as exception
from nova.i18n import _, _LW
from nova.openstack.common import jsonutils
from nova.openstack.common import imageutils
from nova.openstack.common import fileutils as fileutils
from nova.openstack.common import log as logging
from nova.compute import task_states
from nova.volume.cinder import API as cinder_api
from nova.image.api import API as glance_api
from nova.compute import power_state
from nova.virt import driver


# from adapter import Ec2Adapter as Ec2Adapter
import adapter
import exception_ex

hybrid_cloud_opts = [

    cfg.StrOpt('provide_cloud_type',
         default='aws',
         help='provider cloud type  ')
]

ec2_opts = [
    cfg.StrOpt('conversion_dir',
               default='/tmp',
               help='where conversion happens'),

    cfg.StrOpt('access_key_id',
               help='the access key id for connection to EC2  '),

    cfg.StrOpt('secret_key',
               help='the secret key  for connection to EC2  '),

    cfg.StrOpt('region',
               default='us-east-1',
               help='the region for connection to EC2  '),

    cfg.StrOpt('availability_zone',
               default='us-east-1a',
               help='the availability_zone for connection to EC2  '),

    cfg.StrOpt('base_linux_image',
               default='ami-68d8e93a',
               help='use for create a base ec2 instance'),

    cfg.StrOpt('storage_tmp_dir',
               default='wfbucketse',
               help='a cloud storage temp directory '),

    cfg.StrOpt('cascaded_node_id',
               help='az31 node id in provider cloud'),

    cfg.StrOpt('subnet_api',
               help='api subnet'),

    cfg.StrOpt('subnet_data',
               help='data subnet'),

    cfg.StrOpt('cgw_host_ip',
               help='compute gateway ip'),

    cfg.StrOpt('cgw_host_id',
               help='compute gateway id in provider cloud'),

    cfg.StrOpt('cgw_user_name',
               help='compute gateway user name'),

    cfg.StrOpt('cgw_certificate',
               help='full name of compute gateway public key'),

    cfg.StrOpt('rabbit_host_ip_public',
                help=''),
    
    cfg.StrOpt('rabbit_password_public',
               help=''),

    cfg.StrOpt('vpn_route_gateway',
               help=''),

    cfg.DictOpt('flavor_map',
                default={'m1.tiny': 't2.micro', 'm1.small': 't2.micro', 'm1.medium': 't2.micro3',
                         'm1.large': 't2.micro', 'm1.xlarge': 't2.micro'},
                help='map nova flavor name to aws ec2 instance specification id')

    ]


LOG = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts(hybrid_cloud_opts)
CONF.register_opts(ec2_opts, 'provider_opts')

CHUNK_SIZE = 1024*4

# EC2 = get_driver(CONF.ec2.driver_type)

class AwsEc2Driver(driver.ComputeDriver):

    def __init__(self, virtapi):
        # import pdb
        # pdb.set_trace()
        if CONF.provide_cloud_type == 'aws':
            if (CONF.provider_opts.access_key_id is None or
                    CONF.provider_opts.secret_key is None):
                raise Exception(_("Must specify access_key_id and "
                                  "secret_key to use aws ec2"))
            self.compute_adapter = adapter.Ec2Adapter(CONF.provider_opts.access_key_id,
                                              secret=CONF.provider_opts.secret_key,
                                              region=CONF.provider_opts.region,
                                              secure=False)
            self.storage_adapter = adapter.S3Adapter(CONF.provider_opts.access_key_id,
                                                     secret=CONF.provider_opts.secret_key,
                                                     region=CONF.provider_opts.region,
                                                     secure=False)

        self.cinder_api = cinder_api()
        self.glance_api = glance_api()

    def init_host(self, host):
        pass

    def list_instances(self):
        """List VM instances from all nodes."""
        # import pdb
        # pdb.set_trace()
        instances = []
        try:
            nodes = self.compute_adapter.list_nodes()
        except:
            LOG.error('list nodes failed')
            return instances
        if nodes is None:
            LOG.error('list nodes failed, Nodes are null!')
            return instances
        for node in nodes:
            instance_uuid = node.extra.get('tags').get('hybrid_cloud_instance_id')
            instances.append(instance_uuid)

        return instances

    def snapshot(self, context, instance, image_id, update_task_state):
        # import pdb
        # pdb.set_trace()
        # self._do_snapshot_1(context, instance, image_id, update_task_state)
        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)

        self._do_snapshot_2(context, instance, image_id, update_task_state)


    def _do_snapshot_1(self, context, instance, image_id, update_task_state):

        # 1) get  provider node
        provider_node_id = self._get_provider_node_id(instance)
        provider_nodes = self.compute_adapter.list_nodes(ex_node_ids=[provider_node_id])
        if not provider_nodes:
            LOG.error('instance %s is not found' % instance.uuid)
            raise exception.InstanceNotFound
        if len(provider_nodes)>1:
            LOG.error('instance %s are more than one' % instance.uuid)
            raise exception_ex.MultiInstanceConfusion
        provider_node = provider_nodes[0]

        # 2) get root-volume id
        provider_volumes = self.compute_adapter.list_volumes(node=provider_node)
        if not provider_volumes:
            raise exception.VolumeNotFound

        provider_volume = provider_volumes[0]

        # 3) export
        self.compute_adapter.export_volume(provider_volume.id,
                                           CONF.provider_opts.conversion_dir,
                                           image_id,
                                           cgw_host_id=CONF.provider_opts.cgw_host_id,
                                           cgw_host_ip=CONF.provider_opts.cgw_host_ip,
                                           cgw_username=CONF.provider_opts.cgw_username,
                                           cgw_certificate=CONF.provider_opts.cgw_certificate,
                                           transfer_station=CONF.provider_opts.storage_tmp_dir)

        # 4) upload to glance
        src_file_name = '%s/%s' %(CONF.provider_opts.conversion_dir, image_id)
        file_size = os.path.getsize(src_file_name)
        metadata = self.glance_api.get(context, image_id)
        image_metadata = {"disk_format": "qcow2",
                          "is_public": "false",
                          "name": metadata['name'],
                          "status": "active",
                          "container_format": "bare",
                          "size": file_size,
                          "properties": {"owner_id": instance['project_id']}}

        src_file_handle = fileutils.file_open(src_file_name, "rb")
        self.glance_api.create(context,image_metadata,src_file_handle)
        src_file_handle.close()


    def _do_snapshot_2(self, context, instance, image_id, update_task_state):
        # xxx(wangfeng)
        # import pdb
        # pdb.set_trace()
        # a) get  provider node id
        provider_node_id = self._get_provider_node_id(instance)
        provider_nodes = self.compute_adapter.list_nodes(ex_node_ids=[provider_node_id])
        if not provider_nodes:
            LOG.error('instance %s is not found' % instance.uuid)
            raise exception.InstanceNotFound
        if len(provider_nodes)>1:
            LOG.error('instance %s are more than one' % instance.uuid)
            raise exception_ex.MultiInstanceConfusion
        provider_node = provider_nodes[0]

        # b) export-instance to s3
        # self.compute_adapter.ex_stop_node(provider_node)
        try:
            task = self.compute_adapter.create_export_instance_task(provider_node_id,
                                                                    CONF.provider_opts.storage_tmp_dir)
        except:
            task = self.compute_adapter.create_export_instance_task(provider_node_id,
                                                                    CONF.provider_opts.storage_tmp_dir)
        while not task.is_completed():
            time.sleep(10)
            task = self.compute_adapter.get_task_info(task)

        obj_key = task.export_to_s3_info.s3_key
        obj_bucket = task.export_to_s3_info.s3_bucket

        # c) download from s3
        obj = self.storage_adapter.get_object(obj_bucket,obj_key)
        conv_dir = '%s/%s' % (CONF.provider_opts.conversion_dir,image_id)
        fileutils.ensure_tree(conv_dir)
        org_full_name = '%s/%s.vmdk' % (conv_dir,image_id)

        # with open(org_full_name, 'wb') as f:
        #     for chunk in self.storage_adapter.download_object_as_stream(obj,chunk_size=CHUNK_SIZE):
        #         if chunk:
        #             f.write(chunk)
        #             f.flush()

        self.storage_adapter.download_object(obj,org_full_name)


        # d) convert to qcow2
        dest_full_name = '%s/%s.qcow2' % (conv_dir,image_id)
        convert_image(org_full_name,
                     dest_full_name,
                      'qcow2')

        # upload to glance
        update_task_state(task_state=task_states.IMAGE_UPLOADING,
                          expected_state=task_states.IMAGE_PENDING_UPLOAD)

        file_size = os.path.getsize(dest_full_name)
        metadata = self.glance_api.get(context, image_id)
        image_metadata = {"disk_format": "qcow2",
                          "is_public": "false",
                          "name": metadata['name'],
                          "status": "active",
                          "container_format": "bare",
                          "size": file_size,
                          "properties": {"owner_id": instance['project_id']}}

        src_file_handle = fileutils.file_open(dest_full_name, "rb")
        self.glance_api.create(context,image_metadata,src_file_handle)
        src_file_handle.close()


    def _generate_provider_node_name(self, instance):
        # xxx(wangfeng): it may should use instance name(cacading instance uuid)
        return instance.uuid

    def _get_provider_node_size(self, flavor):
        return NodeSize(id=CONF.provider_opts.flavor_map[flavor.name],
                        name=None, ram=None, disk=None, bandwidth=None,price=None, driver=self.compute_adapter)


    def _get_image_id_from_meta(self,image_meta):
        if 'id' in image_meta:
            # create from image
            return image_meta['id']
        elif 'image_id' in image_meta:
            # attach
            return image_meta['image_id']
        elif 'properties' in image_meta:
            # create from volume
            return image_meta['properties']['image_id']
        else:
            return None


    def _spawn_from_image(self, context, instance, image_meta, injected_files,
                                    admin_password, network_info, block_device_info):
        # 0.get provider_image,
        retry_time = 3
        provider_image_id = None
        while (not provider_image_id) and retry_time>0:
            provider_image_id = self._get_provider_image_id(image_meta)
            retry_time = retry_time-1

        if provider_image_id is not None:
            provider_image = self.compute_adapter.get_image(provider_image_id)
        else:
            provider_image = None

        # 1. if provider_image do not exist,, import image first
        if not provider_image:
            image_uuid = self._get_image_id_from_meta(image_meta)
            container = self.storage_adapter.get_container(CONF.provider_opts.storage_tmp_dir)

            try:
                self.storage_adapter.get_object(container.name,image_uuid)
            except ObjectDoesNotExistError:
                # 1.1 download qcow2 file from glance


                this_conversion_dir = '%s/%s' % (CONF.provider_opts.conversion_dir,image_uuid)
                orig_file_full_name = '%s/%s.qcow2' % (this_conversion_dir,'orig_file')
                fileutils.ensure_tree(this_conversion_dir)
                self.glance_api.download(context,image_uuid,dest_path=orig_file_full_name)

                # 1.2 convert to provider image format
                converted_file_format = 'vmdk'
                converted_file_name = '%s.%s' % ('converted_file', converted_file_format)
                converted_file_full_name =  '%s/%s' % (this_conversion_dir,converted_file_name)

                convert_image(orig_file_full_name,
                              converted_file_full_name,
                              converted_file_format,
                              subformat='streamoptimized')

            # 1.3 upload to provider_image_id
            #     self.storage_adapter.upload_object(converted_file_full_name,container,image_uuid)
                object_name = image_uuid
                extra = {'content_type': 'text/plain'}

                with open(converted_file_full_name,'rb') as f:
                    obj = self.storage_adapter.upload_object_via_stream(container=container,
                                                               object_name=object_name,
                                                               iterator=f,
                                                               extra=extra)

            # except:
                # LOG.error('Connect to provider storage error')

            task = self.compute_adapter.create_import_image_task(CONF.provider_opts.storage_tmp_dir,
                                                         image_uuid,
                                                         image_name=image_uuid)
            while not task.is_completed():
                time.sleep(5)
                task = self.compute_adapter.get_task_info(task)

            provider_image = self.compute_adapter.get_image(task.image_id)
            set_tag_func = getattr(self.compute_adapter, 'ex_create_tags')
            if set_tag_func:
                set_tag_func(provider_image, {'hybrid_cloud_image_id': image_uuid})


        # 2. map flovar to node size, from configuration
        provider_size = self._get_provider_node_size(instance.get_flavor())

        # 3. get a subnet, create_node in this subnet
        # provider_subnet = self.compute_adapter.ex_list_subnets()[0]

        provider_subnet_data = self.compute_adapter.ex_list_subnets(
            subnet_ids=[CONF.provider_opts.subnet_data])[0]
        provider_subnet_api = self.compute_adapter.ex_list_subnets(
            subnet_ids=[CONF.provider_opts.subnet_api])[0]

        provider_node_name = self._generate_provider_node_name(instance)
        user_data = self._generate_user_data()
        provider_node = self.compute_adapter.create_node(name=provider_node_name,
                                                         image=provider_image,
                                                         size=provider_size,
                                                         ex_subnet=provider_subnet_data,
                                                         ex_userdata=user_data)

        # 4. mapping instance id to provider node, using metadata
        instance.metadata['provider_node_id'] =  provider_node.id
        instance.save()
        set_tag_func = getattr(self.compute_adapter, 'ex_create_tags')
        if set_tag_func:
            set_tag_func(provider_node, {'hybrid_cloud_instance_id': instance.uuid})

        # 5 create a network interface and attach it to node
        while provider_node.state!=NodeState.RUNNING and provider_node.state!=NodeState.STOPPED:
            provider_node = self.compute_adapter.list_nodes(ex_node_ids=[provider_node.id])[0]
            time.sleep(10)

        provider_interface = self.compute_adapter.ex_create_network_interface(
            provider_subnet_api,
            name='Test Interface',
            description='My Test')
        try:
            self.compute_adapter.ex_attach_network_interface_to_node(provider_interface,provider_node, 1)
        except:
            self.compute_adapter.ex_attach_network_interface_to_node(provider_interface,provider_node, 1)

        return provider_node

    def _generate_user_data(self):
        return 'RABBIT_HOST_IP=%s;RABBIT_PASSWORD=%s;VPN_ROUTE_GATEWAY=%s' % (CONF.provider_opts.rabbit_host_ip_public,
                                                          CONF.provider_opts.rabbit_password_public,
                                                          CONF.provider_opts.vpn_route_gateway)

    def _spawn_from_volume(self, context, instance, image_meta, injected_files,
                                        admin_password, network_info, block_device_info):
        self._create_node_ec2(context, instance, image_meta, injected_files,
                              admin_password, network_info, block_device_info)


    def _create_node_ec2(self, context, instance, image_meta, injected_files,
                                        admin_password, network_info, block_device_info):

        # 1. create a common vm
        # 1.1 map flovar to node size, from configuration
        provider_size = self._get_provider_node_size(instance.get_flavor())
        # 1.2 get common image
        provder_image = self.compute_adapter.get_image(CONF.provider_opts.base_linux_image)
        # 1.3. create_node, and get_node_stat, waiting for node creation finish
        provider_node_name = self._generate_provider_node_name(instance)
        provider_node = self.compute_adapter.create_node(name=provider_node_name, image=provder_image, size=provider_size)

        # 2. power off the vm
        self.compute_adapter.ex_stop_node(provider_node)

        # 3. detach origin root volume
        provider_volumes = self.compute_adapter.list_volumes(node=provider_node)
        provider_volume = provider_volumes[0]
        self.compute_adapter.detach_volume(provider_volume)

        # 4. attach this volume
        self.compute_adapter.attach_volume(provider_node,provider_volume, provider_volume.extra.get('device'))


    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """Create VM instance."""
        # import pdb
        # pdb.set_trace()
        LOG.debug(_("image meta is:%s") % image_meta)
        LOG.debug(_("instance is:%s") % instance)
        bdms = block_device_info.get('block_device_mapping',[])
        if len(bdms) > 0:
            volume_id = bdms[0]['connection_info']['data']['volume_id']
            provider_volume_id = self._get_provider_volume_id(context,volume_id)
            if provider_volume_id is not None:
                provider_volumes = self.compute_adapter.list_volumes(ex_volume_ids=[provider_volume_id])
            else:
                provider_volumes = []

            if not provider_volumes:
                # if has no provider volume, boot from image: (import image in provider cloud, then boot instance)
                provider_node = self._spawn_from_image(context, instance, image_meta, injected_files,
                                    admin_password, network_info, block_device_info)

                provider_volume = self.compute_adapter.list_volumes(node=provider_node)
                self._map_volume_to_provider(context, volume_id, provider_volume[0])

            elif len(provider_volumes) == 0:
                # if has provider volume, boot from volume:
                self._spawn_from_volume(context, instance, image_meta, injected_files,
                                        admin_password, network_info, block_device_info)
            else:
                LOG.error('create instance %s faild: multi volume confusion') % instance.uuid
                raise exception_ex.MultiVolumeConfusion
        else:
            # if boot from image: (import image in provider cloud, then boot instance)
            self._spawn_from_image(context, instance, image_meta, injected_files,
                                    admin_password, network_info, block_device_info)
        LOG.debug("creating instance %s success!" % instance.uuid)

    def _map_volume_to_provider(self,context, volume_id, provider_volume):
        # mapping intance root-volume to cinder volume
        if not provider_volume:
            self.cinder_api.update_volume_metadata(context,
                                                   volume_id,
                                                   {'provider_volume_id': None})
        else:
            self.cinder_api.update_volume_metadata(context,
                                                   volume_id,
                                                   {'provider_volume_id': provider_volume.id})
            set_tag_func = getattr(self.compute_adapter, 'ex_create_tags')
            if set_tag_func:
                set_tag_func(provider_volume, {'hybrid_cloud_volume_id': volume_id})

    def _get_provider_image_id(self, image_obj):
        try:
            image_uuid = self._get_image_id_from_meta(image_obj)
            provider_image = self.compute_adapter.list_images(
                ex_filters={'tag:hybrid_cloud_image_id':image_uuid})
            if provider_image is None:
                raise exception_ex.ProviderRequestTimeOut

            if len(provider_image)==0:
                # raise exception.ImageNotFound
                LOG.warning('Image %s NOT Found at provider cloud' % image_uuid)
                return None
            elif len(provider_image)>1:
                raise exception_ex.MultiImageConfusion
            else:
                return provider_image[0].id
        except:
            LOG.error('Can NOT get image %s from provider cloud tag' % image_uuid)
            return  None


    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        pass

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach volume storage to VM instance."""
        # import pdb
        # pdb.set_trace()

        volume_id = connection_info['data']['volume_id']
        instance_id = instance.uuid
        LOG.info("attach volume")
        provider_node_id = self._get_provider_node_id(instance)
        provider_volume_id = self._get_provider_volume_id(context, volume_id)

        # 1.get node
        if not provider_node_id:
            LOG.error('instance %s is not found' % instance_id)
            raise exception.InstanceNotFound
        else:
            provider_nodes = self.compute_adapter.list_nodes(ex_node_ids=[provider_node_id])

        if not provider_nodes:
            LOG.error('instance %s is not found' % instance_id)
            raise exception.InstanceNotFound
        if len(provider_nodes)>1:
            LOG.error('instance %s are more than one' % instance_id)
            raise exception_ex.MultiInstanceConfusion
        provider_node = provider_nodes[0]

        # 2.get volume
        if not provider_volume_id:
            # LOG.error('volume %s is not found' % volume_id)
            # raise exception.VolumeNotFound
            # 1. if provider_image do not exist,, import image first
            volume = self.cinder_api.get(context,volume_id)
            image_meta = volume.get('volume_image_metadata')
            if not image_meta:
                LOG.error('Provider Volume NOT Found!')
                exception_ex.VolumeNotFoundAtProvider
            else:
                # 1.1 download qcow2 file from glance
                image_uuid = self._get_image_id_from_meta(image_meta)

                orig_file_name = 'orig_file.qcow2'
                this_conversion_dir = '%s/%s' % (CONF.provider_opts.conversion_dir,volume_id)
                orig_file_full_name = '%s/%s' % (this_conversion_dir,orig_file_name)

                fileutils.ensure_tree(this_conversion_dir)
                self.glance_api.download(context,image_uuid,dest_path=orig_file_full_name)

                # 1.2 convert to provider image format
                converted_file_format = 'vmdk'
                converted_file_name = '%s.%s' % ('converted_file', converted_file_format)
                converted_file_path = '%s/%s' % (CONF.provider_opts.conversion_dir,volume_id)
                converted_file_full_name =  '%s/%s' % (converted_file_path,converted_file_name)
                convert_image(orig_file_full_name,
                              converted_file_full_name,
                              converted_file_format,
                              subformat='streamoptimized')


                # 1.3 upload to provider_image_id
                container = self.storage_adapter.get_container(CONF.provider_opts.storage_tmp_dir)
                # self.storage_adapter.upload_object(converted_file_full_name,container,volume_id)

                object_name = volume_id
                extra = {'content_type': 'text/plain'}

                with open(converted_file_full_name,'rb') as f:
                    obj = self.storage_adapter.upload_object_via_stream(container=container,
                                                               object_name=object_name,
                                                               iterator=f,
                                                               extra=extra)

                obj = self.storage_adapter.get_object(container.name,volume_id)

                task = self.compute_adapter.create_import_volume_task(CONF.provider_opts.storage_tmp_dir,
                                                                      volume_id,
                                                                      'VMDK',
                                                                      obj.size,
                                                                      str(volume.get('size')),
                                                                      volume_loc=provider_node.extra.get('availability'))
                while not task.is_completed():
                    time.sleep(10)
                    if task.is_cancelled():
                        LOG.error('import volume fail!')
                        raise exception_ex.UploadVolumeFailure
                    task = self.compute_adapter.get_task_info(task)

                provider_volume_id = task.volume_id


        provider_volumes = self.compute_adapter.list_volumes(ex_volume_ids=[provider_volume_id])

        if provider_volumes is None:
            LOG.error('Time out when query provider volume %s', provider_volume_id)
            raise exception_ex.ProviderRequestTimeOut

        if len(provider_volumes)>1:
            LOG.error('volume %s are more than one' % volume_id)
            raise exception_ex.MultiVolumeConfusion
        provider_volume = provider_volumes[0]

        if provider_volume.state != StorageVolumeState.AVAILABLE:
            LOG.error('volume %s is not available' % volume_id)
            raise exception.InvalidVolume

        # 3.attach
        self.compute_adapter.attach_volume(provider_node,provider_volume,mountpoint)

        # 4. map volume to provider volume
        self._map_volume_to_provider(context, volume_id, provider_volume)


    def _get_provider_volume_id(self, context, volume_id):

        provider_volume_id = self.cinder_api.get_volume_metadata_value(context,volume_id,'provider_volume_id')

        if not provider_volume_id:
            try:
                provider_volumes = self.compute_adapter.list_volumes(ex_filters={'tag:hybrid_cloud_volume_id':volume_id})
                if len(provider_volumes) == 1:
                    provider_volume_id = provider_volumes[0].id
                    self.cinder_api.update_volume_metadata(context,volume_id,{'provider_volume_id':provider_volume_id})
                elif len(provider_volumes)>1:
                    raise exception_ex.MultiImageConfusion
                else:
                    LOG.warning('Volume %s NOT Found at provider cloud' % volume_id)
                    # raise exception.ImageNotFound
            except:
                LOG.error('Can NOT get volume %s from provider cloud tag' % volume_id)

        return provider_volume_id



    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
        # import pdb
        # pdb.set_trace()

        LOG.info("detach volume")

        volume_id = connection_info['data']['volume_id']
        # instance_id = instance.uuid

        # 1.get volume
        # provider_volume_id = self._get_provider_volume_id(volume_id)
        # provider_volumes = self.compute_adapter.list_volumes(ex_volume_ids=[provider_volume_id])
        # xxx(wangfeng): if provdier did not have tags, we need modify this solution
        provider_volumes = self.compute_adapter.list_volumes(ex_filters={'tag:hybrid_cloud_volume_id':volume_id})
        if not provider_volumes:
            LOG.error('volume %s is not found' % volume_id)
            raise exception.VolumeNotFound
        if len(provider_volumes)>1:
            LOG.error('volume %s are more than one' % volume_id)
            raise exception_ex.MultiVolumeConfusion
        provider_volume = provider_volumes[0]

        if provider_volume['state'] != StorageVolumeState.ATTACHING:
            LOG.error('volume %s is not attaching' % volume_id)

        # 2.dettach
        self.compute_adapter.detach_volume(provider_volume)
        # self._map_volume_to_provider(context, volume_id, provider_volume)

        pass

    def get_available_resource(self, nodename):
        """Retrieve resource info.

        This method is called when nova-compute launches, and
        as part of a periodic task.

        :returns: dictionary describing resources

        """
        # xxx(wangfeng):
        return {'vcpus': 32,
                'memory_mb': 164403,
                'local_gb': 5585,
                'vcpus_used': 0,
                'memory_mb_used': 69005,
                'local_gb_used': 3479,
                'hypervisor_type': 'aws',
                'hypervisor_version': 5005000,
                'hypervisor_hostname': nodename,
                'cpu_info': '{"model": ["Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz"], \
                "vendor": ["Huawei Technologies Co., Ltd."], \
                "topology": {"cores": 16, "threads": 32}}',
                'supported_instances': jsonutils.dumps(
                    [["i686", "ec2", "hvm"], ["x86_64", "ec2", "hvm"]]),
                'numa_topology': None,
                }

    def get_available_nodes(self, refresh=False):
        """Returns nodenames of all nodes managed by the compute service.

        This method is for multi compute-nodes support. If a driver supports
        multi compute-nodes, this method returns a list of nodenames managed
        by the service. Otherwise, this method should return
        [hypervisor_hostname].
        """
        # return "aws-ec2-hypervisor"
        return "hybrid_%s" % CONF.provider_opts.region

    def get_info(self, instance):
        # import pdb
        # pdb.set_trace()

        state = power_state.NOSTATE

        # xxx(wangfeng): it is too slow to connect to aws to get info. so I delete it
        # provider_node_id = self._get_provider_node_id(instance)
        # nodes = None
        # if provider_node_id is not None:
        #     nodes = self.compute_adapter.list_nodes(ex_node_ids=[provider_node_id])
        #
        # if not nodes:
        #     LOG.error('instance %s Not Found' % instance.uuid)
        #     # raise exception.InstanceNotFound
        # elif len(nodes) > 1:
        #     LOG.error('more than one instance %s Found' % instance.uuid)
        #     # raise exception_ex.MultiInstanceConfusion
        # else:
        #     node = nodes[0]
        #     node_status = node.get('state')
        #     instance_type =node.get('extra').get('instance_type')


        return {'state': state,
                'max_mem': 0,
                'mem': 0,
                'num_cpu': 1,
                'cpu_time': 0}

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """Destroy VM instance."""
        # import pdb
        # pdb.set_trace()

        LOG.debug('begin destory node %s',instance.uuid)

        provider_node_id = self._get_provider_node_id(instance)
        if not provider_node_id:
            LOG.warning('Instance %s NOT Found at provider cloud' % instance.uuid)
            return
        nodes = self.compute_adapter.list_nodes(ex_node_ids=[provider_node_id])
        if not nodes:
            # raise exception.InstanceNotFound
            LOG.warning('Instance %s NOT Found at provider cloud' % instance.uuid)
            return
        if len(nodes) > 1:
            LOG.error('More than one instance %s are Found at provider cloud' % instance.uuid)
            raise exception_ex.MultiInstanceConfusion

        node = nodes[0]

        if not destroy_disks:
            # dettach volumes
            if len(block_device_info) > 0:
                provider_volume_ids = []
                # get volume id
                for device in block_device_info:
                    volume_id = device[ 'connection_info']['data']['volume_id']
                    provider_volume_ids.append(self._get_provider_volume_id(context,volume_id))

                # get volume in provide cloud
                provider_volumes = self.compute_adapter.list_volumes(node=provider_volume_ids)

                # detach
                for provider_volume in provider_volumes:
                    self.compute_adapter.detach_volume(provider_volume)
                    self._map_volume_to_provider(context, volume_id, None)

        # destory node
        self.compute_adapter.destroy_node(node)


    def _get_provider_node_id(self, instance_obj):
        # import pdb
        # pdb.set_trace()
        """map openstack instance_uuid to ec2 instance id"""
        # if instance has metadata:provider_node_id, it's provider node id
        provider_node_id = instance_obj.metadata.get('provider_node_id')

        # if instance has NOT metadata:provider_node_id, search provider cloud instance's tag
        if not provider_node_id:
            try:
                provider_node = self.compute_adapter.list_nodes(ex_filters={'tag:hybrid_cloud_instance_id':instance_obj.uuid})
                if len(provider_node) == 1:
                    provider_node_id = provider_node[0].id
                    instance_obj.metadata.set('provider_node_id', provider_node_id)
                    instance_obj.save()
                elif len(provider_node)>1:
                    raise exception_ex.MultiImageConfusion
                else:
                    # raise exception.ImageNotFound
                    LOG.warning('Instance %s NOT Found at provider cloud' % instance_obj.uuid)
            except:
                LOG.warning('Can NOT get instance %s from provider cloud tag' % instance_obj.uuid)

        return provider_node_id

    def get_volume_connector(self, instance):
        pass

    def power_off(self, instance, timeout=0, retry_interval=0):
        # import pdb
        # pdb.set_trace()

        LOG.debug('Power off node %s',instance.uuid)
        provider_node_id = self._get_provider_node_id(instance)
        nodes = self.compute_adapter.list_nodes(ex_node_ids=[provider_node_id])
        if not nodes:
            raise exception.InstanceNotFound
        if len(nodes) > 1:
            raise exception_ex.MultiInstanceConfusion
        node = nodes[0]
        self.compute_adapter.ex_stop_node(node)

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        # import pdb
        # pdb.set_trace()

        LOG.debug('Power on node %s',instance.uuid)
        provider_node_id = self._get_provider_node_id(instance)
        nodes = self.compute_adapter.list_nodes(ex_node_ids=[provider_node_id])
        if not nodes:
            raise exception.InstanceNotFound
        if len(nodes) > 1:
            raise exception_ex.MultiInstanceConfusion
        node = nodes[0]
        self.compute_adapter.ex_start_node(node)
        
    def get_instance_macs(self, instance):
        LOG.debug('Start to get macs of instance %s', instance)
        filters = {'tag:Name': instance['uuid']}
        nodes = self.compute_adapter.list_nodes(ex_filters=filters)
        instance_macs = dict()
        if nodes is not None and len(nodes) == 1:
            node = nodes[0]
            nw_interfaces = node.extra['network_interfaces']
            for nw_interface in nw_interfaces:
                subnet_id = nw_interface.extra['subnet_id']
                vpc_id = nw_interface.extra['vpc_id']
                mac_address = nw_interface.extra['mac_address']

                # NOTE(nkapotoxin): Now we make the subnet_id is the provider
                # network id
                instance_macs[subnet_id] = mac_address
            return instance_macs


def qemu_img_info(path):
    """Return an object containing the parsed output from qemu-img info."""
    # flag.
    if not os.path.exists(path):
        msg = (_("Path does not exist %(path)s") % {'path': path})
        raise exception.InvalidDiskInfo(reason=msg)

    out, err = utils.execute('env', 'LC_ALL=C', 'LANG=C',
                             'qemu-img', 'info', path)
    if not out:
        msg = (_("Failed to run qemu-img info on %(path)s : %(error)s") %
               {'path': path, 'error': err})
        raise exception.InvalidDiskInfo(reason=msg)

    return imageutils.QemuImgInfo(out)


def convert_image(source, dest, out_format, run_as_root=False, **kwargs):
    """Convert image to other format."""
    cmd = ('qemu-img', 'convert', '-O', out_format, source, dest)
    utils.execute(*cmd, run_as_root=run_as_root)

    if kwargs.has_key('subformat'):
        if kwargs.get('subformat') == 'streamoptimized':
            dir_name = os.path.dirname(dest)
            base_name = os.path.basename(dest)

            ovf_name = '%s/%s.ovf' % (dir_name,base_name)
            vmx_name_temp = '%s/vmx/template.vmx' % CONF.provider_opts.conversion_dir
            vmx_name = '%s/template.vmx' % dir_name
            shutil.copy2(vmx_name_temp,vmx_name)

            mk_ovf_cmd = ('ovftool', '-o',vmx_name, ovf_name)
            convert_file = '%s/converted-file.vmdk' % dir_name
            os.rename(dest, convert_file)
            utils.execute(*mk_ovf_cmd, run_as_root=run_as_root)
            vmdk_file_name = '%s/%s-disk1.vmdk' % (dir_name,base_name)

            fileutils.delete_if_exists(dest)
            os.rename(vmdk_file_name, dest)

            fileutils.delete_if_exists(ovf_name)
            fileutils.delete_if_exists('%s/%s.mf' % (dir_name,base_name))
            fileutils.delete_if_exists(convert_file)






