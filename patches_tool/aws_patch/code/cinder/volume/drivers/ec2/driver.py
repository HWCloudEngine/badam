import cinder.compute.nova as nova
from cinder.image import image_utils
from oslo.config import cfg
from cinder import exception
from cinder.i18n import _
from cinder.openstack.common import excutils
from cinder.openstack.common import fileutils
from cinder.openstack.common import log as logging
from cinder.openstack.common import units
from cinder.openstack.common import uuidutils
from cinder.volume import driver
from cinder.volume import volume_types

from oslo.config import cfg
# from libcloud.compute.types import Provider
#from libcloud.compute.providers import get_driver
#from libcloud.compute.base import Node
from adapter import Ec2Adapter as Ec2Adapter
import exception_ex
import os
import cinder.context
import pdb

ec2api_opts = [
    cfg.StrOpt('access_key_id',
               default='',
               help='the access key id for connection to EC2  '),

    cfg.StrOpt('secret_key',
               default='',
               help='the secret key  for connection to EC2  '),

    cfg.StrOpt('region',
               default='ap-southeast-1',
               help='the region for connection to EC2  '),

    cfg.StrOpt('driver_type',
               default='ec2_ap_southeast',
               help='the type for driver  '),

    cfg.StrOpt('provider_image_conversion_dir',
               default='/tmp/ec2/',
               help='volume convert to image dir'),

    cfg.StrOpt('provider_instance_id',
               default='',
               help='aws instance id'),

    cfg.StrOpt('cgw_host_id',
               default='',
               help='compute gateway id in provider cloud'),

    cfg.StrOpt('cgw_host_ip',
               default='',
               help='compute gateway ip'),

    cfg.StrOpt('cgw_username',
               default='',
               help='compute gateway user name'),

    cfg.StrOpt('cgw_certificate',
               default='',
               help='full name of compute gateway public key'),

    cfg.StrOpt('storage_tmp_dir',
               default='wfbucketse',
               help='a cloud storage temp directory'),

    cfg.StrOpt('availability_zone',
               default='ap-southeast-1a',
               help='the availability_zone for connection to EC2  ')
]

LOG = logging.getLogger(__name__)

CONF = cfg.CONF
CONF.register_opts(ec2api_opts)
# EC2 = get_driver(CONF.ec2.driver_type)


class AwsEc2VolumeDriver(driver.VolumeDriver):
    VERSION = "1.0"

    def __init__(self, *args, **kwargs):
        super(AwsEc2VolumeDriver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(ec2api_opts)
        LOG.info("access_key_id = %s,secret_key = %s" % (self.configuration.access_key_id,
                                                         self.configuration.secret_key))
        if (self.configuration.access_key_id is None or
                    self.configuration.secret_key is None):
            raise Exception(_("Must specify access_key_id and "
                              "secret_key to use aws ec2"))
        self.adpter = Ec2Adapter(self.configuration.access_key_id, secret=self.configuration.secret_key,
                                 region=self.configuration.region, secure=False)

    def do_setup(self, context):
        """Instantiate common class and log in storage system."""
        pass

    def check_for_setup_error(self):
        """Check configuration file."""
        pass

    def create_volume(self, volume):
        """Create a volume."""
        size = volume['size']
        name = volume['name']
        location = self.adpter.get_location(self.configuration.availability_zone)
        if not location:
            raise exception_ex.ProviderLocationError
        provider_location = self.adpter.create_volume(size, name, location)
        if not provider_location:
            raise exception_ex.ProviderCreateVolumeError(volume_id=volume['id'])
        LOG.info("create volume: %s; provider_volume: %s " % (volume['id'], provider_location.id))
        create_tags_func = getattr(self.adpter, 'ex_create_tags')
        if create_tags_func:
            create_tags_func(provider_location, {'hybrid_cloud_volume_id': volume['id']})
        ctx = cinder.context.get_admin_context()
        if ctx:
            self.db.volume_metadata_update(ctx, volume['id'], {'provider_volume_id': provider_location.id}, False)
        model_update = {'provider_location': provider_location.id}
        return model_update

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot."""
        pass

    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume."""
        pass

    def extend_volume(self, volume, new_size):
        """Extend a volume."""
        pass

    def _get_provider_volumeid_from_volume(self, volume):
        if not volume.get('provider_location',None):
            ctx = cinder.context.get_admin_context()
            metadata = self.db.volume_metadata_get(ctx, volume['id'])
            return metadata.get('provider_volume_id',None)
        else:
            return volume.get('provider_location',None)

    def delete_volume(self, volume):
        """Delete a volume."""
        provider_volume_id = self._get_provider_volumeid_from_volume(volume)
        if not provider_volume_id:
            LOG.error('NO Mapping between cinder volume and provider volume')
            return

        provider_volumes = self.adpter.list_volumes(ex_volume_ids=[provider_volume_id])
        if not provider_volumes:
            LOG.error('provider_volume  is not found')
            return
            #raise exception.VolumeNotFound(volume_id=volume['id'])
        elif len(provider_volumes) > 1:
            LOG.error('volume %s has more than one provider_volume' % volume['id'])
            raise exception_ex.ProviderMultiVolumeError(volume_id=volume['id'])
        delete_ret = self.adpter.destroy_volume(provider_volumes[0])
        LOG.info("deleted volume return%d" % delete_ret)

    def _get_provider_volumeID_from_snapshot(self, snapshot):
        provider_volume_id = self._get_provider_volumeid_from_volume(snapshot['volume'])
        return provider_volume_id

    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        provider_volume_id = self._get_provider_volumeID_from_snapshot(snapshot)
        provider_volumes = self.adpter.list_volumes(ex_volume_ids=[provider_volume_id])
        if not provider_volumes:
            LOG.error('provider_volume %s is not found' % provider_volume_id)
            raise exception.VolumeNotFound(volume_id=snapshot['volume_id'])
        elif len(provider_volumes) > 1:
            LOG.error('volume %s has more than one provider_volume' % snapshot['volume_id'])
            raise exception_ex.ProviderMultiVolumeError(volume_id=snapshot['volume_id'])
        provider_snapshot = self.adpter.create_volume_snapshot(provider_volumes[0], snapshot['name'])
        if not provider_snapshot:
            raise exception_ex.ProviderCreateSnapshotError(snapshot_id=snapshot['id'])
        create_tags_func = getattr(self.adpter, 'ex_create_tags')
        if create_tags_func:
            create_tags_func(provider_snapshot, {'hybrid_cloud_snapshot_id': snapshot['id']})
        ctx = cinder.context.get_admin_context()
        if ctx:
            self.db.snapshot_metadata_update(ctx, snapshot['id'], {'provider_snapshot_id': provider_snapshot.id}, False)
        model_update = {'provider_location': provider_snapshot.id}
        return model_update

    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""

        provider_snapshot_id = snapshot.get('provider_location',None)
        if not provider_snapshot_id:
            LOG.warning('snapshot has no provider_location')
            return

        provider_snapshots = self.adpter.list_snapshots(snapshot_ids=[provider_snapshot_id])
        if not provider_snapshots:
            LOG.warning('provider_snapshot %s is not found' % provider_snapshot_id)
            return

        provider_snapshot = provider_snapshots[0]

        delete_ret = self.adpter.destroy_volume_snapshot(provider_snapshot)
        LOG.info("deleted snapshot return%d" % delete_ret)

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        #volume_backend_name = self.adpter.get_volume_backend_name()
        data = {'volume_backend_name': 'AMAZONEC2',
                'storage_protocol': 'LSI Logic SCSI',
                'driver_version': self.VERSION,
                'vendor_name': 'Huawei',
                'total_capacity_gb': 1024,
                'free_capacity_gb': 1024,
                'reserved_percentage': 0}
        return data

    def create_export(self, context, volume):
        """Export the volume."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    def remove_export(self, context, volume):
        """Remove an export for a volume."""
        pass

    def initialize_connection(self, volume, connector):
        """Map a volume to a host."""
        LOG.info("attach volume: %s; provider_location: %s " % (volume['id'],
                                                                volume['provider_location']))
        properties = {'volume_id': volume['id'],
                      'provider_location': volume['provider_location']}
        LOG.info("initialize_connection success. Return data: %s."
                 % properties)
        return {'driver_volume_type': 'provider_volume', 'data': properties}

    def terminate_connection(self, volume, connector, **kwargs):
        pass

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        if not os.path.exists(self.configuration.provider_image_conversion_dir):
            fileutils.ensure_tree(self.configuration.provider_image_conversion_dir)
        provider_volume_id = self._get_provider_volumeid_from_volume(volume)
        task_ret = self.adpter.export_volume(provider_volume_id,
                                             self.configuration.provider_image_conversion_dir,
                                             str(image_meta['id']),
                                             cgw_host_id=self.configuration.cgw_host_id,
                                             cgw_host_ip=self.configuration.cgw_host_ip,
                                             cgw_username=self.configuration.cgw_username,
                                             cgw_certificate=self.configuration.cgw_certificate,
                                             transfer_station=self.configuration.storage_tmp_dir)
        if not task_ret:
            raise exception_ex.ProviderExportVolumeError
        temp_path = os.path.join(self.configuration.provider_image_conversion_dir, str(image_meta['id']))
        upload_image = temp_path

        try:
            image_utils.upload_volume(context, image_service, image_meta,
                                      upload_image)
        finally:
            fileutils.delete_if_exists(upload_image)

    def copy_image_to_volume(self, context, volume, image_service, image_id):
        pass

    def validate_connector(self, connector):
        """Fail if connector doesn't contain all the data needed by driver."""
        pass

    def clone_image(self, volume, image_location, image_id, image_meta):
        """Create a volume efficiently from an existing image.

        image_location is a string whose format depends on the
        image service backend in use. The driver should use it
        to determine whether cloning is possible.

        image_id is a string which represents id of the image.
        It can be used by the driver to introspect internal
        stores or registry to do an efficient image clone.

        image_meta is a dictionary that includes 'disk_format' (e.g.
        raw, qcow2) and other image attributes that allow drivers to
        decide whether they can clone the image without first requiring
        conversion.

        Returns a dict of volume properties eg. provider_location,
        boolean indicating whether cloning occurred
        """
        return {'provider_location': None}, True