"""
Volume Drivers for aws storage arrays.

"""
import time
from cinder.i18n import _
from cinder import exception
from cinder.openstack.common import log as logging
from cinder.volume import driver
from py4j.java_gateway import JavaGateway

LOG = logging.getLogger(__name__)


class StorageGatewayIscsiDriver(driver.ISCSIDriver):

    aws_sg = None
    VERSION = "1.0"

    def __init__(self, *args, **kwargs):
        super(StorageGatewayIscsiDriver, self).__init__(*args, **kwargs)
        self.aws_sg = JavaGateway().entry_point

    def do_setup(self, context):
        """Instantiate common class and log in storage system."""
        pass

    def check_for_setup_error(self):
        """Check configuration file."""
        pass

    def create_volume(self, volume):
        """Create a volume."""
        volume_size = long(volume['size']) * 1024 * 1024 * 1024
        volume_arn = self.aws_sg.createVolume(volume['name'], volume_size)
        LOG.info("volume:%s, volume arn:%s" % (volume['name'], volume_arn))
        return {'provider_location': volume_arn}

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
        if hasattr(volume, 'provider_location'):
            volume_arn = snapshot['provider_location']
            if volume_arn:
                self.aws_sg.deleteVolume(volume_arn)


    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        volume_name = snapshot.get('volume_id')
        snapshot_id = snapshot.get('id')
        snapshot_name = snapshot.get('display_name')
        snapshot_description = snapshot_id + snapshot_name
        status = 'pending'
        snapshot_arn = self.aws_sg.createSnapshot(volume_name,snapshot_description)
        while status == 'pending':
            time.sleep(10)
            status = self.aws_sg.getSnapshotStatus(snapshot_arn)
        if status == 'completed':
            return {'provider_location': snapshot_arn}
        else:
            raise exception.VolumeBackend(_('Failed to create snapshot %s'),snapshot_id)

    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        if hasattr(snapshot, 'provider_location'):
            snapshot_arn = snapshot['provider_location']
            if snapshot_arn:
                self.aws_sg.deleteSnapshot(snapshot_arn)

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        backend_name = self.configuration.safe_get('volume_backend_name')
        data = {}
        data['volume_backend_name'] = backend_name
        data['storage_protocol'] = 'iSCSI'
        data['driver_version'] = self.VERSION
        data['vendor_name'] = 'Huawei'
        # TODO: get from sg
        data['total_capacity_gb'] = 1000
        data['free_capacity_gb'] = 1000
        data['reserved_percentage'] = 0
        return data

    def initialize_connection(self, volume, connector):
        """Map a volume to a host."""
        LOG.info("attach volume: %s; arn: %s " % (volume['id'], volume['provider_location']))
        target = JavaGateway().jvm.java.util.HashMap()
        target = self.aws_sg.decribeVolume(volume['provider_location'])
        properties = {}
        properties['target_discovered'] = False
        properties['target_portal'] = ('%s:%s' % (target['ip'], '3260'))
        properties['target_iqn'] = target['iqn']
        properties['volume_id'] = volume['id']

        LOG.info("initialize_connection_iscsi success. Return data: %s."
                 % properties)
        return {'driver_volume_type': 'iscsi', 'data': properties}

    def terminate_connection(self, volume, connector, **kwargs):
        pass

    def create_export(self, context, volume):
        """Export the volume."""
        pass

    def ensure_export(self, context, volume):
        """Synchronously recreate an export for a volume."""
        pass

    def remove_export(self, context, volume):
        """Remove an export for a volume."""
        pass
