"""
Volume Drivers for aws storage arrays.

"""
from py4j.java_gateway import JavaGateway, GatewayClient
import time
from cinder.i18n import _
from cinder import exception
from cinder.openstack.common import log as logging
from cinder.volume import driver
from py4j.java_gateway import JavaGateway

LOG = logging.getLogger(__name__)


class EC2VolumeDriver(driver.ISCSIDriver):
    ec2 = None
    VERSION = "1.0"

    def __init__(self, *args, **kwargs):
        super(EC2VolumeDriver, self).__init__(*args, **kwargs)
        self.ec2 = JavaGateway(GatewayClient(port=25535)).entry_point

    def do_setup(self, context):
        """Instantiate common class and log in storage system."""
        pass

    def check_for_setup_error(self):
        """Check configuration file."""
        pass

    def create_volume(self, volume):
        ec2_volume_id = self.ec2.createVolume(volume['id'],
                                              volume['size'])
        LOG.info("create volume: %s; arn: %s " % (volume['id'],
                                                  ec2_volume_id))
        model_update = {'provider_location': ec2_volume_id}
        return model_update

    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume."""
        pass

    def extend_volume(self, volume, new_size):
        """Extend a volume."""
        pass

    def delete_volume(self, volume):
        """Delete a volume."""
        if hasattr(volume, 'id') and volume['id']:
            ec2_volume_id = self.ec2.getVolumeIdFromName(volume['id'])
            if ec2_volume_id != 'None':
                self.ec2.deleteVolume(ec2_volume_id)
                LOG.info("deleted volume %s" % volume['id'])

    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        pass

    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        pass

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        data = {'volume_backend_name': "EC2",
                'storage_protocol': 'LSI Logic SCSI',
                'driver_version': self.VERSION,
                'vendor_name': 'Huawei',
                'total_capacity_gb': 1000,
                'free_capacity_gb': 1000,
                'reserved_percentage': 0}
        # TODO: get from ec2
        return data

    def initialize_connection(self, volume, connector):
        """Map a volume to a host."""
        LOG.info("attach volume: %s; arn: %s " % (volume['id'],
                                                  volume['provider_location']))
        properties = {'volume_id': volume['id'],
                      'remote_id': volume['provider_location']}
        LOG.info("initialize_connection success. Return data: %s."
                 % properties)
        return {'driver_volume_type': 'ec2volume', 'data': properties}

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

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot."""
        snapshot_id = snapshot.get('id')
        volume_id = volume.get('id')
        ec2_volume_id = self.ec2.createVolumeFromSnapshot(snapshot_id, volume_id)
        model_update = {'provider_location': ec2_volume_id}
        return model_update

    def validate_connector(self, connector):
        """Fail if connector doesn't contain all the data needed by driver."""
        LOG.debug('ec2volume Driver: validate_connector')
        pass

