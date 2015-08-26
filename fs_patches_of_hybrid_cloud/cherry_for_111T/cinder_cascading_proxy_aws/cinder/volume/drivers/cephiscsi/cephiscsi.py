"""
Volume Drivers for aws storage arrays.

"""
import time
from cinder.i18n import _
from cinder import exception
from cinder.openstack.common import log as logging
from cinder.volume import driver
from oslo.config import cfg
import cinder.context
import io
import subprocess
import math
from cinder.openstack.common import units
from cinder.openstack.common import strutils
try:
    import rados
    import rbd
except ImportError:
    rados = None
    rbd = None


LOG = logging.getLogger(__name__)

rbd_opts = [
    cfg.StrOpt('rbd_pool',
               default='rbd',
               help='The RADOS pool where rbd volumes are stored'),
    cfg.StrOpt('rbd_user',
               default=None,
               help='The RADOS client name for accessing rbd volumes '
                    '- only set when using cephx authentication'),
    cfg.StrOpt('rbd_ceph_conf',
               default='',  # default determined by librados
               help='Path to the ceph configuration file'),
    cfg.BoolOpt('rbd_flatten_volume_from_snapshot',
                default=False,
                help='Flatten volumes created from snapshots to remove '
                     'dependency from volume to snapshot'),
    cfg.StrOpt('rbd_secret_uuid',
               default=None,
               help='The libvirt uuid of the secret for the rbd_user '
                    'volumes'),
    cfg.StrOpt('volume_tmp_dir',
               default=None,
               help='Directory where temporary image files are stored '
                    'when the volume driver does not write them directly '
                    'to the volume.'),
    cfg.IntOpt('rbd_max_clone_depth',
               default=5,
               help='Maximum number of nested volume clones that are '
                    'taken before a flatten occurs. Set to 0 to disable '
                    'cloning.'),
    cfg.IntOpt('rbd_store_chunk_size', default=4,
               help=_('Volumes will be chunked into objects of this size '
                      '(in megabytes).')),
    cfg.IntOpt('rados_connect_timeout', default=-1,
               help=_('Timeout value (in seconds) used when connecting to '
                      'ceph cluster. If value < 0, no timeout is set and '
                      'default librados value is used.'))
]

ceph_iscsi_opts = [
    cfg.StrOpt('iscsi_server_ip',
               default='',
               help=''),
    cfg.StrOpt('iscsi_server_user',
               default='',
               help=''),
    cfg.StrOpt('iscsi_server_pem',
               default='',
               help='')

]

CONF = cfg.CONF
CONF.register_opts(rbd_opts)
CONF.register_opts(ceph_iscsi_opts)
IMAGE_SCAN_ATTEMPTS_DEFAULT = 5
class RBDImageMetadata(object):
    """RBD image metadata to be used with RBDImageIOWrapper."""
    def __init__(self, image, pool, user, conf):
        self.image = image
        self.pool = strutils.safe_encode(pool)
        self.user = strutils.safe_encode(user)
        self.conf = strutils.safe_encode(conf)


class RBDImageIOWrapper(io.RawIOBase):
    """Enables LibRBD.Image objects to be treated as Python IO objects.

    Calling unimplemented interfaces will raise IOError.
    """

    def __init__(self, rbd_meta):
        super(RBDImageIOWrapper, self).__init__()
        self._rbd_meta = rbd_meta
        self._offset = 0

    def _inc_offset(self, length):
        self._offset += length

    @property
    def rbd_image(self):
        return self._rbd_meta.image

    @property
    def rbd_user(self):
        return self._rbd_meta.user

    @property
    def rbd_pool(self):
        return self._rbd_meta.pool

    @property
    def rbd_conf(self):
        return self._rbd_meta.conf

    def read(self, length=None):
        offset = self._offset
        total = self._rbd_meta.image.size()

        # NOTE(dosaboy): posix files do not barf if you read beyond their
        # length (they just return nothing) but rbd images do so we need to
        # return empty string if we have reached the end of the image.
        if (offset >= total):
            return ''

        if length is None:
            length = total

        if (offset + length) > total:
            length = total - offset

        self._inc_offset(length)
        return self._rbd_meta.image.read(int(offset), int(length))

    def write(self, data):
        self._rbd_meta.image.write(data, self._offset)
        self._inc_offset(len(data))

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        if whence == 0:
            new_offset = offset
        elif whence == 1:
            new_offset = self._offset + offset
        elif whence == 2:
            new_offset = self._rbd_meta.image.size()
            new_offset += offset
        else:
            raise IOError(_("Invalid argument - whence=%s not supported") %
                          (whence))

        if (new_offset < 0):
            raise IOError(_("Invalid argument"))

        self._offset = new_offset

    def tell(self):
        return self._offset

    def flush(self):
        try:
            self._rbd_meta.image.flush()
        except AttributeError:
            LOG.warning(_("flush() not supported in this version of librbd"))

    def fileno(self):
        """RBD does not have support for fileno() so we raise IOError.

        Raising IOError is recommended way to notify caller that interface is
        not supported - see http://docs.python.org/2/library/io.html#io.IOBase
        """
        raise IOError(_("fileno() not supported by RBD()"))

    # NOTE(dosaboy): if IO object is not closed explicitly, Python auto closes
    # it which, if this is not overridden, calls flush() prior to close which
    # in this case is unwanted since the rbd image may have been closed prior
    # to the autoclean - currently triggering a segfault in librbd.
    def close(self):
        pass

class RBDVolumeProxy(object):
    """Context manager for dealing with an existing rbd volume.

    This handles connecting to rados and opening an ioctx automatically, and
    otherwise acts like a librbd Image object.

    The underlying librados client and ioctx can be accessed as the attributes
    'client' and 'ioctx'.
    """
    def __init__(self, driver, name, pool=None, snapshot=None,
                 read_only=False):
        client, ioctx = driver._connect_to_rados(pool)
        if snapshot is not None:
            snapshot = strutils.safe_encode(snapshot)

        try:
            self.volume = driver.rbd.Image(ioctx, strutils.safe_encode(name),
                                           snapshot=snapshot,
                                           read_only=read_only)
        except driver.rbd.Error:
            LOG.exception(_("error opening rbd image %s"), name)
            driver._disconnect_from_rados(client, ioctx)
            raise
        self.driver = driver
        self.client = client
        self.ioctx = ioctx

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        try:
            self.volume.close()
        finally:
            self.driver._disconnect_from_rados(self.client, self.ioctx)

    def __getattr__(self, attrib):
        return getattr(self.volume, attrib)

class RADOSClient(object):
    """Context manager to simplify error handling for connecting to ceph."""
    def __init__(self, driver, pool=None):
        self.driver = driver
        self.cluster, self.ioctx = driver._connect_to_rados(pool)

    def __enter__(self):
        return self

    def __exit__(self, type_, value, traceback):
        self.driver._disconnect_from_rados(self.cluster, self.ioctx)

class CephIscsiDriver(driver.ISCSIDriver):

    VERSION = "1.0"

    def __init__(self, *args, **kwargs):
        super(CephIscsiDriver, self).__init__(*args, **kwargs)
        self.configuration.append_config_values(rbd_opts)
        self.configuration.append_config_values(ceph_iscsi_opts)
        self.rados = kwargs.get('rados', rados)
        self.rbd = kwargs.get('rbd', rbd)
        self._stats = {}
        self.image_scan_attempts = IMAGE_SCAN_ATTEMPTS_DEFAULT
        for attr in ['rbd_user', 'rbd_ceph_conf', 'rbd_pool']:
            val = getattr(self.configuration, attr)
            if val is not None:
                setattr(self.configuration, attr, strutils.safe_encode(val))

    def _connect_to_rados(self, pool=None):
        LOG.debug("opening connection to ceph cluster (timeout=%s)." %
                  (self.configuration.rados_connect_timeout))

        client = self.rados.Rados(rados_id=self.configuration.rbd_user,
                                  conffile=self.configuration.rbd_ceph_conf)
        if pool is not None:
            pool = strutils.safe_encode(pool)
        else:
            pool = self.configuration.rbd_pool

        try:
            if self.configuration.rados_connect_timeout >= 0:
                client.connect(timeout=
                               self.configuration.rados_connect_timeout)
            else:
                client.connect()
            ioctx = client.open_ioctx(pool)
            return client, ioctx
        except self.rados.Error as exc:
            LOG.error("error connecting to ceph cluster.")
            # shutdown cannot raise an exception
            client.shutdown()
            raise exception.VolumeBackendAPIException(data=str(exc))

    def _delete_backup_snaps(self, rbd_image):
        backup_snaps = self._get_backup_snaps(rbd_image)
        if backup_snaps:
            for snap in backup_snaps:
                rbd_image.remove_snap(snap['name'])
        else:
            LOG.debug("volume has no backup snaps")

    def _get_backup_snaps(self, rbd_image):
        """Get list of any backup snapshots that exist on this volume.

        There should only ever be one but accept all since they need to be
        deleted before the volume can be.
        """
        # NOTE(dosaboy): we do the import here otherwise we get import conflict
        # issues between the rbd driver and the ceph backup driver. These
        # issues only seem to occur when NOT using them together and are
        # triggered when the ceph backup driver imports the rbd volume driver.
        from cinder.backup.drivers import ceph
        return ceph.CephBackupDriver.get_backup_snaps(rbd_image)

    def _get_clone_info(self, volume, volume_name, snap=None):
        """If volume is a clone, return its parent info.

        Returns a tuple of (pool, parent, snap). A snapshot may optionally be
        provided for the case where a cloned volume has been flattened but it's
        snapshot still depends on the parent.
        """
        try:
            snap and volume.set_snap(snap)
            pool, parent, parent_snap = tuple(volume.parent_info())
            snap and volume.set_snap(None)
            # Strip the tag off the end of the volume name since it will not be
            # in the snap name.
            if volume_name.endswith('.deleted'):
                volume_name = volume_name[:-len('.deleted')]
            # Now check the snap name matches.
            if parent_snap == "%s.clone_snap" % volume_name:
                return pool, parent, parent_snap
        except self.rbd.ImageNotFound:
            LOG.debug("volume %s is not a clone" % volume_name)
            volume.set_snap(None)

        return (None, None, None)

    def _disconnect_from_rados(self, client, ioctx):
        # closing an ioctx cannot raise an exception
        ioctx.close()
        client.shutdown()

    def _delete_clone_parent_refs(self, client, parent_name, parent_snap):
        """Walk back up the clone chain and delete references.

        Deletes references i.e. deleted parent volumes and snapshots.
        """
        parent_rbd = self.rbd.Image(client.ioctx, parent_name)
        parent_has_snaps = False
        try:
            # Check for grandparent
            _pool, g_parent, g_parent_snap = self._get_clone_info(parent_rbd,
                                                                  parent_name,
                                                                  parent_snap)

            LOG.debug("deleting parent snapshot %s" % (parent_snap))
            parent_rbd.unprotect_snap(parent_snap)
            parent_rbd.remove_snap(parent_snap)

            parent_has_snaps = bool(list(parent_rbd.list_snaps()))
        finally:
            parent_rbd.close()

    def _update_volume_stats(self):
        stats = {
            'vendor_name': 'Open Source',
            'driver_version': self.VERSION,
            'storage_protocol': 'iSCSI',
            'total_capacity_gb': 'unknown',
            'free_capacity_gb': 'unknown',
            'reserved_percentage': 0,
        }
        backend_name = self.configuration.safe_get('volume_backend_name')
        stats['volume_backend_name'] = backend_name

        try:
            with RADOSClient(self) as client:
                new_stats = client.cluster.get_cluster_stats()
            stats['total_capacity_gb'] = new_stats['kb'] / units.Mi
            stats['free_capacity_gb'] = new_stats['kb_avail'] / units.Mi
        except self.rados.Error:
            # just log and return unknown capacities
            LOG.exception(_('error refreshing volume stats'))
        self._stats = stats

    def _supports_layering(self):
        return hasattr(self.rbd, 'RBD_FEATURE_LAYERING')

    def backup_volume(self, context, backup, backup_service):
        """Create a new backup from an existing volume."""
        backup_des = backup.get('display_description', None)
        if backup_des.find('cross_az') >= 0:
            return
        volume = self.db.volume_get(context, backup['volume_id'])

        with RBDVolumeProxy(self, volume['name'],
                            self.configuration.rbd_pool) as rbd_image:
            rbd_meta = RBDImageMetadata(rbd_image, self.configuration.rbd_pool,
                                        self.configuration.rbd_user,
                                        self.configuration.rbd_ceph_conf)
            rbd_fd = RBDImageIOWrapper(rbd_meta)
            backup_service.backup(backup, rbd_fd)

        LOG.debug("volume backup complete.")

    def restore_backup(self, context, backup, volume, backup_service):
        """Restore an existing backup to a new or existing volume."""
        backup_des = backup.get('display_description', None)
        if backup_des and 'cross_az' in backup_des:
            res = backup_des.split(':')
            backup['volume_id'] = res[-1]
            backup['id'] = res[-2]
        LOG.info(_("ceph iscsi driver, got backup_id:%(backup_id)s,"
                   "%(source_volume_id)s, backup_des:%(backup_des)s") %
                 {'backup_id': backup['id'],
                  'source_volume_id': backup['volume_id'],
                  'backup_des': backup_des})

        with RBDVolumeProxy(self, volume['name'],
                            self.configuration.rbd_pool) as rbd_image:
            rbd_meta = RBDImageMetadata(rbd_image, self.configuration.rbd_pool,
                                        self.configuration.rbd_user,
                                        self.configuration.rbd_ceph_conf)
            rbd_fd = RBDImageIOWrapper(rbd_meta)
            backup_service.restore(backup, volume['id'], rbd_fd)

        LOG.debug("volume restore complete.")
    def do_setup(self, context):
        """Instantiate common class and log in storage system."""
        pass

    def check_for_setup_error(self):
        """Check configuration file."""
        pass

    def create_volume(self, volume):
        """Create a volume."""
        ctx = cinder.context.get_admin_context()
        if ctx:
            volume_metadata = self.db.volume_metadata_get(ctx, volume['id'])
            if volume_metadata:
                identify_flag = volume_metadata.get('cross_az', None)
                if identify_flag:
                    model_update = {'provider_location': 'fake_flag'}
                    return model_update
        if int(volume['size']) == 0:
            size = 100 * units.Mi
        else:
            size = int(volume['size']) * units.Gi

        LOG.debug("creating volume '%s'" % (volume['name']))

        old_format = True
        features = 0
        chunk_size = CONF.rbd_store_chunk_size * units.Mi
        order = int(math.log(chunk_size, 2))
        if self._supports_layering():
            old_format = False
            features = self.rbd.RBD_FEATURE_LAYERING

        with RADOSClient(self) as client:
            self.rbd.RBD().create(client.ioctx,
                                  strutils.safe_encode(volume['name']),
                                  size,
                                  order,
                                  old_format=old_format,
                                  features=features)
        if self.image_found(volume['name']):
            command = "ssh -i %s %s@%s sudo bash /home/%s/ceph_iscsi.sh %s %s %s" % \
                      (self.configuration.iscsi_server_pem,
                       self.configuration.iscsi_server_user,
                       self.configuration.iscsi_server_ip,
                       self.configuration.iscsi_server_user,
                       'create', self.configuration.rbd_pool, volume['name'])
            result = subprocess.call([command], shell=True)
            if result != 0:
                LOG.debug("create iscsi target failed '%s'" % (volume['id']))
        else:
            LOG.debug("can not find rbd image,create failed")

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
        """Deletes a logical volume."""
        # NOTE(dosaboy): this was broken by commit cbe1d5f. Ensure names are
        #                utf-8 otherwise librbd will barf.
        if 'fake_flag' == volume.get('provider_location', None):
            return
        volume_name = strutils.safe_encode(volume['name'])
        with RADOSClient(self) as client:
            try:
                rbd_image = self.rbd.Image(client.ioctx, volume_name)
            except self.rbd.ImageNotFound:
                LOG.info(_("volume %s no longer exists in backend")
                         % (volume_name))
                return

            clone_snap = None
            parent = None

            # Ensure any backup snapshots are deleted
            self._delete_backup_snaps(rbd_image)

            # If the volume has non-clone snapshots this delete is expected to
            # raise VolumeIsBusy so do so straight away.
            try:
                snaps = rbd_image.list_snaps()
                for snap in snaps:
                    if snap['name'].endswith('.clone_snap'):
                        LOG.debug("volume has clone snapshot(s)")
                        # We grab one of these and use it when fetching parent
                        # info in case the volume has been flattened.
                        clone_snap = snap['name']
                        break

                    raise exception.VolumeIsBusy(volume_name=volume_name)

                # Determine if this volume is itself a clone
                pool, parent, parent_snap = self._get_clone_info(rbd_image,
                                                                 volume_name,
                                                                 clone_snap)
            finally:
                rbd_image.close()

            if clone_snap is None:
                LOG.debug("deleting rbd volume %s" % (volume_name))
                try:
                    self.rbd.RBD().remove(client.ioctx, volume_name)
                except self.rbd.ImageBusy:
                    msg = (_("ImageBusy error raised while deleting rbd "
                             "volume. This may have been caused by a "
                             "connection from a client that has crashed and, "
                             "if so, may be resolved by retrying the delete "
                             "after 30 seconds has elapsed."))
                    LOG.warn(msg)
                    # Now raise this so that volume stays available so that we
                    # delete can be retried.
                    raise exception.VolumeIsBusy(msg, volume_name=volume_name)

                # If it is a clone, walk back up the parent chain deleting
                # references.
                if parent:
                    LOG.debug("volume is a clone so cleaning references")
                    self._delete_clone_parent_refs(client, parent, parent_snap)
            else:
                # If the volume has copy-on-write clones we will not be able to
                # delete it. Instead we will keep it as a silent volume which
                # will be deleted when it's snapshot and clones are deleted.
                new_name = "%s.deleted" % (volume_name)
                self.rbd.RBD().rename(client.ioctx, volume_name, new_name)
        command = "ssh -i %s %s@%s sudo bash /home/%s/ceph_iscsi.sh %s %s %s" % \
                  (self.configuration.iscsi_server_pem,
                   self.configuration.iscsi_server_user,
                   self.configuration.iscsi_server_ip,
                   self.configuration.iscsi_server_user,
                   'delete', self.configuration.rbd_pool, volume['name'])
        result = subprocess.call([command], shell=True)
        if result != 0:
            LOG.debug("delete iscsi target failed '%s'" % (volume['id']))

    def create_snapshot(self, snapshot):
        """Create a snapshot."""
        pass

    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        pass

    def get_volume_stats(self, refresh=False):
        """Get volume stats."""
        self._update_volume_stats()
        return self._stats

    def image_found(self, image_name):
        try_count = 0
        while try_count < self.image_scan_attempts:
            image_list = self.rbd.RBD().list(RADOSClient(self).ioctx)
            for image in image_list:
                if image == image_name:
                    return True
            try_count = try_count + 1
            time.sleep(try_count ** 2)
        return False

    def initialize_connection(self, volume, connector):
        """Map a volume to a host."""
        LOG.info("attach volume: %s; voluem_name: %s " % (volume['id'], volume['name']))
        properties = {}
        properties['target_discovered'] = False
        properties['target_portal'] = ('%s:%s' % (self.configuration.iscsi_server_ip, '3260'))
        properties['target_iqn'] = 'iqn.2015-08.rbdstore.' + volume['name'] + '.com:iscsi'
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
