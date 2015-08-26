# Copyright (C) 2012 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
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
Backup manager manages volume backups.

Volume Backups are full copies of persistent volumes stored in a backup
store e.g. an object store or any other backup store if and when support is
added. They are usable without the original object being available. A
volume backup can be restored to the original volume it was created from or
any other available volume with a minimum size of the original volume.
Volume backups can be created, restored, deleted and listed.

**Related Flags**

:backup_topic:  What :mod:`rpc` topic to listen to (default:
                        `cinder-backup`).
:backup_manager:  The module name of a class derived from
                          :class:`manager.Manager` (default:
                          :class:`cinder.backup.manager.Manager`).

"""

from oslo.config import cfg
from oslo import messaging

from cinder.backup import driver
from cinder.backup import rpcapi as backup_rpcapi
from cinder import context
from cinder import exception
from cinder.i18n import _
from cinder import manager
from cinder.openstack.common import excutils
from cinder.openstack.common import importutils
from cinder.openstack.common import log as logging
from cinder import quota
from cinder import rpc
from cinder import utils
from cinder.volume import utils as volume_utils

LOG = logging.getLogger(__name__)

backup_manager_opts = [
    cfg.StrOpt('backup_driver',
               default='cinder.backup.drivers.swift',
               help='Driver to use for backups.',
               deprecated_name='backup_service'),
]

# This map doesn't need to be extended in the future since it's only
# for old backup services
mapper = {'cinder.backup.services.swift': 'cinder.backup.drivers.swift',
          'cinder.backup.services.ceph': 'cinder.backup.drivers.ceph'}

CONF = cfg.CONF
CONF.register_opts(backup_manager_opts)
QUOTAS = quota.QUOTAS


class BackupManager(manager.SchedulerDependentManager):
    """Manages backup of block storage devices."""

    RPC_API_VERSION = '1.0'

    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, service_name=None, *args, **kwargs):
        self.service = importutils.import_module(self.driver_name)
        self.az = CONF.storage_availability_zone
        self.volume_managers = {}
        self._setup_volume_drivers()
        self.backup_rpcapi = backup_rpcapi.BackupAPI()
        super(BackupManager, self).__init__(service_name='backup',
                                            *args, **kwargs)

    @property
    def driver_name(self):
        """This function maps old backup services to backup drivers."""

        return self._map_service_to_driver(CONF.backup_driver)

    def _map_service_to_driver(self, service):
        """Maps services to drivers."""

        if service in mapper:
            return mapper[service]
        return service

    @property
    def driver(self):
        return self._get_driver()

    def _get_volume_backend(self, host=None, allow_null_host=False):
        if host is None:
            if not allow_null_host:
                msg = _("NULL host not allowed for volume backend lookup.")
                raise exception.BackupFailedToGetVolumeBackend(msg)
        else:
            LOG.debug("Checking hostname '%s' for backend info." % (host))
            part = host.partition('@')
            if (part[1] == '@') and (part[2] != ''):
                backend = part[2]
                LOG.debug("Got backend '%s'." % (backend))
                return backend

        LOG.info(_("Backend not found in hostname (%s) so using default.") %
                 (host))

        if 'default' not in self.volume_managers:
            # For multi-backend we just pick the top of the list.
            return self.volume_managers.keys()[0]

        return 'default'

    def _get_manager(self, backend):
        LOG.debug("Manager requested for volume_backend '%s'." %
                  (backend))
        if backend is None:
            LOG.debug("Fetching default backend.")
            backend = self._get_volume_backend(allow_null_host=True)
        if backend not in self.volume_managers:
            msg = (_("Volume manager for backend '%s' does not exist.") %
                   (backend))
            raise exception.BackupFailedToGetVolumeBackend(msg)
        return self.volume_managers[backend]

    def _get_driver(self, backend=None):
        LOG.debug("Driver requested for volume_backend '%s'." %
                  (backend))
        if backend is None:
            LOG.debug("Fetching default backend.")
            backend = self._get_volume_backend(allow_null_host=True)
        mgr = self._get_manager(backend)
        mgr.driver.db = self.db
        return mgr.driver

    def _setup_volume_drivers(self):
        if CONF.enabled_backends:
            for backend in CONF.enabled_backends:
                host = "%s@%s" % (CONF.host, backend)
                mgr = importutils.import_object(CONF.volume_manager,
                                                host=host,
                                                service_name=backend)
                config = mgr.configuration
                backend_name = config.safe_get('volume_backend_name')
                LOG.debug("Registering backend %(backend)s (host=%(host)s "
                          "backend_name=%(backend_name)s)." %
                          {'backend': backend, 'host': host,
                           'backend_name': backend_name})
                self.volume_managers[backend] = mgr
        else:
            default = importutils.import_object(CONF.volume_manager)
            LOG.debug("Registering default backend %s." % (default))
            self.volume_managers['default'] = default

    def _init_volume_driver(self, ctxt, driver):
        LOG.info(_("Starting volume driver %(driver_name)s (%(version)s).") %
                 {'driver_name': driver.__class__.__name__,
                  'version': driver.get_version()})
        try:
            driver.do_setup(ctxt)
            driver.check_for_setup_error()
        except Exception as ex:
            LOG.error(_("Error encountered during initialization of driver: "
                        "%(name)s.") %
                      {'name': driver.__class__.__name__})
            LOG.exception(ex)
            # we don't want to continue since we failed
            # to initialize the driver correctly.
            return

        driver.set_initialized()

    def init_host(self):
        """Do any initialization that needs to be run if this is a
           standalone service.
        """
        ctxt = context.get_admin_context()

        for mgr in self.volume_managers.itervalues():
            self._init_volume_driver(ctxt, mgr.driver)
            if mgr.driver.initialized is False:
                return 'INIT_DRIVER_ERROR'
        LOG.info(_("Cleaning up incomplete backup operations."))
        volumes = self.db.volume_get_all_by_host(ctxt, self.host)
        for volume in volumes:
            volume_host = volume_utils.extract_host(volume['host'], 'backend')
            backend = self._get_volume_backend(host=volume_host)
            if volume['status'] == 'backing-up':
                LOG.info(_('Resetting volume %s to available '
                           '(was backing-up).') % volume['id'])
                mgr = self._get_manager(backend)
                mgr.detach_volume(ctxt, volume['id'])
            if volume['status'] == 'restoring-backup':
                LOG.info(_('Resetting volume %s to error_restoring '
                           '(was restoring-backup).') % volume['id'])
                mgr = self._get_manager(backend)
                mgr.detach_volume(ctxt, volume['id'])
                self.db.volume_update(ctxt, volume['id'],
                                      {'status': 'error_restoring'})

        # TODO(smulcahy) implement full resume of backup and restore
        # operations on restart (rather than simply resetting)
        backups = self.db.backup_get_all_by_host(ctxt, self.host)
        for backup in backups:
            if backup['status'] == 'creating':
                LOG.info(_('Resetting backup %s to error (was creating).')
                         % backup['id'])
                err = 'incomplete backup reset on manager restart'
                self.db.backup_update(ctxt, backup['id'], {'status': 'error',
                                                           'fail_reason': err})
            if backup['status'] == 'restoring':
                LOG.info(_('Resetting backup %s to available (was restoring).')
                         % backup['id'])
                self.db.backup_update(ctxt, backup['id'],
                                      {'status': 'available'})
            if backup['status'] == 'deleting':
                LOG.info(_('Resuming delete on backup: %s.') % backup['id'])
                self.delete_backup(ctxt, backup['id'])

    def create_backup(self, context, backup_id):
        """Create volume backups using configured backup service."""
        backup = self.db.backup_get(context, backup_id)
        volume_id = backup['volume_id']

        # Because volume could be available or in-use
        initial_vol_status = self.db.volume_get(context, volume_id)['status']
        self.db.volume_update(context, volume_id, {'status': 'backing-up'})

        volume = self.db.volume_get(context, volume_id)

        LOG.info(_('Create backup started, backup: %(backup_id)s '
                   'volume: %(volume_id)s.') %
                 {'backup_id': backup_id, 'volume_id': volume_id})
        volume_host = volume_utils.extract_host(volume['host'], 'backend')
        backend = self._get_volume_backend(host=volume_host)

        self.db.backup_update(context, backup_id, {'host': self.host,
                                                   'service':
                                                   self.driver_name})

        expected_status = 'backing-up'
        actual_status = volume['status']
        if actual_status != expected_status:
            err = _('Create backup aborted, expected volume status '
                    '%(expected_status)s but got %(actual_status)s.') % {
                'expected_status': expected_status,
                'actual_status': actual_status,
            }
            self.db.backup_update(context, backup_id, {'status': 'error',
                                                       'fail_reason': err})
            raise exception.InvalidVolume(reason=err)

        expected_status = 'creating'
        actual_status = backup['status']
        if actual_status != expected_status:
            err = _('Create backup aborted, expected backup status '
                    '%(expected_status)s but got %(actual_status)s.') % {
                'expected_status': expected_status,
                'actual_status': actual_status,
            }
            self.db.volume_update(context, volume_id, {'status': initial_vol_status})
            self.db.backup_update(context, backup_id, {'status': 'error',
                                                       'fail_reason': err})
            raise exception.InvalidBackup(reason=err)

        try:
            # NOTE(flaper87): Verify the driver is enabled
            # before going forward. The exception will be caught,
            # the volume status will be set back to available and
            # the backup status to 'error'
            utils.require_driver_initialized(self.driver)

            backup_service = self.service.get_backup_driver(context)
            self._get_driver(backend).backup_volume(context, backup,
                                                    backup_service)
        except Exception as err:
            with excutils.save_and_reraise_exception():
                self.db.volume_update(context, volume_id,
                                      {'status': initial_vol_status})
                self.db.backup_update(context, backup_id,
                                      {'status': 'error',
                                       'fail_reason': unicode(err)})

        self.db.volume_update(context, volume_id, {'status': initial_vol_status})
        self.db.backup_update(context, backup_id, {'status': 'available',
                                                   'size': volume['size'],
                                                   'availability_zone':
                                                   self.az})
        LOG.info(_('Create backup finished. backup: %s.'), backup_id)

    def restore_backup(self, context, backup_id, volume_id):
        """Restore volume backups from configured backup service."""
        LOG.info(_('Restore backup started, backup: %(backup_id)s '
                   'volume: %(volume_id)s.') %
                 {'backup_id': backup_id, 'volume_id': volume_id})

        backup = self.db.backup_get(context, backup_id)
        volume = self.db.volume_get(context, volume_id)
        volume_host = volume_utils.extract_host(volume['host'], 'backend')
        backend = self._get_volume_backend(host=volume_host)

        self.db.backup_update(context, backup_id, {'host': self.host})
        LOG.info(_('Restore backup, backup_id:%s, description:%s') %
                 (backup_id, backup['display_description']))

        expected_status = 'restoring-backup'
        actual_status = volume['status']
        if actual_status != expected_status:
            err = (_('Restore backup aborted, expected volume status '
                     '%(expected_status)s but got %(actual_status)s.') %
                   {'expected_status': expected_status,
                    'actual_status': actual_status})
            self.db.backup_update(context, backup_id, {'status': 'available'})
            raise exception.InvalidVolume(reason=err)

        expected_status = 'restoring'
        actual_status = backup['status']
        if actual_status != expected_status:
            err = (_('Restore backup aborted: expected backup status '
                     '%(expected_status)s but got %(actual_status)s.') %
                   {'expected_status': expected_status,
                    'actual_status': actual_status})
            self.db.backup_update(context, backup_id, {'status': 'error',
                                                       'fail_reason': err})
            self.db.volume_update(context, volume_id, {'status': 'error'})
            raise exception.InvalidBackup(reason=err)

        if volume['size'] > backup['size']:
            LOG.info(_('Volume: %(vol_id)s, size: %(vol_size)d is '
                       'larger than backup: %(backup_id)s, '
                       'size: %(backup_size)d, continuing with restore.'),
                     {'vol_id': volume['id'],
                      'vol_size': volume['size'],
                      'backup_id': backup['id'],
                      'backup_size': backup['size']})

        backup_service = self._map_service_to_driver(backup['service'])
        configured_service = self.driver_name
        if backup_service != configured_service:
            err = _('Restore backup aborted, the backup service currently'
                    ' configured [%(configured_service)s] is not the'
                    ' backup service that was used to create this'
                    ' backup [%(backup_service)s].') % {
                'configured_service': configured_service,
                'backup_service': backup_service,
            }
            self.db.backup_update(context, backup_id, {'status': 'available'})
            self.db.volume_update(context, volume_id, {'status': 'error'})
            raise exception.InvalidBackup(reason=err)

        try:
            # NOTE(flaper87): Verify the driver is enabled
            # before going forward. The exception will be caught,
            # the volume status will be set back to available and
            # the backup status to 'error'
            utils.require_driver_initialized(self.driver)

            backup_service = self.service.get_backup_driver(context)
            self._get_driver(backend).restore_backup(context, backup,
                                                     volume,
                                                     backup_service)
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.volume_update(context, volume_id,
                                      {'status': 'error_restoring'})
                self.db.backup_update(context, backup_id,
                                      {'status': 'available'})

        self.db.volume_update(context, volume_id, {'status': 'available'})
        self.db.backup_update(context, backup_id, {'status': 'available'})
        LOG.info(_('Restore backup finished, backup %(backup_id)s restored'
                   ' to volume %(volume_id)s.') %
                 {'backup_id': backup_id, 'volume_id': volume_id})

    def delete_backup(self, context, backup_id):
        """Delete volume backup from configured backup service."""
        try:
            # NOTE(flaper87): Verify the driver is enabled
            # before going forward. The exception will be caught
            # and the backup status updated. Fail early since there
            # are no other status to change but backup's
            utils.require_driver_initialized(self.driver)
        except exception.DriverNotInitialized as err:
            with excutils.save_and_reraise_exception():
                    self.db.backup_update(context, backup_id,
                                          {'status': 'error',
                                           'fail_reason':
                                           unicode(err)})

        LOG.info(_('Delete backup started, backup: %s.'), backup_id)
        backup = self.db.backup_get(context, backup_id)
        self.db.backup_update(context, backup_id, {'host': self.host})

        expected_status = 'deleting'
        actual_status = backup['status']
        if actual_status != expected_status:
            err = _('Delete_backup aborted, expected backup status '
                    '%(expected_status)s but got %(actual_status)s.') \
                % {'expected_status': expected_status,
                   'actual_status': actual_status}
            self.db.backup_update(context, backup_id,
                                  {'status': 'error', 'fail_reason': err})
            raise exception.InvalidBackup(reason=err)

        backup_service = self._map_service_to_driver(backup['service'])
        if backup_service is not None:
            configured_service = self.driver_name
            if backup_service != configured_service:
                err = _('Delete backup aborted, the backup service currently'
                        ' configured [%(configured_service)s] is not the'
                        ' backup service that was used to create this'
                        ' backup [%(backup_service)s].')\
                    % {'configured_service': configured_service,
                       'backup_service': backup_service}
                self.db.backup_update(context, backup_id,
                                      {'status': 'error'})
                raise exception.InvalidBackup(reason=err)

            try:
                backup_service = self.service.get_backup_driver(context)
                backup_service.delete(backup)
            except Exception as err:
                with excutils.save_and_reraise_exception():
                    self.db.backup_update(context, backup_id,
                                          {'status': 'error',
                                           'fail_reason':
                                           unicode(err)})

        # Get reservations
        try:
            reserve_opts = {
                'backups': -1,
                'backup_gigabytes': -backup['size'],
            }
            reservations = QUOTAS.reserve(context,
                                          project_id=backup['project_id'],
                                          **reserve_opts)
        except Exception:
            reservations = None
            LOG.exception(_("Failed to update usages deleting backup"))

        context = context.elevated()
        self.db.backup_destroy(context, backup_id)

        # Commit the reservations
        if reservations:
            QUOTAS.commit(context, reservations,
                          project_id=backup['project_id'])

        LOG.info(_('Delete backup finished, backup %s deleted.'), backup_id)

    def export_record(self, context, backup_id):
        """Export all volume backup metadata details to allow clean import.

        Export backup metadata so it could be re-imported into the database
        without any prerequisite in the backup database.

        :param context: running context
        :param backup_id: backup id to export
        :returns: backup_record - a description of how to import the backup
        :returns: contains 'backup_url' - how to import the backup, and
        :returns: 'backup_service' describing the needed driver.
        :raises: InvalidBackup
        """
        LOG.info(_('Export record started, backup: %s.'), backup_id)

        backup = self.db.backup_get(context, backup_id)

        expected_status = 'available'
        actual_status = backup['status']
        if actual_status != expected_status:
            err = (_('Export backup aborted, expected backup status '
                     '%(expected_status)s but got %(actual_status)s.') %
                   {'expected_status': expected_status,
                    'actual_status': actual_status})
            raise exception.InvalidBackup(reason=err)

        backup_record = {}
        backup_record['backup_service'] = backup['service']
        backup_service = self._map_service_to_driver(backup['service'])
        configured_service = self.driver_name
        if backup_service != configured_service:
            err = (_('Export record aborted, the backup service currently'
                     ' configured [%(configured_service)s] is not the'
                     ' backup service that was used to create this'
                     ' backup [%(backup_service)s].') %
                   {'configured_service': configured_service,
                    'backup_service': backup_service})
            raise exception.InvalidBackup(reason=err)

        # Call driver to create backup description string
        try:
            utils.require_driver_initialized(self.driver)
            backup_service = self.service.get_backup_driver(context)
            backup_url = backup_service.export_record(backup)
            backup_record['backup_url'] = backup_url
        except Exception as err:
            msg = unicode(err)
            raise exception.InvalidBackup(reason=msg)

        LOG.info(_('Export record finished, backup %s exported.'), backup_id)
        return backup_record

    def import_record(self,
                      context,
                      backup_id,
                      backup_service,
                      backup_url,
                      backup_hosts):
        """Import all volume backup metadata details to the backup db.

        :param context: running context
        :param backup_id: The new backup id for the import
        :param backup_service: The needed backup driver for import
        :param backup_url: An identifier string to locate the backup
        :param backup_hosts: Potential hosts to execute the import
        :raises: InvalidBackup
        :raises: ServiceNotFound
        """
        LOG.info(_('Import record started, backup_url: %s.'), backup_url)

        # Can we import this backup?
        if (backup_service != self.driver_name):
            # No, are there additional potential backup hosts in the list?
            if len(backup_hosts) > 0:
                # try the next host on the list, maybe he can import
                first_host = backup_hosts.pop()
                self.backup_rpcapi.import_record(context,
                                                 first_host,
                                                 backup_id,
                                                 backup_service,
                                                 backup_url,
                                                 backup_hosts)
            else:
                # empty list - we are the last host on the list, fail
                err = _('Import record failed, cannot find backup '
                        'service to perform the import. Request service '
                        '%(service)s') % {'service': backup_service}
                self.db.backup_update(context, backup_id, {'status': 'error',
                                                           'fail_reason': err})
                raise exception.ServiceNotFound(service_id=backup_service)
        else:
            # Yes...
            try:
                utils.require_driver_initialized(self.driver)
                backup_service = self.service.get_backup_driver(context)
                backup_options = backup_service.import_record(backup_url)
            except Exception as err:
                msg = unicode(err)
                self.db.backup_update(context,
                                      backup_id,
                                      {'status': 'error',
                                       'fail_reason': msg})
                raise exception.InvalidBackup(reason=msg)

            required_import_options = ['display_name',
                                       'display_description',
                                       'container',
                                       'size',
                                       'service_metadata',
                                       'service',
                                       'object_count']

            backup_update = {}
            backup_update['status'] = 'available'
            backup_update['service'] = self.driver_name
            backup_update['availability_zone'] = self.az
            backup_update['host'] = self.host
            for entry in required_import_options:
                if entry not in backup_options:
                    msg = (_('Backup metadata received from driver for '
                             'import is missing %s.'), entry)
                    self.db.backup_update(context,
                                          backup_id,
                                          {'status': 'error',
                                           'fail_reason': msg})
                    raise exception.InvalidBackup(reason=msg)
                backup_update[entry] = backup_options[entry]
            # Update the database
            self.db.backup_update(context, backup_id, backup_update)

            # Verify backup
            try:
                if isinstance(backup_service, driver.BackupDriverWithVerify):
                    backup_service.verify(backup_id)
                else:
                    LOG.warn(_('Backup service %(service)s does not support '
                               'verify. Backup id %(id)s is not verified. '
                               'Skipping verify.') % {'service':
                                                      self.driver_name,
                                                      'id': backup_id})
            except exception.InvalidBackup as err:
                with excutils.save_and_reraise_exception():
                    self.db.backup_update(context, backup_id,
                                          {'status': 'error',
                                           'fail_reason':
                                           unicode(err)})

            LOG.info(_('Import record id %s metadata from driver '
                       'finished.') % backup_id)

    def reset_status(self, context, backup_id, status):
        """Reset volume backup status.

        :param context: running context
        :param backup_id: The backup id for reset status operation
        :param status: The status to be set
        :raises: InvalidBackup
        :raises: BackupVerifyUnsupportedDriver
        :raises: AttributeError
        """
        LOG.info(_('Reset backup status started, backup_id: '
                   '%(backup_id)s, status: %(status)s.'),
                 {'backup_id': backup_id,
                  'status': status})
        try:
            # NOTE(flaper87): Verify the driver is enabled
            # before going forward. The exception will be caught
            # and the backup status updated. Fail early since there
            # are no other status to change but backup's
            utils.require_driver_initialized(self.driver)
        except exception.DriverNotInitialized:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Backup driver has not been initialized"))

        backup = self.db.backup_get(context, backup_id)
        backup_service = self._map_service_to_driver(backup['service'])
        LOG.info(_('Backup service: %s.'), backup_service)
        if backup_service is not None:
            configured_service = self.driver_name
            if backup_service != configured_service:
                err = _('Reset backup status aborted, the backup service'
                        ' currently configured [%(configured_service)s] '
                        'is not the backup service that was used to create'
                        ' this backup [%(backup_service)s].') % \
                    {'configured_service': configured_service,
                     'backup_service': backup_service}
                raise exception.InvalidBackup(reason=err)
            # Verify backup
            try:
                # check whether the backup is ok or not
                if status == 'available' and backup['status'] != 'restoring':
                    # check whether we could verify the backup is ok or not
                    if isinstance(backup_service,
                                  driver.BackupDriverWithVerify):
                        backup_service.verify(backup_id)
                        self.db.backup_update(context, backup_id,
                                              {'status': status})
                    # driver does not support verify function
                    else:
                        msg = (_('Backup service %(configured_service)s '
                                 'does not support verify. Backup id'
                                 ' %(id)s is not verified. '
                                 'Skipping verify.') %
                               {'configured_service': self.driver_name,
                                'id': backup_id})
                        raise exception.BackupVerifyUnsupportedDriver(
                            reason=msg)
                # reset status to error or from restoring to available
                else:
                    if (status == 'error' or
                        (status == 'available' and
                            backup['status'] == 'restoring')):
                        self.db.backup_update(context, backup_id,
                                              {'status': status})
            except exception.InvalidBackup:
                with excutils.save_and_reraise_exception():
                    msg = (_("Backup id %(id)s is not invalid. "
                             "Skipping reset.") % {'id': backup_id})
                    LOG.error(msg)
            except exception.BackupVerifyUnsupportedDriver:
                with excutils.save_and_reraise_exception():
                    msg = (_('Backup service %(configured_service)s '
                             'does not support verify. Backup id'
                             ' %(id)s is not verified. '
                             'Skipping verify.') %
                           {'configured_service': self.driver_name,
                            'id': backup_id})
                    LOG.error(msg)
            except AttributeError:
                msg = (_('Backup service %(service)s does not support '
                         'verify. Backup id %(id)s is not verified. '
                         'Skipping reset.') %
                       {'service': self.driver_name,
                        'id': backup_id})
                LOG.error(msg)
                raise exception.BackupVerifyUnsupportedDriver(
                    reason=msg)

            # send notification to ceilometer
            notifier_info = {'id': backup_id, 'update': {'status': status}}
            notifier = rpc.get_notifier('backupStatusUpdate')
            notifier.info(context, "backups" + '.reset_status.end',
                          notifier_info)