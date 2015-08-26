# Copyright 2014  Huawei Technologies Co., LTD
# All Rights Reserved.
#
#    @author: Huawei Technologies Co., LTD
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

import time
import datetime

from oslo.config import cfg
from oslo import messaging
from oslo.db import exception as db_exc

from cinder import context
from cinder import exception
from cinder import manager
from cinder import quota
from cinder import utils
from cinder import volume

from cinder.i18n import _
from cinder.openstack.common import excutils
from cinder.openstack.common import log as logging
from cinder.openstack.common import periodic_task
from cinder.openstack.common import timeutils

from cinder.volume.configuration import Configuration
from cinder.volume import utils as volume_utils
from cinderclient.v2 import client as cinder_client

from cinderclient import exceptions as cinder_exception

from eventlet.greenpool import GreenPool
from keystoneclient.v2_0 import client as kc
from keystoneclient import exceptions as keystone_exception

from cinderclient import client as client_cinder


LOG = logging.getLogger(__name__)

QUOTAS = quota.QUOTAS
CGQUOTAS = quota.CGQUOTAS

volume_backup_opts = [
    cfg.IntOpt('migration_create_volume_timeout_secs',
               default=300,
               help='Timeout for creating the volume to migrate to '
                    'when performing volume migration (seconds)'),
    cfg.ListOpt('enabled_volume_types',
                default=None,
                help='A list of volume types to use'),
    cfg.IntOpt('volume_sync_interval',
               default=5,
               help='seconds between cascading and cascaded cinders'
                    'when synchronizing volume data'),
    cfg.IntOpt('voltype_sync_interval',
               default=600,
               help='seconds between cascading and cascaded cinders'
                    'when synchronizing volume type and qos data'),
    cfg.BoolOpt('volume_sync_timestamp_flag',
                default=True,
                help='whether to sync volume status based on timestamp'),
    cfg.BoolOpt('volume_service_inithost_offload',
                default=False,
                help='Offload pending volume delete during '
                     'volume service startup'),
    cfg.StrOpt('cinder_username',
               default='cinder_username',
               help='username for connecting to cinder in admin context'),
    cfg.StrOpt('admin_password',
               default='admin_password',
               help='password for connecting to cinder in admin context',
               secret=True),
    cfg.StrOpt('cinder_tenant_name',
               default='cinder_tenant_name',
               help='tenant name for connecting to cinder in admin context'),
    cfg.StrOpt('cinder_tenant_id',
               default='cinder_tenant_id',
               help='tenant id for connecting to cinder in admin context'),
    cfg.StrOpt('cascaded_available_zone',
               default='nova',
               help='available zone for cascaded OpenStack'),
    cfg.StrOpt('keystone_auth_url',
               default='http://127.0.0.1:5000/v2.0/',
               help='value of keystone url'),
    cfg.StrOpt('cascaded_cinder_url',
               default='http://127.0.0.1:8776/v2/%(project_id)s',
               help='value of cascaded cinder url'),
    cfg.StrOpt('cascading_cinder_url',
               default='http://127.0.0.1:8776/v2/%(project_id)s',
               help='value of cascading cinder url'),
    cfg.StrOpt('cascaded_region_name',
               default='RegionOne',
               help='Region name of this node'),
]
CONF = cfg.CONF
CONF.register_opts(volume_backup_opts)


def locked_volume_operation(f):
    """Lock decorator for volume operations.

    Takes a named lock prior to executing the operation. The lock is named with
    the operation executed and the id of the volume. This lock can then be used
    by other operations to avoid operation conflicts on shared volumes.

    Example use:

    If a volume operation uses this decorator, it will block until the named
    lock is free. This is used to protect concurrent operations on the same
    volume e.g. delete VolA while create volume VolB from VolA is in progress.
    """
    def lvo_inner1(inst, context, volume_id, **kwargs):
        @utils.synchronized("%s-%s" % (volume_id, f.__name__), external=True)
        def lvo_inner2(*_args, **_kwargs):
            return f(*_args, **_kwargs)
        return lvo_inner2(inst, context, volume_id, **kwargs)
    return lvo_inner1


def locked_backup_operation(f):
    """Lock decorator for backup operations.

    Takes a named lock prior to executing the operation. The lock is named with
    the operation executed and the id of the snapshot. This lock can then be
    used by other operations to avoid operation conflicts on shared snapshots.

    Example use:

    If a snapshot operation uses this decorator, it will block until the named
    lock is free. This is used to protect concurrent operations on the same
    snapshot e.g. delete SnapA while create volume VolA from SnapA is in
    progress.
    """
    def lso_inner1(inst, context, backup_id, **kwargs):
        @utils.synchronized("%s-%s" % (backup_id, f.__name__), external=True)
        def lso_inner2(*_args, **_kwargs):
            return f(*_args, **_kwargs)
        return lso_inner2(inst, context, backup_id, **kwargs)
    return lso_inner1


class CinderBackupProxy(manager.SchedulerDependentManager):

    """Manages attachable block storage devices."""

    RPC_API_VERSION = '1.18'
    target = messaging.Target(version=RPC_API_VERSION)

    VOLUME_NAME_MAX_LEN = 255
    VOLUME_UUID_MAX_LEN = 36
    BACKUP_NAME_MAX_LEN = 255
    BACKUP_UUID_MAX_LEN = 36

    def __init__(self, service_name=None, *args, **kwargs):
        """Load the specified in args, or flags."""
        # update_service_capabilities needs service_name to be volume
        super(CinderBackupProxy, self).__init__(service_name='backup',
                                          *args, **kwargs)
        self.configuration = Configuration(volume_backup_opts,
                                           config_group=service_name)
        self._tp = GreenPool()
        self.volume_api = volume.API()
        self._last_info_volume_state_heal = 0
        self._change_since_time = None
        self.volumes_mapping_cache = {'backups': {}}
        self.init_flag = False
        self.backup_cache = []
        self.tenant_id = self._get_tenant_id()
        self.adminCinderClient = self._get_cascaded_cinder_client()
    def _init_volume_mapping_cache(self,context):
        try:
            backups = self.db.backup_get_all(context)
            for backup in backups:
                backup_id = backup['id']
                status = backup['status']
                try:
                    cascaded_backup_id =self._get_cascaded_backup_id(backup_id)
                except Exception as ex:
                     continue
                if cascaded_backup_id == '' or status == 'error':
                    continue
                self.volumes_mapping_cache['backups'][backup_id] = cascaded_backup_id

            LOG.info(_("cascade info: init volume mapping cache is %s"),
                     self.volumes_mapping_cache)
        except Exception as ex:
            LOG.error(_("Failed init volumes mapping cache"))
            LOG.exception(ex)

    def _gen_ccding_backup_name(self, backup_id):
        
        return "backup" + "@" + backup_id

    def _get_cinder_cascaded_admin_client(self):

        try:
            kwargs = {'username': cfg.CONF.cinder_username,
                      'password': cfg.CONF.admin_password,
                      'tenant_name': CONF.cinder_tenant_name,
                      'auth_url': cfg.CONF.keystone_auth_url,
                      'insecure': True
                      }

            keystoneclient = kc.Client(**kwargs)
            cinderclient = cinder_client.Client(
                username=cfg.CONF.cinder_username,
                auth_url=cfg.CONF.keystone_auth_url,
                insecure=True)
            cinderclient.client.auth_token = keystoneclient.auth_ref.auth_token
            diction = {'project_id': cfg.CONF.cinder_tenant_id}
            cinderclient.client.management_url = \
                cfg.CONF.cascaded_cinder_url % diction

            return cinderclient
        except keystone_exception.Unauthorized:
            with excutils.save_and_reraise_exception():
                LOG.error(_('Token unauthorized failed for keystoneclient '
                            'constructed when get cascaded admin client'))
        except cinder_exception.Unauthorized:
            with excutils.save_and_reraise_exception():
                LOG.error(_('Token unauthorized failed for cascaded '
                            'cinderClient constructed'))
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_('Failed to get cinder python client.'))

    def _add_to_threadpool(self, func, *args, **kwargs):
        self._tp.spawn_n(func, *args, **kwargs)

    @property
    def initialized(self):
        return self.init_flag

    def init_host(self):


        ctxt = context.get_admin_context()
        self._init_volume_mapping_cache(ctxt)
        LOG.info(_("Cleaning up incomplete backup operations."))
        
        # TODO(smulcahy) implement full resume of backup and restore
        # operations on restart (rather than simply resetting)
        backups = self.db.backup_get_all_by_host(ctxt, self.host)
        for backup in backups:
            if backup['status'] == 'creating' or backup['status'] == 'restoring':
                backup_info = {'status':backup['status'],
                               'id':backup['id']}
                self.backup_cache.append(backup_info)

            # TODO: this won't work because under this context, you have
            # no project id
            '''if backup['status'] == 'deleting':
                LOG.info(_('Resuming delete on backup: %s.') % backup['id'])
                self.delete_backup(ctxt, backup['id'])'''

        self.init_flag = True

    def create_backup(self, context, backup_id):
        """Create volume backups using configured backup service."""
        backup = self.db.backup_get(context, backup_id)
        volume_id = backup['volume_id']

        display_description = backup['display_description']
        container = backup['container']
        display_name = self._gen_ccding_backup_name(backup_id)
        availability_zone = cfg.CONF.storage_availability_zone

        # Because volume could be available or in-use
        initial_vol_status = self.db.volume_get(context, volume_id)['status']
        self.db.volume_update(context, volume_id, {'status': 'backing-up'})

        '''if volume status is in-use, it must have been checked with force flag
            in cascading api layer'''
        force = False
        if initial_vol_status == 'in-use':
            force = True

        LOG.info(_('cascade info: Create backup started, backup: %(backup_id)s '
                   'volume: %(volume_id)s.') %
                 {'backup_id': backup_id, 'volume_id': volume_id})

        volume = self.db.volume_get(context, volume_id)
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

        cascaded_snapshot_id=''
        query_status = "error"
        try:
            cascaded_volume_id = self._query_cascaded_vol_id(context,volume_id)
            LOG.info(_("begin to create backup,cascaded volume : %s"), cascaded_volume_id)
            if container:
                try:
                    cascaded_snapshot_id = self._get_cascaded_snapshot_id(context,container)
                except Exception as err:
                    cascaded_snapshot_id = ''
                    LOG.info(_("the container is not snapshot :%s"),
                                 container)
            if cascaded_snapshot_id:
                LOG.info(_("the container is  snapshot :%s"),
                                 container)
                snapshot_ref = self.db.snapshot_get(context, container)
                update_volume_id = snapshot_ref['volume_id']
                container = cascaded_snapshot_id
                self.db.backup_update(context, backup_id, {'volume_id': update_volume_id})

            cinderClient = self ._get_cascaded_cinder_client(context)
            bodyResponse = cinderClient.backups.create(
                volume_id=cascaded_volume_id,
                container=container,
                name=display_name,
                description=display_description,
                force=force)
            LOG.info(_("cascade ino: create backup while response is:%s"),
                     bodyResponse._info)
            self.volumes_mapping_cache['backups'][backup_id] = \
                bodyResponse._info['id']

            # use service metadata to record cascading to cascaded backup id
            # mapping, to support cross az backup restore
            metadata = "mapping_uuid:" + bodyResponse._info['id'] + ";"
            tmp_metadata = None
            while True:
                time.sleep(CONF.volume_sync_interval)
                queryResponse = \
                    cinderClient.backups.get(bodyResponse._info['id'])
                query_status = queryResponse._info['status']
                if query_status != 'creating':
                    tmp_metadata = queryResponse._info.get('service_metadata','')
                    self.db.backup_update(context, backup['id'],
                                            {'status': query_status})
                    self.db.volume_update(context, volume_id, {'status': initial_vol_status})
                    break
                else:
                    continue
        except Exception as err:
            with excutils.save_and_reraise_exception():
                self.db.volume_update(context, volume_id,
                                      {'status': initial_vol_status})
                self.db.backup_update(context, backup['id'],
                                      {'status': 'error',
                                       'fail_reason': unicode(err)})
                return

        if tmp_metadata:
            metadata = metadata + tmp_metadata
        self.db.backup_update(context, backup_id, {'status': query_status,
                                                   'size': volume['size'],
                                                   'availability_zone': availability_zone,
                                                    'service_metadata': metadata})
        LOG.info(_('Create backup finished. backup: %s.'), backup_id)

    def _get_cascaded_backup_id(self, backup_id):

        count = 0
        display_name =self._gen_ccding_backup_name(backup_id)
        try:
            sopt={
                    "name":display_name
                  }
            cascaded_backups = self.adminCinderClient.backups.list(search_opts=sopt)
        except cinder_exception.Unauthorized:
            count = count + 1
            self.adminCinderClient = self._get_cascaded_cinder_client()
            if count < 2:
                LOG.info(_('To try again for get_cascaded_backup_id()'))
                self._get_cascaded_backup_id(backup_id)

        if cascaded_backups:
            cascaded_backup_id = getattr(cascaded_backups[-1], '_info')['id']
        else:
            err = _('the backup  %s is not exist ') %display_name
            raise exception.InvalidBackup(reason=err)
        return cascaded_backup_id

    def _get_cascaded_snapshot_id(self, context, snapshot_id):
        metadata = self.db.snapshot_metadata_get(context, snapshot_id)
        cascaded_snapshot_id = metadata['mapping_uuid']
        if cascaded_snapshot_id:
            LOG.info(_("cascade ino: cascaded_snapshot_id is:%s"),
                     cascaded_snapshot_id)
        return cascaded_snapshot_id

    def _clean_up_fake_resource(self, context,
                                fake_backup_id,
                                fake_source_volume_id):
        cinderClient = self._get_cascaded_cinder_client(context)
        cinderClient.backups.delete(fake_backup_id)
        cinderClient.volumes.delete(fake_source_volume_id)

    def restore_backup(self, context, backup_id, volume_id):
        """Restore volume backups from configured backup service."""
        LOG.info(_('Restore backup started, backup: %(backup_id)s '
                   'volume: %(volume_id)s.') %
                 {'backup_id': backup_id, 'volume_id': volume_id})

        backup = self.db.backup_get(context, backup_id)
        volume = self.db.volume_get(context, volume_id)
        availability_zone = cfg.CONF.storage_availability_zone

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
        try:
            cinderClient = self._get_cascaded_cinder_client(context)
            cascaded_volume_id = self._query_cascaded_vol_id(context, volume_id)

            # the backup to be restored may be cross-az, so get cascaded backup id
            # not from cache (since cache is built from cinder client of its own
            # region), but retrieve it from service meta data
            LOG.info(_("backup az:(backup_az)%s, conf az:%(conf_az)s") %
                     {'backup_az': backup['availability_zone'],
                      'conf_az': availability_zone})
            fake_description = ""
            fake_source_volume_id = None
            fake_backup_id = None
            if backup['availability_zone'] != availability_zone:
                volumeResponse = cinderClient.volumes.create(
                    volume['size'],
                    name=volume['display_name'] + "-fake",
                    description=volume['display_description'],
                    user_id=context.user_id,
                    project_id=context.project_id,
                    availability_zone=availability_zone,
                    metadata={'cross_az': ""})
                fake_source_volume_id = volumeResponse._info['id']
                time.sleep(30)

                # retrieve cascaded backup id
                md_set = backup['service_metadata'].split(';')
                cascaded_backup_id = None
                if len(md_set) > 1 and 'mapping_uuid' in md_set[0]:
                    mapping_set = md_set[0].split(':')
                    cascaded_backup_id = mapping_set[1]

                # save original backup id
                cascaded_source_backup_id = cascaded_backup_id
                # retrieve the original cascaded_source_volume_id
                cascading_source_volume_id = backup['volume_id']
                cascaded_source_volume_id = self._query_cascaded_vol_id(
                    context, cascading_source_volume_id)

                LOG.info(_("cascaded_source_backup_id:%(cascaded_source_backup_id)s,"
                           "cascaded_source_volume_id:%(cascaded_source_volume_id)s" %
                           {'cascaded_source_backup_id': cascaded_source_backup_id,
                            'cascaded_source_volume_id': cascaded_source_volume_id}))
                # compose display description for cascaded volume driver mapping to
                # original source backup id and original source volume_id
                fake_description = "cross_az:" + cascaded_source_backup_id + ":" + \
                                      cascaded_source_volume_id
                backup_bodyResponse = cinderClient.backups.create(
                    volume_id=fake_source_volume_id,
                    container=backup['container'],
                    name=backup['display_name'] + "-fake",
                    description=fake_description)

                # set cascaded_backup_id as the faked one, which will help call
                # into our volume driver's restore function
                fake_backup_id = backup_bodyResponse._info['id']
                cascaded_backup_id = backup_bodyResponse._info['id']
                LOG.info(_("update cacaded_backup_id to created one:%s"),
                         cascaded_backup_id)

            LOG.info(_("restore, cascaded_backup_id:%(cascaded_backup_id)s, "
                       "cascaded_volume_id:%(cascaded_volume_id)s, "
                       "description:%(description)s") %
                     {'cascaded_backup_id': cascaded_backup_id,
                     'cascaded_volume_id': cascaded_volume_id,
                     'description': fake_description})

            bodyResponse = cinderClient.restores.restore(
                backup_id=cascaded_backup_id,
                volume_id=cascaded_volume_id)
            LOG.info(_("cascade info: restore backup  while response is:%s"),
                     bodyResponse._info)
            while True:
                time.sleep(CONF.volume_sync_interval)
                queryResponse = \
                    cinderClient.backups.get(cascaded_backup_id)
                query_status = queryResponse._info['status']
                if query_status != 'restoring':
                    self.db.volume_update(context, volume_id, {'status': 'available'})
                    self.db.backup_update(context, backup_id, {'status': query_status})
                    LOG.info(_("get backup:%(backup)s status:%(status)s" %
                               {'backup': cascaded_backup_id,
                                'status': query_status}))
                    if fake_backup_id and fake_source_volume_id:
                        LOG.info(_("cleanup fake backup:%(backup)s,"
                                   "fake source volume id:%(volume)" %
                                   {'backup': fake_backup_id,
                                    'volume': fake_source_volume_id}))
                        # TODO: check fake_source_volume_id status issue and clean it
                else:
                    continue
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.volume_update(context, volume_id,
                                      {'status': 'error_restoring'})
                self.db.backup_update(context, backup_id,
                                      {'status': 'available'})

        LOG.info(_('Restore backup finished, backup %(backup_id)s restored'
                   ' to volume %(volume_id)s.') %
                 {'backup_id': backup_id, 'volume_id': volume_id})

    def _query_cascaded_vol_id(self,ctxt,volume_id=None):
        volume = self.db.volume_get(ctxt, volume_id)
        volume_metadata = dict((item['key'], item['value'])
                            for item in volume['volume_metadata'])
        mapping_uuid = volume_metadata.get('mapping_uuid', None)
        return mapping_uuid

    def _delete_backup_cascaded(self, context, backup_id):
        try:
            cascaded_backup_id = \
                self.volumes_mapping_cache['backups'].get(backup_id, '')
            LOG.info(_("cascade ino: delete cascaded backup :%s"),
                     cascaded_backup_id)

            cinderClient = self._get_cascaded_cinder_client(context)
            cinderClient.backups.get(cascaded_backup_id)
            resp = cinderClient.backups.delete(cascaded_backup_id)
            self.volumes_mapping_cache['backups'].pop(backup_id, '')
            LOG.info(_("delete cascaded backup %s successfully. resp :%s"),
                     cascaded_backup_id, resp)
            return
        except cinder_exception.NotFound:
            self.volumes_mapping_cache['backups'].pop(backup_id, '')
            LOG.info(_("delete cascaded backup %s successfully."),
                     cascaded_backup_id)
            return
        except Exception:
            with excutils.save_and_reraise_exception():
                self.db.backup_update(context,
                                      backup_id,
                                      {'status': 'error_deleting'})
                LOG.error(_("failed to delete cascaded backup %s"),
                          cascaded_backup_id)

    @locked_backup_operation
    def delete_backup(self, context, backup_id):
        """Delete volume backup from configured backup service."""

        LOG.info(_('cascade info:delete backup started, backup: %s.'), backup_id)
        backup = self.db.backup_get(context, backup_id)

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
        
        try:
            self._delete_backup_cascaded(context,backup_id)
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

        # Call driver to create backup description string
        try:

            cinderClient = self._get_cascaded_cinder_client(context)
            cascaded_backup_id = \
                self.volumes_mapping_cache['backups'].get(backup_id, '')
            LOG.info(_("cascade ino: export  cascade backup :%s"),
                     cascaded_backup_id)
            bodyResponse = cinderClient.backups.export_record(cascaded_backup_id)

            backup_record['backup_url'] = bodyResponse['backup_url']
            backup_record['backup_service'] = bodyResponse['backup_service']
        except Exception as err:
            msg = unicode(err)
            raise exception.InvalidBackup(reason=msg)
        LOG.info(_('Export record finished, backup %s exported.'), cascaded_backup_id)
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

        try:
            cinderClient = self._get_cascaded_cinder_client(context)
            bodyResponse = cinderClient.backups.import_record(backup_service,backup_url)

        except Exception as err:
            msg = unicode(err)
            self.db.backup_update(context,
                                      backup_id,
                                      {'status': 'error',
                                       'fail_reason': msg})
            raise exception.InvalidBackup(reason=msg)

        backup_update = {}
        backup_update['status'] = 'available'
        backup_update['host'] = self.host

        self.db.backup_update(context, backup_id, backup_update)

            # Verify backup

        LOG.info(_('Import record id %s metadata from driver '
                       'finished.') % backup_id)


    @periodic_task.periodic_task(spacing=CONF.volume_sync_interval,
                                 run_immediately=True)
    def _deal_backup_status(self,context):
        if not self.init_flag:
            LOG.debug(_('cinder backup proxy is not ready'))
            return

        for backup in self.backup_cache:
            try:
                cascaded_backup_id = \
                        self.volumes_mapping_cache['backups'].get(backup['id'],
                                                                None)
                if not cascaded_backup_id:
                    self.backup_cache.pop()
                    continue

                cinderClient = self._get_cinder_cascaded_admin_client()
                queryResponse = cinderClient.backups.get(cascaded_backup_id)
                query_status = queryResponse._info['status']
                if query_status != backup['status']:
                    metadata = queryResponse._info.get('service_metadata','')
                    self.db.backup_update(context, backup['id'],
                                            {'status': query_status})
                    self.db.volume_update(context, backup['volume_id'], {'status': 'available'})
                    self.backup_cache.pop()
            except Exception:
                pass


    def _get_tenant_id(self):
        tenant_id = None
        try:
            kwargs = {'username': CONF.cinder_username,
                  'password': CONF.admin_password,
                  'tenant_name': CONF.cinder_tenant_name,
                  'auth_url': CONF.keystone_auth_url,
                  'insecure': True
                  }

            keystoneclient = kc.Client(**kwargs)
            tenant_id = keystoneclient.tenants.find(name=CONF.cinder_tenant_name).to_dict().get('id')
            LOG.debug("_get_tenant_id tenant_id: %s" %str(tenant_id))
        except keystone_exception.Unauthorized:
            with excutils.save_and_reraise_exception():
                LOG.error('_get_tenant_id Unauthorized')
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error('_get_tenant_id raise Exception')
        return tenant_id
    def _get_management_url(self, kc, **kwargs):
        return kc.service_catalog.url_for(**kwargs)

    def _get_cascaded_cinder_client(self, context=None):
        try:
            if context is None:
                cinderclient = cinder_client.Client(
                    auth_url=CONF.keystone_auth_url,
                    region_name=CONF.cascaded_region_name,
                    tenant_id=self.tenant_id,
                    api_key=CONF.admin_password,
                    username=CONF.cinder_username,
                    insecure=True,
                    timeout=30,
                    retries=3)
            else:
                ctx_dict = context.to_dict()

                kwargs = {
                    'auth_url': CONF.keystone_auth_url,
                    'tenant_name': CONF.cinder_tenant_name,
                    'username': CONF.cinder_username,
                    'password': CONF.admin_password,
                    'insecure': True
                }
                keystoneclient = kc.Client(**kwargs)
                management_url = self._get_management_url(keystoneclient, service_type='volumev2',
                                                      attr='region',
                                                      endpoint_type='publicURL',
                                                      filter_value=CONF.cascaded_region_name)

                LOG.info("before replace: management_url:%s", management_url)
                url = management_url.rpartition("/")[0]
                management_url = url+ '/' + ctx_dict.get("project_id")

                LOG.info("after replace: management_url:%s", management_url)

                cinderclient = cinder_client.Client(
                username=ctx_dict.get('user_id'),
                auth_url=cfg.CONF.keystone_auth_url,
                insecure=True,
                timeout=30,
                retries=3)
                cinderclient.client.auth_token = ctx_dict.get('auth_token')
                cinderclient.client.management_url = management_url

            LOG.info(_("cascade info: os_region_name:%s"), CONF.cascaded_region_name)
            return cinderclient
        except keystone_exception.Unauthorized:
            with excutils.save_and_reraise_exception():
                LOG.error(_('Token unauthorized failed for keystoneclient '
                            'constructed when get cascaded admin client'))
        except cinder_exception.Unauthorized:
            with excutils.save_and_reraise_exception():
                LOG.error(_('Token unauthorized failed for cascaded '
                            'cinderClient constructed'))
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_('Failed to get cinder python client.'))