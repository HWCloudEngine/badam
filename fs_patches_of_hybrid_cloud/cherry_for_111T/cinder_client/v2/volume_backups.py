# Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
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
Volume Backups interface (1.1 extension).
"""
import six
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

SORT_DIR_VALUES = ('asc', 'desc')
SORT_KEY_VALUES = ('id', 'status', 'size', 'availability_zone', 'name',
                   'bootable', 'created_at')

from cinderclient import base


class VolumeBackup(base.Resource):
    """A volume backup is a block level backup of a volume."""
    def __repr__(self):
        return "<VolumeBackup: %s>" % self.id

    def delete(self):
        """Delete this volume backup."""
        return self.manager.delete(self)


class VolumeBackupManager(base.ManagerWithFind):
    """Manage :class:`VolumeBackup` resources."""
    resource_class = VolumeBackup

    def create(self, volume_id, container=None,
               name=None, description=None,
               force=False):
        """Creates a volume backup.

        :param volume_id: The ID of the volume to backup.
        :param container: The name of the backup service container.
        :param name: The name of the backup.
        :param description: The description of the backup.
        :rtype: :class:`VolumeBackup`
        """
        body = {'backup': {'volume_id': volume_id,
                           'container': container,
                           'name': name,
                           'description': description,
                           'force': force}}
        return self._create('/backups', body, 'backup')

    def get(self, backup_id):
        """Show volume backup details.

        :param backup_id: The ID of the backup to display.
        :rtype: :class:`VolumeBackup`
        """
        return self._get("/backups/%s" % backup_id, "backup")
    def list(self, detailed=True, search_opts=None, marker=None, limit=None,
             sort_key=None, sort_dir=None):
        """Lists all volumes.

        :param detailed: Whether to return detailed volume info.
        :param search_opts: Search options to filter out volumes.
        :param marker: Begin returning volumes that appear later in the volume
                       list than that represented by this volume id.
        :param limit: Maximum number of volumes to return.
        :param sort_key: Key to be sorted.
        :param sort_dir: Sort direction, should be 'desc' or 'asc'.
        :rtype: list of :class:`Volume`
        """
        if search_opts is None:
            search_opts = {}
        qparams = {}

        for opt, val in six.iteritems(search_opts):
            if val:
                qparams[opt] = val

        if marker:
            qparams['marker'] = marker

        if limit:
            qparams['limit'] = limit

        if sort_key is not None:
            if sort_key in SORT_KEY_VALUES:
                qparams['sort_key'] = sort_key
            else:
                raise ValueError('sort_key must be one of the following: %s.'
                                 % ', '.join(SORT_KEY_VALUES))

        if sort_dir is not None:
            if sort_dir in SORT_DIR_VALUES:
                qparams['sort_dir'] = sort_dir
            else:
                raise ValueError('sort_dir must be one of the following: %s.'
                                 % ', '.join(SORT_DIR_VALUES))

        # Transform the dict to a sequence of two-element tuples in fixed
        # order, then the encoded string will be consistent in Python 2&3.
        if qparams:
            new_qparams = sorted(qparams.items(), key=lambda x: x[0])
            query_string = "?%s" % urlencode(new_qparams)
        else:
            query_string = ""

        detail = ""
        if detailed:
            detail = "/detail"

        return self._list("/backups%s%s" % (detail, query_string),
                          "backups")

    def delete(self, backup):
        """Delete a volume backup.

        :param backup: The :class:`VolumeBackup` to delete.
        """
        self._delete("/backups/%s" % base.getid(backup))

    def export_record(self, backup_id):
        """Export volume backup metadata record.

        :param backup_id: The ID of the backup to export.
        :rtype: :class:`VolumeBackup`
        """
        resp, body = \
            self.api.client.get("/backups/%s/export_record" % backup_id)
        return body['backup-record']

    def import_record(self, backup_service, backup_url):
        """Export volume backup metadata record.

        :param backup_service: Backup service to use for importing the backup
        :param backup_urlBackup URL for importing the backup metadata
        :rtype: :class:`VolumeBackup`
        """
        body = {'backup-record': {'backup_service': backup_service,
                                  'backup_url': backup_url}}
        self.run_hooks('modify_body_for_update', body, 'backup-record')
        resp, body = self.api.client.post("/backups/import_record", body=body)
        return body['backup']
