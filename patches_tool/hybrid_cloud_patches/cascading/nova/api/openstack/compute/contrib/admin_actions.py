#   Copyright 2011 OpenStack Foundation
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import threading
import uuid
from nova.compute import flavors
from nova.compute import utils as compute_utils
import nova.image
import time
from nova.openstack.common import log as logging
from nova import volume
from nova import objects
from nova.openstack.common import uuidutils
from nova import block_device
from nova.compute import task_states

import os.path
import traceback

import six
import webob
from webob import exc

from nova.api.openstack import common
from nova.api.openstack import extensions
from nova.api.openstack import wsgi
from nova import compute
from nova.compute import vm_states
from nova.compute import power_state
from nova import exception
from nova.i18n import _
from nova.i18n import _LE
from nova.openstack.common import log as logging
from nova.openstack.common import strutils

LOG = logging.getLogger(__name__)

# States usable in resetState action
state_map = dict(active=vm_states.ACTIVE, error=vm_states.ERROR)


def authorize(context, action_name):
    action = 'admin_actions:%s' % action_name
    extensions.extension_authorizer('compute', action)(context)


class AdminActionsController(wsgi.Controller):
    def __init__(self, ext_mgr, *args, **kwargs):
        super(AdminActionsController, self).__init__(*args, **kwargs)
        self.compute_api = compute.API()
        self.ext_mgr = ext_mgr

    # TODO(bcwaldon): These action names should be prefixed with 'os-'

    @wsgi.action('pause')
    def _pause(self, req, id, body):
        """Permit Admins to pause the server."""
        ctxt = req.environ['nova.context']
        authorize(ctxt, 'pause')
        server = common.get_instance(self.compute_api, ctxt, id,
                                     want_objects=True)
        try:
            self.compute_api.pause(ctxt, server)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'pause')
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("Compute.api::pause %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

    @wsgi.action('unpause')
    def _unpause(self, req, id, body):
        """Permit Admins to unpause the server."""
        ctxt = req.environ['nova.context']
        authorize(ctxt, 'unpause')
        server = common.get_instance(self.compute_api, ctxt, id,
                                     want_objects=True)
        try:
            self.compute_api.unpause(ctxt, server)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'unpause')
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("Compute.api::unpause %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

    @wsgi.action('suspend')
    def _suspend(self, req, id, body):
        """Permit admins to suspend the server."""
        context = req.environ['nova.context']
        authorize(context, 'suspend')
        server = common.get_instance(self.compute_api, context, id,
                                     want_objects=True)
        try:
            self.compute_api.suspend(context, server)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'suspend')
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("compute.api::suspend %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

    @wsgi.action('resume')
    def _resume(self, req, id, body):
        """Permit admins to resume the server from suspend."""
        context = req.environ['nova.context']
        authorize(context, 'resume')
        server = common.get_instance(self.compute_api, context, id,
                                     want_objects=True)
        try:
            self.compute_api.resume(context, server)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'resume')
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("compute.api::resume %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

    @wsgi.action('migrate')
    def _migrate(self, req, id, body):
        """Permit admins to migrate a server to a new host."""

        param_dict=body.get('migrate')
        no_sys_vol = param_dict.get('no_sys_vol',False)
        az=param_dict.get('az')
        boot_system_volume = not no_sys_vol
        context = req.environ['nova.context']
        authorize(context, 'migrate')
        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        if az is not None:
            availability_zone = instance.availability_zone
            if az == availability_zone:
                msg = _("The target azone can't be the same one.")
                raise exc.HTTPBadRequest(explanation=msg)
                
            migrateThread = MigrateThread(context,instance,az,boot_system_volume)
            migrateThread.start()
            
        else:
			host = None
	        if self.ext_mgr.is_loaded('os-migrate-host'):
	            migrate_body = body.get('migrate')
	            host = migrate_body.get('host') if migrate_body else None
	        LOG.debug("Going to try to cold migrate %(uuid)s to %(host)s",
	                  {"uuid":instance["uuid"], "host":(host or "another host")})
            try:
                self.compute_api.resize(req.environ['nova.context'], instance)
            except exception.QuotaError as error:
                raise exc.HTTPForbidden(explanation=error.format_message())
            except exception.InstanceIsLocked as e:
                raise exc.HTTPConflict(explanation=e.format_message())
            except exception.InstanceInvalidState as state_error:
                common.raise_http_conflict_for_instance_invalid_state(state_error,
                        'migrate')
            except exception.InstanceNotFound as e:
                raise exc.HTTPNotFound(explanation=e.format_message())
            except exception.NoValidHost as e:
                raise exc.HTTPBadRequest(explanation=e.format_message())
            except Exception as e:
                LOG.exception(_LE("Error in migrate %s"), e)
                raise exc.HTTPBadRequest()
            return webob.Response(status_int=202)

    @wsgi.action('resetNetwork')
    def _reset_network(self, req, id, body):
        """Permit admins to reset networking on a server."""
        context = req.environ['nova.context']
        authorize(context, 'resetNetwork')
        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        try:
            self.compute_api.reset_network(context, instance)
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("Compute.api::reset_network %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

    @wsgi.action('injectNetworkInfo')
    def _inject_network_info(self, req, id, body):
        """Permit admins to inject network info into a server."""
        context = req.environ['nova.context']
        authorize(context, 'injectNetworkInfo')
        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        try:
            self.compute_api.inject_network_info(context, instance)
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("Compute.api::inject_network_info %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

    @wsgi.action('lock')
    def _lock(self, req, id, body):
        """Lock a server instance."""
        context = req.environ['nova.context']
        authorize(context, 'lock')
        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        try:
            self.compute_api.lock(context, instance)
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("Compute.api::lock %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

    @wsgi.action('unlock')
    def _unlock(self, req, id, body):
        """Unlock a server instance."""
        context = req.environ['nova.context']
        authorize(context, 'unlock')
        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        try:
            self.compute_api.unlock(context, instance)
        except exception.PolicyNotAuthorized as e:
            raise webob.exc.HTTPForbidden(explanation=e.format_message())
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("Compute.api::unlock %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

    @wsgi.action('createBackup')
    def _create_backup(self, req, id, body):
        """Backup a server instance.

        Images now have an `image_type` associated with them, which can be
        'snapshot' or the backup type, like 'daily' or 'weekly'.

        If the image_type is backup-like, then the rotation factor can be
        included and that will cause the oldest backups that exceed the
        rotation factor to be deleted.

        """
        context = req.environ["nova.context"]
        authorize(context, 'createBackup')
        entity = body["createBackup"]

        try:
            image_name = entity["name"]
            backup_type = entity["backup_type"]
            rotation = entity["rotation"]

        except KeyError as missing_key:
            msg = _("createBackup entity requires %s attribute") % missing_key
            raise exc.HTTPBadRequest(explanation=msg)

        except TypeError:
            msg = _("Malformed createBackup entity")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            rotation = int(rotation)
        except ValueError:
            msg = _("createBackup attribute 'rotation' must be an integer")
            raise exc.HTTPBadRequest(explanation=msg)
        if rotation < 0:
            msg = _("createBackup attribute 'rotation' must be greater "
                    "than or equal to zero")
            raise exc.HTTPBadRequest(explanation=msg)

        props = {}
        metadata = entity.get('metadata', {})
        common.check_img_metadata_properties_quota(context, metadata)
        try:
            props.update(metadata)
        except ValueError:
            msg = _("Invalid metadata")
            raise exc.HTTPBadRequest(explanation=msg)

        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        try:
            image = self.compute_api.backup(context, instance, image_name,
                    backup_type, rotation, extra_properties=props)
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'createBackup')

        resp = webob.Response(status_int=202)

        # build location of newly-created image entity if rotation is not zero
        if rotation > 0:
            image_id = str(image['id'])
            image_ref = os.path.join(req.application_url, 'images', image_id)
            resp.headers['Location'] = image_ref

        return resp

    @wsgi.action('os-migrateLive')
    def _migrate_live(self, req, id, body):
        """Permit admins to (live) migrate a server to a new host."""
        context = req.environ["nova.context"]
        authorize(context, 'migrateLive')

        try:
            block_migration = body["os-migrateLive"]["block_migration"]
            disk_over_commit = body["os-migrateLive"]["disk_over_commit"]
            host = body["os-migrateLive"]["host"]
        except (TypeError, KeyError):
            msg = _("host, block_migration and disk_over_commit must "
                    "be specified for live migration.")
            raise exc.HTTPBadRequest(explanation=msg)

        try:
            block_migration = strutils.bool_from_string(block_migration,
                                                        strict=True)
            disk_over_commit = strutils.bool_from_string(disk_over_commit,
                                                         strict=True)
        except ValueError as err:
            raise exc.HTTPBadRequest(explanation=six.text_type(err))

        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        try:
            self.compute_api.live_migrate(context, instance, block_migration,
                                          disk_over_commit, host)
        except (exception.NoValidHost,
                exception.ComputeServiceUnavailable,
                exception.InvalidHypervisorType,
                exception.InvalidCPUInfo,
                exception.UnableToMigrateToSelf,
                exception.DestinationHypervisorTooOld,
                exception.InvalidLocalStorage,
                exception.InvalidSharedStorage,
                exception.HypervisorUnavailable,
                exception.InstanceNotRunning,
                exception.ComputeHostNotFound,
                exception.MigrationPreCheckError) as ex:
            raise exc.HTTPBadRequest(explanation=ex.format_message())
        except exception.InstanceNotFound as e:
            raise exc.HTTPNotFound(explanation=e.format_message())
        except exception.InstanceIsLocked as e:
            raise exc.HTTPConflict(explanation=e.format_message())
        except exception.InstanceInvalidState as state_error:
            common.raise_http_conflict_for_instance_invalid_state(state_error,
                    'os-migrateLive')
        except Exception:
            if host is None:
                msg = _("Live migration of instance %s to another host "
                        "failed") % id
            else:
                msg = _("Live migration of instance %(id)s to host %(host)s "
                        "failed") % {'id': id, 'host': host}
            LOG.exception(msg)
            # Return messages from scheduler
            raise exc.HTTPBadRequest(explanation=msg)

        return webob.Response(status_int=202)

    @wsgi.action('os-resetState')
    def _reset_state(self, req, id, body):
        """Permit admins to reset the state of a server."""
        context = req.environ["nova.context"]
        authorize(context, 'resetState')

        # Identify the desired state from the body
        try:
            state = state_map[body["os-resetState"]["state"]]
        except (TypeError, KeyError):
            msg = _("Desired state must be specified.  Valid states "
                    "are: %s") % ', '.join(sorted(state_map.keys()))
            raise exc.HTTPBadRequest(explanation=msg)

        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        try:
            instance.vm_state = state
            instance.task_state = None
            instance.save(admin_state_reset=True)
        except exception.InstanceNotFound:
            msg = _("Server not found")
            raise exc.HTTPNotFound(explanation=msg)
        except Exception:
            readable = traceback.format_exc()
            LOG.exception(_LE("Compute.api::resetState %s"), readable)
            raise exc.HTTPUnprocessableEntity()
        return webob.Response(status_int=202)

class MigrateThread(threading.Thread):
    def __init__(self,context,instance,availability_zone,migrate_system_volume):
        threading.Thread.__init__(self)
        self.context = context
        self.instance = instance
        #self.flavor_id = flavor_id
        self.availability_zone = availability_zone
        self.migrate_system_volume = migrate_system_volume
        self.compute_api = compute.API()
        self.host_api = compute.HostAPI()
        self.image_api = nova.image.API()
        #self.ext_mgr = ext_mgr
        self.volume_api = volume.API()
        
    def _get_power_state(self, context, instance):
        """Retrieve the power state for the given instance."""
        LOG.debug('Checking state', instance=instance)
        return instance.vm_state
    
    def _convert_volume_type(self,context,availability_zone): 
        """ convert different azone's volume type"""
        volume_type_dist = {'az01.shenzhen--fusionsphere': 'lvm', 'az02.hangzhou--fusionsphere': 'lvm',
		                     'az11.shenzhen--vcloud': None, 'az31.singapore--aws': 'ec2', 'az32.singapore--aws': None}
        if availability_zone is not None:
            return volume_type_dist.get(availability_zone, None) 
            
    def _delete_tmp_image(self,context,image_api,image_uuid,volume_dist_for_image_id,volume_dist_for_boot_index): 
        """ delete the created image during the migrate """
        if image_uuid is not None:
            image_api.delete(context,image_uuid)
        for volume_id in volume_dist_for_image_id.keys():
            if volume_dist_for_boot_index.get(volume_id) is None:
                cascading_image_id = volume_dist_for_image_id.get(volume_id)
                filters = {'name':cascading_image_id}
                imagelist = image_api.get_all(context,filters=filters)
                image = imagelist[0]
                image_api.delete(context,cascading_image_id)
                image_api.delete(context,image['id'])
                
            if volume_dist_for_boot_index.get(volume_id) is not None and volume_dist_for_boot_index.get(volume_id) ==0: 
                cascading_image_id = volume_dist_for_image_id.get(volume_id)
                image_api.delete(context,cascading_image_id) 
                
    def _upload_volume_to_image(self,context,volume_api,volume_ids,volume_dict_for_boot_index,migrate_system_volume):
        """ upload the volume to glance """    
        volume_dist_for_image_id ={}
        image_id = None
        for volume_id in volume_ids:
            if volume_dict_for_boot_index[volume_id] == 0 and migrate_system_volume is False:
                volume = volume_api.get(context, volume_id)
                volume_image_metadata = volume.get('volume_metadata')
                image_id = volume_image_metadata['image_id']
            else:
                response = volume_api.upload_to_image(context,
                                                        volume_id,
                                                        True,
                                                        volume_id,
                                                        'bare',
                                                        'qcow2')
                image_uuid_of_volume = response[1]['os-volume_upload_image']['image_id']
                volume_dist_for_image_id[volume_id] = image_uuid_of_volume
        return volume_dist_for_image_id, image_id
  
    def  _delete_volume_after_migrate(self,context,volume_api,volume_ids):
        for volume_id in volume_ids:
            volume = volume_api.get(context, volume_id)
            query_volume_status=1800
            if  volume:
                volume_status=volume.get('status')
                if volume_status=='error' \
                    or volume_status=='deleting' \
                    or volume_status=='error_deleting':
                    return
                while volume_status != 'available':
                    time.sleep(1)
                    volume = volume_api.get(context, volume_id) 
                    if volume:
                        volume_status=volume.get('status')
                        query_volume_status = query_volume_status-1
                        if query_volume_status==0 and volume_status !='available':
                            return
                volume_api.delete(context, volume_id)
                query_volume_status_count=10
                delete_volume_try_count =5
                volume = volume_api.get(context, volume_id)
                while volume:
                    if volume.get('status') == 'error_deleting':
                        time.sleep(2)
                        volume = volume_api.get(context, volume_id)
                        while volume.get('status') != 'available': 
                            time.sleep(1)
                            volume = volume_api.get(context, volume_id) 
                            query_volume_status_count = query_volume_status_count -1
                            if volume.get('status') == 'error':
                                volume_api.delete(context, volume_id)
                            if query_volume_status_count == 0:
                                volume_api.delete(context, volume_id)  
                        volume_api.delete(context, volume_id)
                    time.sleep(1)
                    volume = volume_api.get(context, volume_id)
                    if not volume:
                        return
                    delete_volume_try_count =delete_volume_try_count-1
                    if delete_volume_try_count ==0:
                        volume_api.delete(context, volume_id)
                        return

    #copy from servers for migrate
    def _get_requested_networks(self, requested_networks):
        """Create a list of requested networks from the networks attribute."""
        networks = []
        network_uuids = []
        for network in requested_networks:
            request = objects.NetworkRequest()
            try:
                try:
                    request.port_id = network.get('port', None)
                except ValueError:
                    msg = _("Bad port format: port uuid is "
                            "not in proper format "
                            "(%s)") % network.get('port')
                    raise exc.HTTPBadRequest(explanation=msg)
                if request.port_id:
                    request.network_id = None
                    if not utils.is_neutron():
                        # port parameter is only for neutron v2.0
                        msg = _("Unknown argument : port")
                        raise exc.HTTPBadRequest(explanation=msg)
                else:
                    request.network_id = network['uuid']

                if (not request.port_id and not
                        uuidutils.is_uuid_like(request.network_id)):
                    br_uuid = request.network_id.split('-', 1)[-1]
                    if not uuidutils.is_uuid_like(br_uuid):
                        msg = _("Bad networks format: network uuid is "
                                "not in proper format "
                                "(%s)") % request.network_id
                        raise exc.HTTPBadRequest(explanation=msg)

                # fixed IP address is optional
                # if the fixed IP address is not provided then
                # it will use one of the available IP address from the network
                try:
                    request.address = network.get('fixed_ip', None)
                except ValueError:
                    msg = _("Invalid fixed IP address (%s)") % request.address
                    raise exc.HTTPBadRequest(explanation=msg)

                if (request.network_id and
                        request.network_id in network_uuids):
                    expl = (_("Duplicate networks"
                              " (%s) are not allowed") %
                            request.network_id)
                    raise exc.HTTPBadRequest(explanation=expl)
                network_uuids.append(request.network_id)
                networks.append(request)
            except KeyError as key:
                expl = _('Bad network format: missing %s') % key
                raise exc.HTTPBadRequest(explanation=expl)
            except TypeError:
                expl = _('Bad networks format')
                raise exc.HTTPBadRequest(explanation=expl)

        return objects.NetworkRequestList(objects=networks)
    #copy end
    def run(self):
        
       
        #imageName=str(uuid.uuid4())
        
        #create image
        #image_meta = self.compute_api.snapshot(self.context, self.instance, name=imageId, extra_properties=None)
        
        bdms = objects.BlockDeviceMappingList.get_by_instance_uuid(
                self.context, self.instance['uuid'])
        is_boot_from_image = False

        
        #judge if Create volume from image and boot instance
        is_boot_from_volume_created_image= False
        #save the volume
        volume_dict_for_boot_index = {}
        volume_dict_for_image_id ={}
        volume_dict_for_mountpoint ={}
        block_device_mapping = None
        volume_ids = []
        system_volume_image_id = None
        instance = common.get_instance(self.compute_api, self.context, self.instance.uuid, want_objects=True) 
        for bdm in bdms:
            if bdm.image_id is not None and bdm.boot_index == 0 and bdm.destination_type =='local':
                is_boot_from_image =True
                system_volume_image_id = bdm.image_id
            elif bdm.image_id is not None and bdm.boot_index == 0 and bdm.destination_type =='volume':
                is_boot_from_volume_created_image=True
                volume_create_from_image_size=bdm.volume_size
            if bdm.volume_id is not None:
                volume_dict_for_boot_index[bdm.volume_id]=bdm.boot_index
                volume_ids.append(bdm.volume_id)
                volume_dict_for_mountpoint[bdm.volume_id] =bdm.device_name
                
        current_power_state = self._get_power_state(self.context, instance)
        if current_power_state != vm_states.STOPPED:
            self.compute_api.stop(self.context,instance)
            query_vm_status_count=600 
            instance = common.get_instance(self.compute_api, self.context, instance.uuid, want_objects=True) 
            current_power_state = self._get_power_state(self.context, instance)   
            while current_power_state !=  vm_states.STOPPED:
                time.sleep(1)
                instance = common.get_instance(self.compute_api, self.context, instance.uuid, want_objects=True) 
                current_power_state = self._get_power_state(self.context, instance) 
                if current_power_state == vm_states.ERROR:
                    msg = _("migrate vm failed.")
                    raise exc.HTTPBadRequest(explanation=msg)
                query_vm_status_count =query_vm_status_count -1
                if query_vm_status_count==0 and current_power_state !=  vm_states.STOPPED:
                    msg = _("migrate vm failed.")
                    raise exc.HTTPBadRequest(explanation=msg)
        
        image_uuid = None       
        if is_boot_from_image or self.migrate_system_volume is False:
            if self.migrate_system_volume is False:
                image_uuid = system_volume_image_id
            else:
                tmp_image_name = "%s@%s" % (uuid.uuid1(), self.instance.uuid)
                image_meta = self.compute_api.snapshot(self.context, instance, name=tmp_image_name, extra_properties=None)
                #image_uuid = image_meta['id']
                try:
                    query_image_status_count=1800
                    filters = {'name':tmp_image_name}
                    imagelist = self.image_api.get_all(self.context,filters=filters)
                    image = imagelist[0]
					
                    filters = {'name': image['id']}
                    imagelist = self.image_api.get_all(self.context,filters=filters)
                    query_cascaded_image_count = 1800
                    while not imagelist:
                        time.sleep(1)
                        imagelist = self.image_api.get_all(self.context,filters=filters)											
                        query_cascaded_image_count = query_cascaded_image_count-1
                        if query_cascaded_image_count == 0 and  not imagelist:
                            msg = _("migrate vm failed.")
                            raise exc.HTTPBadRequest(explanation=msg)
                    self.image_api.delete(self.context,image['id'])
                    image = imagelist[0]
                    image_uuid = image['id']
                    while image['status'] != 'active':
                    	time.sleep(1) 
                    	image = self.image_api.get(self.context,image_uuid )
                    	if image['status'] =='error':
                        	msg = _("migrate vm failed.")
                        	raise exc.HTTPBadRequest(explanation=msg)
                    	query_image_status_count = query_image_status_count-1
                    	if query_image_status_count == 0 and image['status'] != 'active':
                        	msg = _("migrate vm failed.")
                        	raise exc.HTTPBadRequest(explanation=msg)
                    
                #if is_boot_from_volume_created_image:
                #   bdm_dict={'boot_index':0,'destination_type':'volume','uuid':image_uuid,'source_type':'image','volume_size':volume_create_from_image_size,'delete_on_termination':True}
                #   block_device_mapping = [block_device.BlockDeviceDict.from_api(bdm_dict)]
                except (exception.NotFound, exception.InvalidImageRef):
            	    explanation = _("Image not found.")
                    raise webob.exc.HTTPNotFound(explanation=explanation)
            #data_volume upload to glance
            volume_dict_for_image_id, image_uuid = self._upload_volume_to_image(self.context,self.volume_api,volume_ids,
                                                                    volume_dict_for_boot_index,self.migrate_system_volume)
            if image_uuid is None:
                image_uuid = system_volume_image_id
        else : 
            instance.task_state = task_states.IMAGE_SNAPSHOT
            instance.save(expected_task_state=[None])   
            volume_dict_for_image_id, image_uuid = self._upload_volume_to_image(self.context,self.volume_api,volume_ids,
                                                                    volume_dict_for_boot_index,self.migrate_system_volume)
            for volume_id in volume_ids:
                if volume_dict_for_boot_index.get(volume_id) is not None and volume_dict_for_boot_index.get(volume_id) ==0:
                    image_uuid= volume_dict_for_image_id.get(volume_id)
                    try:
                        query_cascaded_image_status_count=1800 
                        query_cascaded_image_count =1800
                        image = self.image_api.get(self.context, image_uuid)
                        cascading_image_name = image['id']
                        time.sleep(1) 
                        filters = {'name':cascading_image_name}
                        cascading_image = self.image_api.get_all(self.context,filters=filters)
                        while not cascading_image:
                            time.sleep(1)
                            cascading_image = self.image_api.get_all(self.context,filters=filters)
                            query_cascaded_image_count = query_cascaded_image_count-1
                            if query_cascaded_image_count == 0 and  not cascading_image:
                                #exception occurred,reset the instance task_state
                                instance.task_state = None
                                instance.save()
                                msg = _("migrate vm failed.")
                                raise exc.HTTPBadRequest(explanation=msg)
                        cascading_image_id = cascading_image[0]['id']
                        cascading_image = self.image_api.get(self.context,cascading_image_id )
                        image_uuid=cascading_image_id
                        while cascading_image['status'] != 'active':
                            time.sleep(1) 
                            cascading_image = self.image_api.get(self.context,cascading_image_id )
                            if cascading_image['status'] == 'error':
                                #exception occurred,reset the instance task_state
                                instance.task_state = None
                                instance.save()
                                msg = _("migrate vm failed.")
                                raise exc.HTTPBadRequest(explanation=msg)
                            query_cascaded_image_status_count = query_cascaded_image_status_count-1
                            if query_cascaded_image_status_count == 0 and image['status'] != 'active':
                                #exception occurred,reset the instance task_state
                                instance.task_state = None
                                instance.save()
                                msg = _("migrate vm failed.")
                                raise exc.HTTPBadRequest(explanation=msg)
                    except (exception.NotFound, exception.InvalidImageRef):
                        explanation = _("Image not found.")
                        #exception occurred,reset the instance task_state
                        instance.task_state = None
                        instance.save()
                        raise webob.exc.HTTPNotFound(explanation=explanation)
                    volume = self.volume_api.get(self.context, volume_id)
                    size= volume.get('size')
                    volume_type = self._convert_volume_type(self.context,self.availability_zone)
                    volume_name = volume.get('display_name')
                    metadata ={'readonly':'False','attached_mode':'rw'}
                    volume_boot = self.volume_api.create(self.context,size,volume_name,None,image_id=cascading_image_id,volume_type=volume_type, metadata=metadata,availability_zone=self.availability_zone)
                    query_system_volume_count=1800
                    while volume_boot.get('status') != 'available':
                        time.sleep(2)
                        volume_boot = self.volume_api.get(self.context, volume_boot['id'])  
                        if volume_boot.get('status') == 'error':
                            #exception occurred,reset the instance task_state
                            instance.task_state = None
                            instance.save()
                            msg = _("migrate vm failed.")
                            raise exc.HTTPBadRequest(explanation=msg)
                        query_system_volume_count = query_system_volume_count-1
                        if query_system_volume_count==0 and  volume_boot.get('status') != 'available':
                            msg = _("migrate vm failed.")
                            #exception occurred,reset the instance task_state
                            instance.task_state = None
                            instance.save()
                            raise exc.HTTPBadRequest(explanation=msg)
                    bdm_dict={'boot_index':0,'uuid': volume_boot['id'],'source_type':'volume','delete_on_termination':False,'volume_id':volume_boot['id'], 'destination_type':'volume'}
                    block_device_mapping = [block_device.BlockDeviceDict.from_api(bdm_dict)]
                    #bdm_dict={'boot_index':0,'destination_type':'volume','uuid':image_uuid,'source_type':'image','volume_size':size,'delete_on_termination':True}
                    #block_device_mapping = [block_device.BlockDeviceDict.from_api(bdm_dict)]
            #reset the instance task_state
            instance.task_state = None
            instance.save() 
        access_ip_v4 = instance.access_ip_v4
        if access_ip_v4 is not None:
            self._validate_access_ipv4(access_ip_v4)
            
        access_ip_v6 = instance.access_ip_v6
        if access_ip_v6 is not None:
            self._validate_access_ipv6(access_ip_v6)
            
        #networks = common.get_networks_for_instance(context, instance)
        min_count = 1
        max_count = 1
        
        name=instance.display_name
        key_name = None
        metadata = instance.metadata
        injected_files = []
        security_group=instance.security_groups
        user_data=instance.user_data
        
        flavor_id = instance.system_metadata['instance_type_flavorid']
        
        scheduler_hints = {}
         
        #check_server_group_quota = \
        #    self.ext_mgr.is_loaded('os-server-group-quotas')
        check_server_group_quota=True
        
        requested_networks = []
        nw_info = compute_utils.get_nw_info_for_instance(instance)
        for vif in nw_info:
            net_uuid = vif['network']['id']
            net_ip = vif['network']['subnets'][0]['ips'][0]['address']
            requested_networks.append({'fixed_ip':net_ip, 'uuid':net_uuid})
        
        requested_networks = self._get_requested_networks(requested_networks)
        #update the instance metadata
        self.compute_api.update_instance_metadata(self.context,instance,{'quick_delete_once': 'True'},delete=False) 
        #detach port delete
        self.compute_api.delete(self.context,instance)
        
        while True:
            time.sleep(3)
            try:
                _get_inst_type = flavors.get_flavor_by_flavor_id
                inst_type = _get_inst_type(flavor_id, ctxt=self.context,
                                           read_deleted="no")
                if is_boot_from_image or self.migrate_system_volume is False:
                    (instances, resv_id) = self.compute_api.create(self.context,
                                inst_type,
                                image_uuid,
                                display_name=name,
                                display_description=name,
                                key_name=key_name,
                                metadata=metadata,
                                access_ip_v4=access_ip_v4,
                                access_ip_v6=access_ip_v6,
                                injected_files=injected_files,
                                admin_password=None,
                                min_count=min_count,
                                max_count=max_count,
                                requested_networks=requested_networks,
                                security_group=security_group,
                                user_data=user_data,
                                availability_zone=self.availability_zone,
                                config_drive=None,
                                block_device_mapping=None,
                                auto_disk_config=None,
                                scheduler_hints=scheduler_hints,
                                legacy_bdm=True,
                                check_server_group_quota=check_server_group_quota)
                else:
                    (instances, resv_id) = self.compute_api.create(self.context,
                                inst_type,
                                None,
                                display_name=name,
                                display_description=name,
                                key_name=key_name,
                                metadata=metadata,
                                access_ip_v4=access_ip_v4,
                                access_ip_v6=access_ip_v6,
                                injected_files=injected_files,
                                admin_password=None,
                                min_count=min_count,
                                max_count=max_count,
                                requested_networks=requested_networks,
                                security_group=security_group,
                                user_data=user_data,
                                availability_zone=self.availability_zone,
                                config_drive=None,
                                block_device_mapping=block_device_mapping,
                                auto_disk_config=None,
                                scheduler_hints=scheduler_hints,
                                legacy_bdm=False,
                                check_server_group_quota=check_server_group_quota)
                    
            except (exception.QuotaError,
                    exception.PortLimitExceeded) as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception1:%s', readable)
                raise exc.HTTPForbidden(
                    explanation=error.format_message(),
                    headers={'Retry-After': 0})
            except exception.InvalidMetadataSize as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception2:%s', readable)
                raise exc.HTTPRequestEntityTooLarge(
                    explanation=error.format_message())
            except exception.ImageNotFound as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception3:%s', readable)
                msg = _("Can not find requested image")
                raise exc.HTTPBadRequest(explanation=msg)
            except exception.FlavorNotFound as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception4:%s', readable)
                msg = _("Invalid flavorRef provided.")
                raise exc.HTTPBadRequest(explanation=msg)
            except exception.KeypairNotFound as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception5:%s', readable)
                msg = _("Invalid key_name provided.")
                raise exc.HTTPBadRequest(explanation=msg)
            except exception.ConfigDriveInvalidValue:
                readable = traceback.format_exc()
                LOG.exception('migrate exception6:%s', readable)
                msg = _("Invalid config_drive provided.")
                raise exc.HTTPBadRequest(explanation=msg)
            except UnicodeDecodeError as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception7:%s', readable)
                msg = "UnicodeError: %s" % unicode(error)
                raise exc.HTTPBadRequest(explanation=msg)
            except (exception.ImageNotActive,
                    exception.FlavorDiskTooSmall,
                    exception.FlavorMemoryTooSmall,
                    exception.NetworkNotFound,
                    exception.PortNotFound,
                    exception.SecurityGroupNotFound,
                    exception.InstanceUserDataTooLarge,
                    exception.InstanceUserDataMalformed) as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception8:%s', readable)
                raise exc.HTTPBadRequest(explanation=error.format_message())
            except (exception.ImageNUMATopologyIncomplete,
                    exception.ImageNUMATopologyForbidden,
                    exception.ImageNUMATopologyAsymmetric,
                    exception.ImageNUMATopologyCPUOutOfRange,
                    exception.ImageNUMATopologyCPUDuplicates,
                    exception.ImageNUMATopologyCPUsUnassigned,
                    exception.ImageNUMATopologyMemoryOutOfRange) as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception9:%s', readable)
                raise exc.HTTPBadRequest(explanation=error.format_message())
            except (exception.PortInUse,
                    exception.NoUniqueMatch) as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception10:%s', readable)
                continue
                raise exc.HTTPConflict(explanation=error.format_message())
            except exception.FixedIpAlreadyInUse as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception11:%s', readable)
                continue
                raise exc.HTTPBadRequest(explanation=error.format_message())
            except exception.Invalid as error:
                readable = traceback.format_exc()
                LOG.exception('migrate exception12:%s', readable)
                raise exc.HTTPBadRequest(explanation=error.format_message())
            break
            
        volume_dist_for_mount_point ={}
        
        for volume_id in volume_dict_for_image_id.keys():
            if volume_dict_for_boot_index.get(volume_id) is None:
                try:
                    cascading_image_name = volume_dict_for_image_id.get(volume_id)
                    filters = {'name':cascading_image_name}
                    imagelist = self.image_api.get_all(self.context,filters=filters)
                    image = imagelist[0]
                    while image['status'] != 'active':
                        time.sleep(1)
                        imagelist = self.image_api.get_all(self.context,filters=filters)
                        image = imagelist[0]
                        if image['status'] =='error':
                            msg = _("migrate vm failed.")
                            raise exc.HTTPBadRequest(explanation=msg)
                    volume = self.volume_api.get(self.context, volume_id)
                    size= volume.get('size')
                    volume_name = volume.get('display_name')
                    volume_type = self._convert_volume_type(self.context,self.availability_zone)
                    volume_new = self.volume_api.create(self.context,size,volume_name,None,image_id=image['id'],volume_type=volume_type, availability_zone=self.availability_zone)
                    volume_dist_for_mount_point[volume_new.get('id')]=volume_dict_for_mountpoint.get(volume_id)
                except (exception.NotFound, exception.InvalidImageRef):
                    explanation = _("Image not found.")
                    raise webob.exc.HTTPNotFound(explanation=explanation)
      
        if instances is not None and len(instances) == 1:
            instance_new = instances[0]
            query_new_vm_status_count=600
            while instance_new.vm_state != 'active':
                time.sleep(2)
                instance_new = common.get_instance(self.compute_api, self.context, instance_new.uuid,
                                       want_objects=True)
                if instance_new.vm_state == 'error' : 
                    LOG.error("bulid instance failed")
                    msg = _("migrate vm failed.")
                    raise exc.HTTPBadRequest(explanation=msg)
                query_new_vm_status_count =query_new_vm_status_count-1
                if query_new_vm_status_count ==0 and instance_new.vm_state != 'active':
                    msg = _("migrate vm failed.")
                    raise exc.HTTPBadRequest(explanation=msg)
            if instance_new.vm_state == 'active':           
                for volume_id in volume_dist_for_mount_point.keys():
                    volume = self.volume_api.get(self.context, volume_id)
                    query_data_volume_count=60
                    while volume.get('status') != 'available':
                        time.sleep(2)
                        volume = self.volume_api.get(self.context, volume_id)  
                        if volume.get('status') == 'error':
                            msg = _("migrate vm failed.")
                            raise exc.HTTPBadRequest(explanation=msg)
                        query_data_volume_count = query_data_volume_count-1
                        if query_data_volume_count==0 and  volume.get('status') != 'available':
                            msg = _("migrate vm failed.")
                            raise exc.HTTPBadRequest(explanation=msg)
                    mount_point = volume_dist_for_mount_point.get(volume_id)
                    if mount_point is None:
                        mount_point = '/dev/vda'
                    self.compute_api.attach_volume(self.context,instance_new,volume_id,mount_point)
                
                for volume_id in volume_dist_for_mount_point.keys():
                    volume = self.volume_api.get(self.context, volume_id)
                    query_volume_status_count=360
                    while volume.get('status') !='in-use':
                        time.sleep(10)
                        volume = self.volume_api.get(self.context, volume_id)
                        if volume.get('status') == 'error':
                            msg = _("attach volume failed when migrating vm")
                            raise exc.HTTPBadRequest(explanation=msg)
                        query_volume_status_count = query_volume_status_count -1  
                        if query_volume_status_count==0 and  volume.get('status') != 'in-use':
                            msg = _("attach volume failed when migrating vm")
                            raise exc.HTTPBadRequest(explanation=msg)
                                            
        #delete the image
        if self.migrate_system_volume is False:
            image_uuid = None
        self._delete_tmp_image(self.context, self.image_api, image_uuid, volume_dict_for_image_id, volume_dict_for_boot_index)
        #delete the volume
        self._delete_volume_after_migrate(self.context,self.volume_api,volume_ids) 

class Admin_actions(extensions.ExtensionDescriptor):
    """Enable admin-only server actions

    Actions include: pause, unpause, suspend, resume, migrate,
    resetNetwork, injectNetworkInfo, lock, unlock, createBackup
    """

    name = "AdminActions"
    alias = "os-admin-actions"
    namespace = "http://docs.openstack.org/compute/ext/admin-actions/api/v1.1"
    updated = "2011-09-20T00:00:00Z"

    def get_controller_extensions(self):
        controller = AdminActionsController(self.ext_mgr)
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
