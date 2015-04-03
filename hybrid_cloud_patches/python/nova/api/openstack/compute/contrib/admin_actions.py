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
    def __init__(self, *args, **kwargs):
        super(AdminActionsController, self).__init__(*args, **kwargs)
        self.compute_api = compute.API()

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
        az=body.get('migrate')
        context = req.environ['nova.context']
        authorize(context, 'migrate')
        instance = common.get_instance(self.compute_api, context, id,
                                       want_objects=True)
        if az is not None:
            availability_zone = instance.availability_zone
            if az == availability_zone:
                msg = _("The target azone can't be the same one.")
                raise exc.HTTPBadRequest(explanation=msg)
                
            migrateThread = MigrateThread(context,instance,az)
            migrateThread.start()
            
        else:
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
    def __init__(self,context,instance,availability_zone): 
        threading.Thread.__init__(self)
        self.context = context
        self.instance = instance
        #self.flavor_id = flavor_id
        self.availability_zone = availability_zone
        self.compute_api = compute.API()
        self.host_api = compute.HostAPI()
        self.image_api = nova.image.API()
        #self.ext_mgr = ext_mgr
        self.volume_api = volume.API()
         
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
        volume_ids = [bdm.volume_id for bdm in bdms if bdm.volume_id]
        
         
        image_uuid = None
        if volume_ids is None or volume_ids == []:
            tmp_image_name = "%s@%s" % (uuid.uuid1(), self.instance.uuid)
            image_meta = self.compute_api.snapshot(self.context, self.instance, name=tmp_image_name, extra_properties=None)
            image_uuid = image_meta['id']
            try:
                filters = {'name':tmp_image_name}
                imagelist = self.image_api.get_all(self.context,filters=filters)
                image = imagelist[0]
                while image['status'] != 'active':
                    time.sleep(1) 
                    imagelist = self.image_api.get_all(self.context,filters=filters)
                    image = imagelist[0]
                    image_uuid = image['id']
                    image = self.image_api.get(self.context,image_uuid )
            except (exception.NotFound, exception.InvalidImageRef):
                explanation = _("Image not found.")
                raise webob.exc.HTTPNotFound(explanation=explanation)
             
        else :
            for volume_id in volume_ids:
                volume = self.volume_api.get(self.context, volume_id)
                #import pdb
                #pdb.set_trace()
                response = self.volume_api.upload_to_image(self.context,
                                                                volume_id,
                                                                True,
                                                                volume_id,
                                                                'bare',
                                                                'qcow2')
                image_uuid = response[1]['os-volume_upload_image']['image_id']
         
            #image_uuid = image_meta['id']
            try:
                image = self.image_api.get(self.context, image_uuid)
                cascading_image_name = image['id']
                filters = {'name':cascading_image_name}
                cascading_image = self.image_api.get_all(self.context,filters=filters)
                cascading_image_id = cascading_image[0]['id']
                cascading_image = self.image_api.get(self.context,cascading_image_id )
                while cascading_image['status'] != 'active':
                    time.sleep(1) 
                    cascading_image = self.image_api.get(self.context,cascading_image_id )
            except (exception.NotFound, exception.InvalidImageRef):
                explanation = _("Image not found.")
                raise webob.exc.HTTPNotFound(explanation=explanation)
        
        access_ip_v4 = self.instance.access_ip_v4
        if access_ip_v4 is not None:
            self._validate_access_ipv4(access_ip_v4)
            
        access_ip_v6 = self.instance.access_ip_v6
        if access_ip_v6 is not None:
            self._validate_access_ipv6(access_ip_v6)
            
        #networks = common.get_networks_for_instance(context, instance)
        min_count = 1
        max_count = 1
        
        name=self.instance.display_name
        key_name = None
        metadata = self.instance.metadata
        injected_files = []
        security_group=self.instance.security_groups
        user_data=self.instance.user_data
        
        flavor_id = self.instance.system_metadata['instance_type_flavorid']
        
        scheduler_hints = {}
        legacy_bdm = True
        #check_server_group_quota = \
        #    self.ext_mgr.is_loaded('os-server-group-quotas')
        check_server_group_quota=True
        
        requested_networks = []
        nw_info = compute_utils.get_nw_info_for_instance(self.instance)
        for vif in nw_info:
            net_uuid = vif['network']['id']
            net_ip = vif['network']['subnets'][0]['ips'][0]['address']
            requested_networks.append({'fixed_ip':net_ip, 'uuid':net_uuid})
        
        requested_networks = self._get_requested_networks(requested_networks)
        #detach port delete
        self.compute_api.delete(self.context,self.instance)
        
        while True:
            time.sleep(3)
            try:
                _get_inst_type = flavors.get_flavor_by_flavor_id
                inst_type = _get_inst_type(flavor_id, ctxt=self.context,
                                           read_deleted="no")
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
                            legacy_bdm=legacy_bdm,
                            check_server_group_quota=check_server_group_quota)
            except (exception.QuotaError,
                    exception.PortLimitExceeded) as error:
                raise exc.HTTPForbidden(
                    explanation=error.format_message(),
                    headers={'Retry-After': 0})
            except exception.InvalidMetadataSize as error:
                raise exc.HTTPRequestEntityTooLarge(
                    explanation=error.format_message())
            except exception.ImageNotFound as error:
                msg = _("Can not find requested image")
                raise exc.HTTPBadRequest(explanation=msg)
            except exception.FlavorNotFound as error:
                msg = _("Invalid flavorRef provided.")
                raise exc.HTTPBadRequest(explanation=msg)
            except exception.KeypairNotFound as error:
                msg = _("Invalid key_name provided.")
                raise exc.HTTPBadRequest(explanation=msg)
            except exception.ConfigDriveInvalidValue:
                msg = _("Invalid config_drive provided.")
                raise exc.HTTPBadRequest(explanation=msg)
            except UnicodeDecodeError as error:
                msg = "UnicodeError: %s" % unicode(error)
                raise exc.HTTPBadRequest(explanation=msg)
            except (exception.ImageNotActive,
                    exception.FlavorDiskTooSmall,
                    exception.FlavorMemoryTooSmall,
                    exception.NetworkNotFound,
                    exception.PortNotFound,
                    exception.FixedIpAlreadyInUse,
                    exception.SecurityGroupNotFound,
                    exception.InstanceUserDataTooLarge,
                    exception.InstanceUserDataMalformed) as error:
                raise exc.HTTPBadRequest(explanation=error.format_message())
            except (exception.ImageNUMATopologyIncomplete,
                    exception.ImageNUMATopologyForbidden,
                    exception.ImageNUMATopologyAsymmetric,
                    exception.ImageNUMATopologyCPUOutOfRange,
                    exception.ImageNUMATopologyCPUDuplicates,
                    exception.ImageNUMATopologyCPUsUnassigned,
                    exception.ImageNUMATopologyMemoryOutOfRange) as error:
                raise exc.HTTPBadRequest(explanation=error.format_message())
            except (exception.PortInUse,
                    exception.NoUniqueMatch) as error:
                continue
                raise exc.HTTPConflict(explanation=error.format_message())
            except exception.Invalid as error:
                raise exc.HTTPBadRequest(explanation=error.format_message())
            break
        

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
        controller = AdminActionsController()
        extension = extensions.ControllerExtension(self, 'servers', controller)
        return [extension]
