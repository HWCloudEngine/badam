"""
A connection to the VMware vCenter platform.
"""

import re
import shutil

from oslo.config import cfg

from nova.openstack.common import log as logging
from nova.virt.vmwareapi import host
from nova.virt.hybridvmwareapi import vmops
from nova.virt.vmwareapi import volumeops
from nova.virt.vmwareapi import driver
from nova.virt.hybridvmwareapi import vif as vmwarevif
from six import moves
from nova import utils


LOG = logging.getLogger(__name__)

vmwareapi_opts = [
    cfg.StrOpt('host_ip',
               help='Hostname or IP address for connection to VMware VC '
                    'host.'),
    cfg.IntOpt('host_port',
               default=443,
               help='Port for connection to VMware VC host.'),
    cfg.StrOpt('host_username',
               help='Username for connection to VMware VC host.'),
    cfg.StrOpt('host_password',
               help='Password for connection to VMware VC host.',
               secret=True),
    cfg.MultiStrOpt('cluster_name',
                    help='Name of a VMware Cluster ComputeResource.'),
    cfg.StrOpt('datastore_regex',
               help='Regex to match the name of a datastore.'),
    cfg.FloatOpt('task_poll_interval',
                 default=0.5,
                 help='The interval used for polling of remote tasks.'),
    cfg.IntOpt('api_retry_count',
               default=10,
               help='The number of times we retry on failures, e.g., '
                    'socket error, etc.'),
    cfg.IntOpt('vnc_port',
               default=5900,
               help='VNC starting port'),
    cfg.IntOpt('vnc_port_total',
               default=10000,
               help='Total number of VNC ports'),
    cfg.BoolOpt('use_linked_clone',
                default=True,
                help='Whether to use linked clone'),
    cfg.StrOpt('wsdl_location',
               help='Optional VIM Service WSDL Location '
                    'e.g http://<server>/vimService.wsdl. '
                    'Optional over-ride to default location for bug '
                    'work-arounds'),
    cfg.StrOpt('ovs_ethport',
               default='eth1',
               help='The eth port of ovs-vm use '
               'to connect vm openstack create '),
    cfg.StrOpt('ovs_dvs_name',
               default='dvSwitch',
               help='The dvs of ovs-vm use to connect vm openstack create '),
    cfg.StrOpt('relation_files',
               default='/etc/nova/nova-relations',
               help='The vlan instance port relation files '),
]

CONF = cfg.CONF
CONF.register_opts(vmwareapi_opts, 'vmware')

TIME_BETWEEN_API_CALL_RETRIES = 1.0


class VMwareVCDriver(driver.VMwareVCDriver):

    """The VC host connection object."""

    def __init__(self, virtapi, scheme="https"):
        super(VMwareVCDriver, self).__init__(virtapi, scheme)
        self.ovsport_info = {'ovs_ethport': CONF.vmware.ovs_ethport,
                             'ovs_dvs_name': CONF.vmware.ovs_dvs_name,
                             'relation_files': CONF.vmware.relation_files}
        self.available_pg_vlans = set(moves.xrange(2, 4094))
        self.pg_vlan_instance_map = {}
        self._update_pg_instance_vlan_relation(CONF.vmware.relation_files)

    def _update_resources(self):
        """This method creates a dictionary of VMOps, VolumeOps and VCState.

        The VMwareVMOps, VMwareVolumeOps and VCState object is for each
        cluster/rp. The dictionary is of the form
        {
            domain-1000 : {'vmops': vmops_obj,
                          'volumeops': volumeops_obj,
                          'vcstate': vcstate_obj,
                          'name': MyCluster},
            resgroup-1000 : {'vmops': vmops_obj,
                              'volumeops': volumeops_obj,
                              'vcstate': vcstate_obj,
                              'name': MyRP},
        }
        """
        added_nodes = set(self.dict_mors.keys()) - set(self._resource_keys)
        for node in added_nodes:
            _volumeops = volumeops.VMwareVolumeOps(
                self._session,
                self.dict_mors[node]['cluster_mor'])
            _vmops = vmops.VMwareVMOps(self._session, self._virtapi,
                                       _volumeops,
                                       self.dict_mors[node]['cluster_mor'],
                                       datastore_regex=self._datastore_regex)
            name = self.dict_mors.get(node)['name']
            nodename = self._create_nodename(node, name)
            _vc_state = host.VCState(self._session, nodename,
                                     self.dict_mors.get(node)['cluster_mor'])
            self._resources[nodename] = {'vmops': _vmops,
                                         'volumeops': _volumeops,
                                         'vcstate': _vc_state,
                                         'name': name,
                                         }
            self._resource_keys.add(node)

        deleted_nodes = (set(self._resource_keys) -
                         set(self.dict_mors.keys()))
        for node in deleted_nodes:
            name = self.dict_mors.get(node)['name']
            nodename = self._create_nodename(node, name)
            del self._resources[nodename]
            self._resource_keys.discard(node)

    def plug_vifs(self, instance, network_info):
        _vmops = self._get_vmops_for_compute_node(instance['node'])
        _vmops.plug_vifs(
            instance,
            network_info,
            self.ovsport_info,
            self.pg_vlan_instance_map)

    def unplug_vifs(self, instance, network_info):
        _vmops = self._get_vmops_for_compute_node(instance['node'])
        _vmops.unplug_vifs(
            instance,
            network_info,
            self.ovsport_info,
            self.pg_vlan_instance_map,
            True)

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):
        """Create VM instance."""
        _vmops = self._get_vmops_for_compute_node(instance['node'])
        LOG.debug('Start to generate_portgroup', instance=instance)
        self._generate_portgroup(network_info, instance)
        LOG.debug('Generate_portgroup finished', instance=instance)
        _vmops.spawn(context, instance, image_meta, injected_files,
                     admin_password, network_info,
                     self.ovsport_info,
                     self.pg_vlan_instance_map,
                     block_device_info)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        """Destroy VM instance."""

        # Destroy gets triggered when Resource Claim in resource_tracker
        # is not successful. When resource claim is not successful,
        # node is not set in instance. Perform destroy only if node is set
        LOG.debug("Start to destory, instance:%(instance)s "
                  "network_info:%(network_info)s",
                  {'instance': instance, 'network_info': network_info})
        if not instance['node']:
            return

        _vmops = self._get_vmops_for_compute_node(instance['node'])
        _vmops.destroy(instance, destroy_disks)

        # remove error pg and relations
        LOG.debug("Start to clean_pg_relations check, instance:%(instance)s "
                  "network_info:%(network_info)s",
                  {'instance': instance, 'network_info': network_info})
        if None is network_info or len(network_info) == 0:
            self.clean_pg_and_relations_with_instance(instance)

        LOG.debug('Start to cleanup', instance=instance)
        # cleanup pg and bridge etc
        self.cleanup(context, instance, network_info,
                     self.ovsport_info, self.pg_vlan_instance_map,
                     block_device_info, destroy_disks, migrate_data)

        # remove the recode of nova-relations
        LOG.debug('Start to remove_port_relations', instance=instance)
        self.remove_port_relations(network_info, CONF.vmware.relation_files)

    def clean_pg_and_relations_with_instance(self, instance):
        instance_id = instance.uuid
        _vmops = self._get_vmops_for_compute_node(instance['node'])
        vif_ids = self._get_vif_by_instanceid(instance_id)
        for id in vif_ids:
            vmwarevif.remove_neutron_relation_pg(
                _vmops._session,
                _vmops._cluster,
                self.pg_vlan_instance_map[id])

            self._remove_pg_instance_vlan_relation(
                self.pg_vlan_instance_map[id],
                CONF.vmware.relation_files)
            self.available_pg_vlans.add(
                self.pg_vlan_instance_map[id].vlan)
            self.pg_vlan_instance_map.pop(id)

    def _get_vif_by_instanceid(self, instance_id):
        vif_ids = []
        for vif_id in self.pg_vlan_instance_map:
            if self.pg_vlan_instance_map[vif_id].instanceid == instance_id:
                vif_ids.append(vif_id)

        return vif_ids

    def cleanup(self, context, instance, network_info,
                ovsport_info, pg_vlan_instance_map,
                block_device_info=None, destroy_disks=True,
                migrate_data=None, destroy_vifs=True):
        if destroy_vifs:
            _vmops = self._get_vmops_for_compute_node(instance['node'])
            _vmops.unplug_vifs(
                instance,
                network_info,
                ovsport_info,
                pg_vlan_instance_map,
                True)

    def remove_port_relations(self, network_info, fileabname):
        for vif in network_info:
            if vif['id'] in self.pg_vlan_instance_map:
                self._remove_pg_instance_vlan_relation(
                    self.pg_vlan_instance_map[vif['id']],
                    fileabname)
                self.available_pg_vlans.add(
                    self.pg_vlan_instance_map[vif['id']].vlan)
                self.pg_vlan_instance_map.pop(vif['id'])

    # Remove pgname port in nova-relaitons
    def _remove_pg_instance_vlan_relation(
            self, portgroup_instance_mapping, fileabname):
        with open(fileabname, 'r') as f:
            with open(fileabname + '.tmp', 'w') as g:
                for line in f.readlines():
                    if len(line) > 1 and \
                            portgroup_instance_mapping.pg_name not in line:
                        g.write(line)
        shutil.move(fileabname + '.tmp', fileabname)
        utils.execute('chmod', '666', fileabname, run_as_root=True)

    # General a new pgname with a no used vlan tag
    def _generate_portgroup(self, network_info, instance):
        """
        Generate new pg name
        :return: pg name
        """
        if network_info is None:
            return None
        for vif in network_info:
            pgvid = self.available_pg_vlans.pop()
            pg_name = 'hybridpg-' + vif['id'] + str(pgvid)
            self.pg_vlan_instance_map[vif['id']] = \
                PortGroupInstanceMapping(pgvid, pg_name,
                                         CONF.vmware.ovs_dvs_name,
                                         instance.uuid,
                                         vif)
            self._save_pg_instance_vlan_relation(
                self.pg_vlan_instance_map[vif['id']],
                CONF.vmware.relation_files)

    def _save_pg_instance_vlan_relation(
            self, portgroup_instance_mapping, fileabname):
        with open(fileabname, 'a') as f:
            append_map = {}
            append_map['vifid'] = portgroup_instance_mapping.vif['id']
            append_map['vlan'] = portgroup_instance_mapping.vlan
            append_map['pg_name'] = portgroup_instance_mapping.pg_name
            append_map['dvs_name'] = portgroup_instance_mapping.dvs_name
            append_map['instanceid'] = portgroup_instance_mapping.instanceid
            append_map['bridge_name'] = \
                portgroup_instance_mapping.vif['network']['bridge']
            appendstr = str(append_map)
            f.write(appendstr + '\n')

    def _update_pg_instance_vlan_relation(self, fileabname):
        with open(fileabname, 'r') as f:
            for tmp_line in f:
                if tmp_line is not None and len(str(tmp_line)) > 1:
                    tmp_dict = eval(tmp_line.strip('\n'))
                    if tmp_dict is not None and tmp_dict['vifid'] is not None:
                        self.pg_vlan_instance_map[tmp_dict['vifid']] = \
                            PortGroupInstanceMapping(tmp_dict['vlan'],
                                                     tmp_dict['pg_name'],
                                                     tmp_dict['dvs_name'],
                                                     tmp_dict['instanceid'])
                        self.pg_vlan_instance_map[tmp_dict['vifid']].vif = \
                            {'id': tmp_dict['vifid'],
                             'network': {'bridge': tmp_dict['bridge_name']}}
                        self.available_pg_vlans.remove(tmp_dict['vlan'])


class PortGroupInstanceMapping:

    def __init__(self, vlan, pg_name, dvs_name, instanceid=None, vif=None):
        self.vlan = vlan
        self.pg_name = pg_name
        self.dvs_name = dvs_name
        self.instanceid = instanceid
        self.vif = vif

    def __str__(self):
        return ("pg-vlanid = %s pg-name = %s "
                "dvs_name = %s instance = %s vif = %s" %
                (self.vlan, self.pg_name, self.dvs_name,
                    self.instanceid, self.vif))
