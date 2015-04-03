"""
Class for VM tasks like spawn, snapshot, suspend, resume etc.
"""

import collections

from oslo.config import cfg

from nova import compute
from nova.compute import power_state
from nova.openstack.common import log as logging
from nova import utils
from nova.virt import configdrive
from nova.virt import driver
from nova.virt.vmwareapi import imagecache
from nova.virt.vmwareapi import vm_util
from nova.virt.vmwareapi import vmware_images
from nova.virt.vmwareapi import vmops
from nova.virt.hybridvmwareapi import vif as vmwarevif
from nova.network import linux_net
from nova.network import model as network_model


CONF = cfg.CONF
CONF.import_opt('image_cache_subdirectory_name', 'nova.virt.imagecache')
CONF.import_opt('remove_unused_base_images', 'nova.virt.imagecache')
CONF.import_opt('vnc_enabled', 'nova.vnc')
CONF.import_opt('my_ip', 'nova.netconf')

LOG = logging.getLogger(__name__)

VMWARE_POWER_STATES = {
    'poweredOff': power_state.SHUTDOWN,
    'poweredOn': power_state.RUNNING,
    'suspended': power_state.SUSPENDED}

RESIZE_TOTAL_STEPS = 4

DcInfo = collections.namedtuple('DcInfo',
                                ['ref', 'name', 'vmFolder'])


class VMwareVMOps(vmops.VMwareVMOps):

    """Management class for VM-related tasks."""

    def __init__(self, session, virtapi, volumeops, cluster=None,
                 datastore_regex=None):
        """Initializer."""
        self.compute_api = compute.API()
        self._session = session
        self._virtapi = virtapi
        self._volumeops = volumeops
        self._cluster = cluster
        self._datastore_regex = datastore_regex
        # Ensure that the base folder is unique per compute node
        if CONF.remove_unused_base_images:
            self._base_folder = '%s%s' % (CONF.my_ip,
                                          CONF.image_cache_subdirectory_name)
        else:
            # Aging disable ensures backward compatibility
            self._base_folder = CONF.image_cache_subdirectory_name
        self._tmp_folder = 'vmware_temp'
        self._default_root_device = 'vda'
        self._rescue_suffix = '-rescue'
        self._migrate_suffix = '-orig'
        self._datastore_dc_mapping = {}
        self._datastore_browser_mapping = {}
        self._imagecache = imagecache.ImageCacheManager(self._session,
                                                        self._base_folder)

    def build_virtual_machine(self, instance, instance_name, image_info,
                              dc_info, datastore, network_info,
                              pg_vlan_instance_map):
        node_mo_id = vm_util.get_mo_id_from_instance(instance)
        res_pool_ref = vm_util.get_res_pool_ref(self._session,
                                                self._cluster, node_mo_id)
        vif_infos = vmwarevif.get_vif_info(self._session,
                                           self._cluster,
                                           utils.is_neutron(),
                                           image_info.vif_model,
                                           network_info,
                                           pg_vlan_instance_map)

        allocations = self._get_cpu_allocations(instance.instance_type_id)

        # Get the create vm config spec
        client_factory = self._session._get_vim().client.factory
        config_spec = vm_util.get_vm_create_spec(client_factory,
                                                 instance,
                                                 instance_name,
                                                 datastore.name,
                                                 vif_infos,
                                                 image_info.os_type,
                                                 allocations=allocations)
        # Create the VM
        vm_ref = vm_util.create_vm(self._session, instance, dc_info.vmFolder,
                                   config_spec, res_pool_ref)
        return vm_ref

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info, ovsport_info,
              pg_vlan_instance_map, block_device_info=None,
              instance_name=None, power_on=True):

        client_factory = self._session._get_vim().client.factory
        image_info = vmware_images.VMwareImage.from_image(instance.image_ref,
                                                          image_meta)
        #add by liuling
        image_info.file_type = 'vmdk'
        vi = self._get_vm_config_info(instance, image_info, instance_name)

        # Creates the virtual machine. The virtual machine reference returned
        # is unique within Virtual Center.
        vm_ref = self.build_virtual_machine(instance,
                                            vi.instance_name,
                                            image_info,
                                            vi.dc_info,
                                            vi.datastore,
                                            network_info,
                                            pg_vlan_instance_map)

        # Cache the vm_ref. This saves a remote call to the VC. This uses the
        # instance_name. This covers all use cases including rescue and resize.
        vm_util.vm_ref_cache_update(vi.instance_name, vm_ref)

        # Set the machine.id parameter of the instance to inject
        # the NIC configuration inside the VM
        if CONF.flat_injected:
            self._set_machine_id(client_factory, instance, network_info)

        # Set the vnc configuration of the instance, vnc port starts from 5900
        if CONF.vnc_enabled:
            self._get_and_set_vnc_config(client_factory, instance)

        block_device_mapping = []
        if block_device_info is not None:
            block_device_mapping = driver.block_device_info_get_mapping(
                block_device_info)

        # NOTE(mdbooth): the logic here is that we ignore the image if there
        # are block device mappings. This behaviour is incorrect, and a bug in
        # the driver.  We should be able to accept an image and block device
        # mappings.
        if len(block_device_mapping) > 0:
            msg = "Block device information present: %s" % block_device_info
            # NOTE(mriedem): block_device_info can contain an auth_password
            # so we have to scrub the message before logging it.
            LOG.debug(logging.mask_password(msg), instance=instance)

            for root_disk in block_device_mapping:
                connection_info = root_disk['connection_info']
                # TODO(hartsocks): instance is unnecessary, remove it
                # we still use instance in many locations for no other purpose
                # than logging, can we simplify this?
                self._volumeops.attach_root_volume(connection_info, instance,
                                                   self._default_root_device,
                                                   vi.datastore.ref)
        else:
            self._imagecache.enlist_image(
                image_info.image_id, vi.datastore, vi.dc_info.ref)
            self._fetch_image_if_missing(context, vi)

            if image_info.is_iso:
                self._use_iso_image(vm_ref, vi)
            elif image_info.linked_clone:
                self._use_disk_image_as_linked_clone(vm_ref, vi)
            else:
                self._use_disk_image_as_full_clone(vm_ref, vi)

        if configdrive.required_by(instance):
            self._configure_config_drive(
                instance, vm_ref, vi.dc_info, vi.datastore,
                injected_files, admin_password)

        LOG.debug('Start to create network', instance=instance)
        self.create_network(
            instance,
            network_info,
            ovsport_info,
            pg_vlan_instance_map)
        LOG.debug('Create network finished', instance=instance)

        if power_on:
            vm_util.power_on_instance(self._session, instance, vm_ref=vm_ref)

    def create_network(
            self, instance, network_info, ovsport_info, pg_vlan_instance_map):
        self.plug_vifs(
            instance,
            network_info,
            ovsport_info,
            pg_vlan_instance_map)

    def plug_vifs(self, instance, network_info, ovsport_info,
                  pg_vlan_instance_map):
        """Plug VIFs into networks."""
        for vif in network_info:
            self.plug_ovs_hybrid(
                instance,
                vif,
                ovsport_info,
                pg_vlan_instance_map[
                    vif['id']])

    def plug_ovs_hybrid(
            self, instance, vif, ovsport_info, portgroup_instance_mapping):
        """Plug using hybrid strategy

        Create a per-VIF linux bridge, then link that bridge to the OVS
        integration bridge via a veth device, setting up the other end
        of the veth device just like a normal OVS port.  Then boot the
        VIF on the linux bridge using standard libvirt mechanisms.
        """
        iface_id = self.get_ovs_interfaceid(vif)
        br_name = self.get_br_name(vif['id'])
        v1_name, v2_name = self.get_veth_pair_names(vif['id'])
        gbr_name = self.get_gbr_name(vif['id'])
        tap_name, taq_name = self.get_gveth_pair_names(vif['id'])

        # add the first gbr to connect to the origin qbr
        if not linux_net.device_exists(gbr_name):
            utils.execute('brctl', 'addbr', gbr_name, run_as_root=True)
            utils.execute('brctl', 'setfd', gbr_name, 0, run_as_root=True)
            utils.execute('brctl', 'stp', gbr_name, 'off', run_as_root=True)
            utils.execute('tee',
                          ('/sys/class/net/%s/bridge/multicast_snooping' %
                           gbr_name),
                          process_input='0',
                          run_as_root=True,
                          check_exit_code=[0, 1])

        if not linux_net.device_exists(tap_name):
            linux_net._create_veth_pair(tap_name, taq_name)
            utils.execute(
                'ip',
                'link',
                'set',
                gbr_name,
                'up',
                run_as_root=True)
            utils.execute(
                'brctl',
                'addif',
                gbr_name,
                taq_name,
                run_as_root=True)

        # add the second qbr to connect to the origin ovs br-int
        if not linux_net.device_exists(br_name):
            utils.execute('brctl', 'addbr', br_name, run_as_root=True)
            utils.execute('brctl', 'setfd', br_name, 0, run_as_root=True)
            utils.execute('brctl', 'stp', br_name, 'off', run_as_root=True)
            utils.execute('tee',
                          ('/sys/class/net/%s/bridge/multicast_snooping' %
                           br_name),
                          process_input='0',
                          run_as_root=True,
                          check_exit_code=[0, 1])
            utils.execute(
                'brctl',
                'addif',
                br_name,
                tap_name,
                run_as_root=True)

        if not linux_net.device_exists(v2_name):
            linux_net._create_veth_pair(v1_name, v2_name)
            utils.execute('ip', 'link', 'set', br_name, 'up', run_as_root=True)
            utils.execute('brctl', 'addif', br_name, v1_name, run_as_root=True)
            linux_net.create_ovs_vif_port(self.get_bridge_name(vif),
                                          v2_name, iface_id, vif['address'],
                                          instance['uuid'])

        # connect qbrxxxx to nic
        ovs_nicport = ovsport_info['ovs_ethport']
        vlan_tag = str(portgroup_instance_mapping.vlan)
        nic_name = ovs_nicport + '.' + vlan_tag
        if not linux_net.device_exists(nic_name):
            try:
                # ifup ovs_ethport
                utils.execute('ifconfig', ovs_nicport, 'up', run_as_root=True)

                # add brif
                utils.execute('vconfig', 'add', ovs_nicport, vlan_tag,
                              run_as_root=True)

                # up the if
                utils.execute('ifconfig', nic_name, 'up', run_as_root=True)

                self.connect_nic_to_br(instance, gbr_name, nic_name)
            except Exception as exc:
                LOG.exception(exc, instance=instance)
            LOG.debug(
                'Connect nic to br finished, vir:%s',
                vif,
                instance=instance)

    def get_ovs_interfaceid(self, vif):
        return vif.get('ovs_interfaceid') or vif['id']

    def get_br_name(self, iface_id):
        return ("qbr" + iface_id)[:network_model.NIC_NAME_LEN]

    def get_gbr_name(self, iface_id):
        """generate the security supported br"""
        return ("qgr" + iface_id)[:network_model.NIC_NAME_LEN]

    def get_gveth_pair_names(self, iface_id):
        """generate the security supported pair veth"""
        return (("tap%s" % iface_id)[:network_model.NIC_NAME_LEN],
                ("taq%s" % iface_id)[:network_model.NIC_NAME_LEN])

    def get_veth_pair_names(self, iface_id):
        return (("qvb%s" % iface_id)[:network_model.NIC_NAME_LEN],
                ("qvo%s" % iface_id)[:network_model.NIC_NAME_LEN])

    # connect the nic to the qbrxxxx
    def connect_nic_to_br(self, instance, br_name, nic_name):
        utils.execute('brctl', 'addif', br_name, nic_name, run_as_root=True)

    def get_bridge_name(self, vif):
        return vif['network']['bridge']

    def unplug_vifs(self, instance, network_info, ovsport_info,
                    pg_vlan_instance_map, ignore_errors):
        """Unplug VIFs from networks."""
        for vif in network_info:
            if vif['id'] in pg_vlan_instance_map:
                self.unplug_ovs(
                    instance,
                    vif,
                    ovsport_info,
                    pg_vlan_instance_map[
                        vif['id']])
                vmwarevif.remove_neutron_relation_pg(
                    self._session,
                    self._cluster,
                    pg_vlan_instance_map[
                        vif['id']])

    def unplug_ovs(self, instance, vif, ovsport_info,
                   portgroup_instance_mapping):
        self.unplug_ovs_hybrid(
            instance,
            vif,
            ovsport_info,
            portgroup_instance_mapping)

    def unplug_ovs_hybrid(
            self, instance, vif, ovsport_info, portgroup_instance_mapping):
        """UnPlug using hybrid strategy

        Unhook port from OVS, unhook port from bridge, delete
        bridge, and delete both veth devices.
        """

        # now dirver use the configed nic eth0.100 instead
        ovs_nicport = ovsport_info['ovs_ethport']
        vlan_tag = str(portgroup_instance_mapping.vlan)
        nic_name = ovs_nicport + '.' + vlan_tag

        # remove the eth1 vlan config
        try:
            # try to delete the exists nic_name in whatever br
            utils.execute('vconfig', 'rem', nic_name, run_as_root=True)
        except Exception as exc:
            LOG.exception(exc, instance=instance)

        try:
            br_name = self.get_br_name(vif['id'])
            v1_name, v2_name = self.get_veth_pair_names(vif['id'])
            gbr_name = self.get_gbr_name(vif['id'])
            tap_name, taq_name = self.get_gveth_pair_names(vif['id'])

            if linux_net.device_exists(br_name):
                utils.execute('brctl', 'delif', br_name, v1_name,
                              run_as_root=True)
                utils.execute('brctl', 'delif', br_name, tap_name,
                              run_as_root=True)
                utils.execute('ip', 'link', 'set', br_name, 'down',
                              run_as_root=True)
                utils.execute('brctl', 'delbr', br_name,
                              run_as_root=True)

            linux_net.delete_ovs_vif_port(self.get_bridge_name(vif),
                                          v2_name)

            if linux_net.device_exists(gbr_name):
                utils.execute('brctl', 'delif', gbr_name, taq_name,
                              run_as_root=True)
                utils.execute('ip', 'link', 'set', gbr_name, 'down',
                              run_as_root=True)
                utils.execute('brctl', 'delbr', gbr_name,
                              run_as_root=True)

            # delete veth peer
            linux_net.delete_net_dev(v1_name)
            linux_net.delete_net_dev(v2_name)
            linux_net.delete_net_dev(tap_name)
            linux_net.delete_net_dev(taq_name)
        except Exception as exc:
            LOG.exception(exc, instance=instance)

    def unplug_ovs_bridge(self, instance, vif):
        """No manual unplugging required."""
        pass
