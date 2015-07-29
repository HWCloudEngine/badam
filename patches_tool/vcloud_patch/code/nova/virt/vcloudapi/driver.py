# Copyright 2011 OpenStack Foundation
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
A connection to the VMware vCloud platform.
"""

import re
import contextlib
import subprocess
import os
import time
import suds
import urllib2
import shutil

from lxml import etree

from oslo.config import cfg
from oslo.vmware import api
from oslo.vmware import vim

from nova.compute import power_state
from nova.compute import task_states
from nova.console import type as ctype
from nova import exception
from nova import utils
from nova import objects
from nova import image
from nova.i18n import _, _LI, _LW
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.openstack.common import uuidutils
from nova.openstack.common import fileutils as fileutils
from nova.virt import driver
from nova.virt import diagnostics
from nova.virt import virtapi
from nova.virt.vcloudapi import vcenter_utils
from nova.virt.vcloudapi import vcloud_network_utils
from nova.virt.vcloudapi import util
from nova.virt.vcloudapi.vcloudair import *
from nova.virt.vcloudapi.vcloudair import VCloudAPISession as VCASession

from nova.virt.vcloudapi import vcloud_task_states

vcloudapi_opts = [

    cfg.StrOpt('vcloud_node_name',
               default='vcloud_node_01',
               help='node name,which a node is a vcloud vcd '
               'host.'),
    cfg.StrOpt('vcloud_host_ip',
               help='Hostname or IP address for connection to VMware VCD '
               'host.'),
    cfg.IntOpt('vcloud_host_port',
               default=443,
               help='Host port for cnnection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_host_username',
               help='Host username for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_host_password',
               help='Host password for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_org',
               help='User org for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_vdc',
               help='Vdc for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_version',
               default='5.5',
               help='Version for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_service',
               default='85-719',
               help='Service for connection to VMware VCD '
               'host.'),
    cfg.BoolOpt('vcloud_verify',
                default=False,
                help='Verify for connection to VMware VCD '
                'host.'),
    cfg.StrOpt('vcloud_service_type',
               default='vcd',
               help='Service type for connection to VMware VCD '
               'host.'),
    cfg.IntOpt('vcloud_api_retry_count',
               default=2,
               help='Api retry count for connection to VMware VCD '
               'host.'),
    cfg.StrOpt('vcloud_ovs_ethport',
               default='eth1',
               help='The eth port of ovs-vm use '
               'to connect vm openstack create '),

    cfg.StrOpt('vcloud_conversion_dir',
               default='/vcloud/convert_tmp',
               help='the directory where images are converted in '),

    cfg.StrOpt('vcloud_volumes_dir',
               default='/vcloud/volumes',
               help='the directory of volume files'),

    cfg.StrOpt('vcloud_dvs_name',
               default='nkapotoxinSwitch',
               help='the dvs of the vcd used'),

    cfg.StrOpt('vcloud_vm_naming_rule',
               default='openstack_vm_id',
               help='the rule to name vcloud VMs, valid options: openstack_vm_id, openstack_vm_name, cascaded_openstack_rule'),

    cfg.DictOpt('vcloud_flavor_map',
                default={
                    'm1.tiny': '1',
                    'm1.small': '2',
                    'm1.medium': '3',
                    'm1.large': '4',
                    'm1.xlarge': '5'},
                help='map nova flavor name to vcloud vm specification id'),

]

status_dict_vapp_to_instance = {
    VCLOUD_STATUS.FAILED_CREATION: power_state.CRASHED,
    VCLOUD_STATUS.UNRESOLVED: power_state.BUILDING,
    VCLOUD_STATUS.RESOLVED: power_state.BUILDING,
    VCLOUD_STATUS.DEPLOYED: power_state.NOSTATE,
    VCLOUD_STATUS.SUSPENDED: power_state.SUSPENDED,
    VCLOUD_STATUS.POWERED_ON: power_state.RUNNING,
    VCLOUD_STATUS.WAITING_FOR_INPUT: power_state.NOSTATE,
    VCLOUD_STATUS.UNKNOWN: power_state.NOSTATE,
    VCLOUD_STATUS.UNRECOGNIZED: power_state.NOSTATE,
    VCLOUD_STATUS.POWERED_OFF: power_state.SHUTDOWN,
    VCLOUD_STATUS.INCONSISTENT_STATE: power_state.NOSTATE,
    VCLOUD_STATUS.MIXED: power_state.NOSTATE,
    VCLOUD_STATUS.DESCRIPTOR_PENDING: power_state.NOSTATE,
    VCLOUD_STATUS.COPYING_CONTENTS: power_state.NOSTATE,
    VCLOUD_STATUS.DISK_CONTENTS_PENDING: power_state.NOSTATE,
    VCLOUD_STATUS.QUARANTINED: power_state.NOSTATE,
    VCLOUD_STATUS.QUARANTINE_EXPIRED: power_state.NOSTATE,
    VCLOUD_STATUS.REJECTED: power_state.NOSTATE,
    VCLOUD_STATUS.TRANSFER_TIMEOUT: power_state.NOSTATE,
    VCLOUD_STATUS.VAPP_UNDEPLOYED: power_state.NOSTATE,
    VCLOUD_STATUS.VAPP_PARTIALLY_DEPLOYED: power_state.NOSTATE,
}


CONF = cfg.CONF
CONF.register_opts(vcloudapi_opts, 'vcloud')

LOG = logging.getLogger(__name__)


IMAGE_API = image.API()


class VCloudNode(object):

    def __init__(self, name, **args):
        self.name = name
        for key in args.keys():
            self.__setattr__(key, args.get(key))


class VMwareVcloudDriver(driver.ComputeDriver):

    """The VCloud host connection object."""

    def __init__(self, virtapi, scheme="https"):
        self.instances = {}
        self._node_name = CONF.vcloud.vcloud_node_name
        self._session = VCloudAPISession(scheme=scheme)

        if not os.path.exists(CONF.vcloud.vcloud_conversion_dir):
            os.makedirs(CONF.vcloud.vcloud_conversion_dir)

        if not os.path.exists(CONF.vcloud.vcloud_volumes_dir):
            os.makedirs(CONF.vcloud.vcloud_volumes_dir)

        super(VMwareVcloudDriver, self).__init__(virtapi)

        self.init_vcenterapi()
        self.ovsport_info = {'ovs_ethport': CONF.vcloud.vcloud_ovs_ethport}

    def init_vcenterapi(self):
        self._vcenterapi = vcenter_utils.VCenterAPI()

    def create_networks(self, network_info):
        """create cloud networks"""
        for vif in network_info:
            self._create_org_vdc_network(vif)

    def delete_networks(self, network_info, ignore_errors):
        """docstring for delete_networks"""
        for vif in network_info:
            try:
                self._delete_org_vdc_network(vif)
            except Exception:
                if not ignore_errors:
                    raise
                LOG.error("Delete network error, vif:%s" % vif, exc_info=True)

    def _create_org_vdc_network(self, vif):
        return vcloud_network_utils.create_org_vdc_network(self._session,
                                                           self._session._vdc,
                                                           vif)

    def _delete_org_vdc_network(self, vif):
        return vcloud_network_utils.delete_org_vdc_network(self._session,
                                                           self._session._vdc,
                                                           vif)

    def _get_vcloud_vdc(self):
        return self._session._call_method(self._session.vca,
                                          "get_vdc",
                                          self._session.vdc)

    def _get_vcloud_vapp(self, vapp_name):

        the_vdc = self._session._call_method(self._session.vca,
                                             "get_vdc",
                                             self._session.vdc)

        the_vapp = self._session._call_method(self._session.vca,
                                              "get_vapp",
                                              the_vdc,
                                              vapp_name)

        if not the_vapp:
            #raise exception.NovaException("can't find the vapp")
            LOG.info("can't find the vapp %s" % vapp_name)
            return None
        else:
            return the_vapp

    def _power_off_vapp(self, the_vapp):
        task_stop = self._session._call_method(the_vapp,
                                               "undeploy")
        if not task_stop:
            raise exception.NovaException(
                "undeploy vapp failed, task")
        self._session._wait_for_task(task_stop)
        return self._get_vcloud_vapp(the_vapp.name)

    def _power_on_vapp(self, the_vapp):
        task = self._session._call_method(the_vapp, "poweron")
        if not task:
            raise exception.NovaException(
                "deploy vapp failed, task")
        self._session._wait_for_task(task)
        return self._get_vcloud_vapp(the_vapp.name)

    def _delete_vapp(self, the_vapp):
        task = self._session._call_method(the_vapp, "delete")
        if not task:
            raise exception.NovaException(
                "delete vapp failed, task: %s" % task)
        self._session._wait_for_task(task)

    def _query_vmdk_url(self, the_vapp):
        # node_name = instance.node

        # 0. shut down the app first
        try:
            the_vapp = self._power_off_vapp(the_vapp)
        except:
            LOG.error('power off failed')

        # 1.enable download.
        task = self._session._call_method(the_vapp, 'enableDownload')
        if not task:
            raise exception.NovaException(
                "enable vmdk file download failed, task:")
        self._session._wait_for_task(task)

        # 2.get vapp info and ovf descriptor
        the_vapp = self._get_vcloud_vapp(the_vapp.name)
        # the_vapp = self._session._call_method(the_vapp, 'get_updated_vapp')

        ovf = self._session._call_method(the_vapp, 'get_ovf_descriptor')

        # 3.get referenced file url
        referenced_file_url = self._session._call_method(
            the_vapp,
            'get_referenced_file_url',
            ovf)
        if not referenced_file_url:
            raise exception.NovaException(
                "get vmdk file url failed")
        return referenced_file_url

    def init_host(self, host):
        return

    def list_instances(self):
        # xxx
        return self.instances.keys()

    def list_instance_uuids(self):
        return

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        for vif in network_info:
            vcloud_network_utils.plug_vif(
                self._vcenterapi,
                instance,
                vif,
                self.ovsport_info)

    def _unplug_vifs(self, instance, network_info, ignore_errors=False):
        for vif in network_info:
            try:
                vcloud_network_utils.unplug_vif(
                    self._vcenterapi,
                    instance,
                    vif,
                    self.ovsport_info)
            except Exception:
                if not ignore_errors:
                    raise
                LOG.error("Unplug vif error, vif:%s" % vif, instance=instance,
                          exc_info=True)

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        self._unplug_vifs(instance, network_info)

    def _add_mac_address_to_ovf(self, ovf_name, mac_address):
        tree = etree.parse(ovf_name)
        root = tree.getroot()
        namespace_ovf = 'http://schemas.dmtf.org/ovf/envelope/1'
        namespace_cim = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"\
            "CIM_ResourceAllocationSettingData"
        eth_tag = 'Item'
        resource_type_tag = 'ResourceType'
        mac_tag = 'Address'
        eth_resource_type_id = '10'
        xpath_eth = ".//{%s}%s[{%s}%s='%s']" % (namespace_ovf,
                                                eth_tag,
                                                namespace_cim,
                                                resource_type_tag,
                                                eth_resource_type_id)
        elmt_eth = root.find(xpath_eth)

        xpath_mac = "{%s}%s" % (namespace_cim, mac_tag)
        elmt_eth.insert(0, etree.Element(xpath_mac))

        elmt_eth[0].text = mac_address

        fileutils.delete_if_exists(ovf_name)
        tree.write(ovf_name)

    def _update_vm_task_state(self, instance, task_state):
        instance.task_state = task_state
        instance.save()

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None):

        #import pdb
        # pdb.set_trace()

        LOG.debug('[vcloud nova driver] spawn: %s' % instance.uuid)

        mac_address = ''
        if len(network_info) > 0:
            mac_address = network_info[0]['address']

        name = instance['name']
        state = power_state.BUILDING

        # 0.get vorg, user name,password vdc  from configuration file (only one
        # org)

        node_name = instance.node

        vorg_name = self._session.org
        user_name = self._session.username
        password = self._session.password
        vdc_name = self._session.vdc
        vcloud_host = self._session.host_ip

        # 1.1 get image id, vm info ,flavor info
        # image_uuid = instance.image_ref
        if 'id' in image_meta:
            # create from image
            image_uuid = image_meta['id']
        else:
            # create from volume
            image_uuid = image_meta['properties']['image_id']

        vm_uuid = instance.uuid
        vm_name = instance.name
        vm_hostname = instance.hostname
        #vm_flavor_id = instance.get_flavor().flavorid
        vm_flavor_name = instance.get_flavor().name
        vcloud_flavor_id = CONF.vcloud.vcloud_flavor_map[vm_flavor_name]
        vm_task_state = instance.task_state

        # 1.3 (optional)
        is_poweron = True

        # 2~3 get vmdk file. check if the image or volume vmdk file cached first
        image_cache_dir = CONF.vcloud.vcloud_conversion_dir
        volume_cache_dir = CONF.vcloud.vcloud_volumes_dir

        this_conversion_dir = '%s/%s' % (CONF.vcloud.vcloud_conversion_dir, vm_uuid)
        fileutils.ensure_tree(this_conversion_dir)
        os.chdir(this_conversion_dir)

        converted_file_name = this_conversion_dir + \
            '/converted-file.vmdk'

        block_device_mapping = driver.block_device_info_get_mapping(
            block_device_info)

        image_vmdk_file_name = '%s/%s.vmdk' % (
            image_cache_dir, image_uuid)

        volume_file_name = ''
        if len(block_device_mapping) > 0:
            volume_id = block_device_mapping[0][
                'connection_info']['data']['volume_id']
            volume_file_name = '%s/%s.vmdk' % (
                volume_cache_dir, volume_id)

        # 2.1 check if the image or volume vmdk file cached
        if os.path.exists(volume_file_name):
            # if volume cached, move the volume file to conversion dir
            shutil.move(volume_file_name, converted_file_name)
        elif os.path.exists(image_vmdk_file_name):
            # if image cached, copy ghe image file to conversion dir
            shutil.copy2(image_vmdk_file_name, converted_file_name)
        else:
            # if NOT cached, download qcow2 file from glance to local, then convert it to vmdk
            # tmp_dir = '/hctemp'
            self._update_vm_task_state(
                instance,
                task_state=vcloud_task_states.DOWNLOADING)

            metadata = IMAGE_API.get(context, image_uuid)
            file_size = int(metadata['size'])
            read_iter = IMAGE_API.download(context, image_uuid)
            glance_file_handle = util.GlanceFileRead(read_iter)

            orig_file_name = this_conversion_dir + \
                '/' + image_uuid + '.tmp'
            orig_file_handle = fileutils.file_open(orig_file_name, "wb")

            util.start_transfer(context, glance_file_handle, file_size,
                                write_file_handle=orig_file_handle, task_state=vcloud_task_states.DOWNLOADING, instance=instance)

            # 2.2. convert to vmdk
            self._update_vm_task_state(
                instance,
                task_state=vcloud_task_states.CONVERTING)

            if metadata["disk_format"] == 'qcow2':
                convert_commond = "qemu-img convert -f %s -O %s %s %s" % \
                    ('qcow2',
                     'vmdk',
                     orig_file_name,
                     converted_file_name)
                convert_result = subprocess.call([convert_commond], shell=True)

                if convert_result != 0:
                    LOG.error('convert qcow2 to vmdk failed')
                    # do something, change metadata
                    # file_size = os.path.getsize(converted_file_name)
            elif metadata["disk_format"] == 'raw':
                convert_commond = "qemu-img convert -f %s -O %s %s %s" % \
                    ('raw',
                     'vmdk',
                     orig_file_name,
                     converted_file_name)
                convert_result = subprocess.call([convert_commond], shell=True)

                if convert_result != 0:
                    LOG.error('convert qcow2 to vmdk failed')
                    # do something, change metadata
                    # file_size = os.path.getsize(converted_file_name)
            else:
                os.rename(orig_file_name, converted_file_name)

            shutil.copy2(converted_file_name,image_vmdk_file_name)

        # 3. vmdk to ovf
        self._update_vm_task_state(
            instance,
            task_state=vcloud_task_states.PACKING)

        vmx_file_dir = '%s/%s' % (CONF.vcloud.vcloud_conversion_dir,'vmx')
        vmx_name = 'base-%s.vmx' % vcloud_flavor_id
        vmx_cache_full_name = '%s/%s' % (vmx_file_dir, vmx_name)
        vmx_full_name = '%s/%s' % (this_conversion_dir, vmx_name)
        shutil.copy2(vmx_cache_full_name, vmx_full_name)

        ovf_name = '%s/%s.ovf' % (this_conversion_dir,vm_uuid)

        mk_ovf_cmd = "ovftool -o %s %s" % (vmx_full_name, ovf_name)
        mk_ovf_result = subprocess.call(mk_ovf_cmd, shell=True)

        if mk_ovf_result != 0:
            LOG.error('make ovf faild!')
            self._update_vm_task_state(instance, task_state=vm_task_state)
            return
        # add mac address to ovf
        if mac_address != '':
            self._add_mac_address_to_ovf(ovf_name, mac_address)

        # 5~6: UPLOAD ovf to vcloud and create a vm
        # todo:5. upload ovf to vcloud template, using image's uuid as template name
        # todo:6. create vm from template
        self._update_vm_task_state(
            instance,
            task_state=vcloud_task_states.NETWORK_CREATING)
        self.create_networks(network_info)
        net_name = None
        for vif in network_info:
            net_name = vif['id']
        self.plug_vifs(instance, network_info)

        self._update_vm_task_state(
            instance,
            task_state=vcloud_task_states.IMPORTING)
        vapp_name = self._get_vcloud_vapp_name(instance)
        if not net_name:
            if is_poweron:
                create_vapp_cmd = 'ovftool --powerOn' \
                    ' %s "vcloud://%s:%s@%s?org=%s&vdc=%s&vapp=%s"' % \
                    (ovf_name,
                     user_name,
                     password,
                     vcloud_host,
                     vorg_name,
                     vdc_name,
                     vapp_name)
            else:
                create_vapp_cmd = 'ovftool  %s "vcloud://%s:%s@%s?org=%s&vdc=%s&vapp=%s"' % \
                    (ovf_name,
                     user_name,
                     password,
                     vcloud_host,
                     vorg_name,
                     vdc_name,
                     vapp_name)
        else:
            if is_poweron:
                create_vapp_cmd = 'ovftool --powerOn --net:"VM Network=%s"' \
                    ' %s "vcloud://%s:%s@%s?org=%s&vdc=%s&vapp=%s"' % \
                    (net_name,
                     ovf_name,
                     user_name,
                     password,
                     vcloud_host,
                     vorg_name,
                     vdc_name,
                     vapp_name)
            else:
                create_vapp_cmd = 'ovftool --net:"VM Network=%s" %s "vcloud://%s:%s@%s?org=%s&vdc=%s&vapp=%s"' % \
                    (net_name,
                     ovf_name,
                     user_name,
                     password,
                     vcloud_host,
                     vorg_name,
                     vdc_name,
                     vapp_name)

        fileutils.delete_if_exists(
            '%s/%s.mf' % (this_conversion_dir, vm_uuid))
        create_vapp_cmd_result = subprocess.call(create_vapp_cmd, shell=True)

        if create_vapp_cmd_result != 0:
            LOG.error('create vapp faild!')
            self._update_vm_task_state(instance, task_state=vm_task_state)
            return

        self._update_vm_task_state(
            instance,
            task_state=vcloud_task_states.VM_CREATING)
        # import pdb
        # pdb.set_trace()
        if is_poweron:
            expected_vapp_status = VCLOUD_STATUS.POWERED_ON
        else:
            expected_vapp_status = VCLOUD_STATUS.POWERED_OFF

        vapp_name = self._get_vcloud_vapp_name(instance)
        vapp_status = self._get_vcloud_vapp_status(vapp_name)
        LOG.debug('vapp status: %s' % vapp_status)
        retry_times = 60
        while vapp_status != expected_vapp_status and retry_times > 0:
            time.sleep(3)
            vapp_status = self._get_vcloud_vapp_status(vapp_name)
            LOG.debug('vapp status: %s' % vapp_status)
            retry_times = retry_times - 1

        # 7. clean up
        self._update_vm_task_state(instance, task_state=vm_task_state)
        shutil.rmtree(this_conversion_dir, ignore_errors=True)
        # os.chdir(CONF.vcloud.vcloud_conversion_dir)
        # fileutils.delete_if_exists(orig_file_name)
        # fileutils.delete_if_exists(ovf_name)
        # fileutils.delete_if_exists(vm_uuid + '-disk1.vmdk')
        # os.rename(converted_file_name, image_vmdk_file_name)

    def _get_vcloud_vapp_status(self, vapp_name):
        the_vapp = self._get_vcloud_vapp(vapp_name)
        return the_vapp.me.status

    def _get_vcloud_vapp_name(self, instance):
        if CONF.vcloud.vcloud_vm_naming_rule == 'openstack_vm_id':
            return instance.uuid
        elif CONF.vcloud.vcloud_vm_naming_rule == 'openstack_vm_name':
            return instance.display_name
        elif CONF.vcloud.vcloud_vm_naming_rule == 'cascaded_openstack_rule':
            return instance.display_name
        else:
            return instance.uuid

    def _download_vmdk_from_vcloud(self, context, src_url, dst_file_name):

        # local_file_handle = open(dst_file_name, "wb")
        local_file_handle = fileutils.file_open(dst_file_name, "wb")

        remote_file_handle = urllib2.urlopen(src_url)
        file_size = remote_file_handle.headers['content-length']

        util.start_transfer(context, remote_file_handle, file_size,
                            write_file_handle=local_file_handle)

    def _upload_image_to_glance(
            self, context, src_file_name, image_id, instance):

        vm_task_state = instance.task_state
        file_size = os.path.getsize(src_file_name)
        read_file_handle = fileutils.file_open(src_file_name, "rb")

        metadata = IMAGE_API.get(context, image_id)

        # The properties and other fields that we need to set for the image.
        image_metadata = {"disk_format": "qcow2",
                          "is_public": "false",
                          "name": metadata['name'],
                          "status": "active",
                          "container_format": "bare",
                          "size": file_size,
                          "properties": {"owner_id": instance['project_id']}}

        util.start_transfer(context, read_file_handle, file_size,
                            image_id=metadata['id'], image_meta=image_metadata, task_state=task_states.IMAGE_UPLOADING, instance=instance)
        self._update_vm_task_state(instance, task_state=vm_task_state)

    def snapshot(self, context, instance, image_id, update_task_state):

        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)
        # 1. get vmdk url
        vapp_name = self._get_vcloud_vapp_name(instance)
        the_vapp = self._get_vcloud_vapp(vapp_name)

        remote_vmdk_url = self._query_vmdk_url(the_vapp)

        # 2. download vmdk
        temp_dir = '%s/%s' % (CONF.vcloud.vcloud_conversion_dir, instance.uuid)
        fileutils.ensure_tree(temp_dir)

        vmdk_name = remote_vmdk_url.split('/')[-1]
        local_file_name = '%s/%s' % (temp_dir, vmdk_name)

        self._download_vmdk_from_vcloud(
            context,
            remote_vmdk_url,
            local_file_name)

        # 3. convert vmdk to qcow2
        converted_file_name = temp_dir + '/converted-file.qcow2'
        convert_commond = "qemu-img convert -f %s -O %s %s %s" % \
            ('vmdk',
             'qcow2',
             local_file_name,
             converted_file_name)
        convert_result = subprocess.call([convert_commond], shell=True)

        if convert_result != 0:
            # do something, change metadata
            LOG.error('converting file failed')

        # 4. upload qcow2 to image repository\
        update_task_state(task_state=task_states.IMAGE_UPLOADING,
                          expected_state=task_states.IMAGE_PENDING_UPLOAD)

        self._upload_image_to_glance(
            context,
            converted_file_name,
            image_id,
            instance)

        # 5. delete temporary files
        shutil.rmtree(temp_dir, ignore_errors=True)
        # fileutils.delete_if_exists(local_file_name)
        # fileutils.delete_if_exists(converted_file_name)

#         if instance['name'] not in self.instances:
#             raise exception.InstanceNotRunning(instance_id=instance['uuid'])
#         update_task_state(task_state=task_states.IMAGE_UPLOADING)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        pass

    @staticmethod
    def get_host_ip_addr():
        pass
        # return '192.168.0.1'

    def set_admin_password(self, instance, new_pass):
        pass

    def inject_file(self, instance, b64_path, b64_contents):
        pass

    def resume_state_on_host_boot(self, context, instance, network_info,
                                  block_device_info=None):
        pass

    def rescue(self, context, instance, network_info, image_meta,
               rescue_password):
        pass

    def unrescue(self, instance, network_info):
        pass

    def poll_rebooting_instances(self, timeout, instances):
        pass

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   flavor, network_info,
                                   block_device_info=None,
                                   timeout=0, retry_interval=0):
        pass

    def finish_revert_migration(self, context, instance, network_info,
                                block_device_info=None, power_on=True):
        pass

    def post_live_migration_at_destination(self, context, instance,
                                           network_info,
                                           block_migration=False,
                                           block_device_info=None):
        pass

    def power_off(self, instance, shutdown_timeout=0, shutdown_attempts=0):
        vapp_name = self._get_vcloud_vapp_name(instance)
        the_vapp = self._get_vcloud_vapp(vapp_name)

        try:
            self._power_off_vapp(the_vapp)
        except:
            LOG.error('power off failed')

    def power_on(self, context, instance, network_info, block_device_info):
        vapp_name = self._get_vcloud_vapp_name(instance)
        the_vapp = self._get_vcloud_vapp(vapp_name)
        self._power_on_vapp(the_vapp)

    def soft_delete(self, instance):
        pass

    def restore(self, instance):
        pass

    def pause(self, instance):
        pass

    def unpause(self, instance):
        pass

    def suspend(self, instance):
        pass

    def resume(self, context, instance, network_info, block_device_info=None):
        pass

    def _do_destroy_vm(self, context, instance, network_info, block_device_info=None,
                       destroy_disks=True, migrate_data=None):

        is_quick_delete = bool(
            instance.metadata.get(
                'quick_delete_once',
                False))

        instance.metadata['quick_delete_once'] = False
        instance.save()

        try:
            vapp_name = self._get_vcloud_vapp_name(instance)
            the_vapp = self._get_vcloud_vapp(vapp_name)
        except:
            LOG.info("can't find the vapp %s" % instance.uuid)
            return

        try:
            the_vapp = self._power_off_vapp(the_vapp)
        except:
            LOG.error('power off failed')

        vm_task_state = instance.task_state

        if not (is_quick_delete):

            # if the vm have volumes, download the first volume to local
            # directory
            block_device_mapping = driver.block_device_info_get_mapping(
                block_device_info)
            if len(block_device_mapping) > 0:
                # get first block device
                # remote_vmdk_url = vca.get_vapp_referenced_file_url(the_vapp)
                try:
                    self._update_vm_task_state(
                        instance,
                        vcloud_task_states.EXPORTING)
                    remote_vmdk_url = self._query_vmdk_url(the_vapp)
                except:
                    LOG.error('Getting Remote VMDK Url failed')
                    # return
                # download vmdk to local
                else:
                    volume_id = block_device_mapping[0][
                        'connection_info']['data']['volume_id']
                    local_filename = '%s/%s.vmdk' % (
                        CONF.vcloud.vcloud_volumes_dir, volume_id)
                    self._download_vmdk_from_vcloud(
                        context,
                        remote_vmdk_url,
                        local_filename)

        self._update_vm_task_state(instance, vm_task_state)
        self._delete_vapp(the_vapp)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        # import pdb
        # pdb.set_trace()
        LOG.debug('[vcloud nova driver] destroy: %s' % instance.uuid)
        self._do_destroy_vm(context, instance, network_info, block_device_info,
                            destroy_disks, migrate_data)

        self.cleanup(context, instance, network_info, block_device_info,
                     destroy_disks, migrate_data)

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True):
        if destroy_vifs:
            self._unplug_vifs(instance, network_info, True)
            self.delete_networks(network_info, True)

        LOG.debug("Cleanup network finished", instance=instance)

    def attach_volume(self, context, connection_info, instance, mountpoint,
                      disk_bus=None, device_type=None, encryption=None):
        """Attach the disk to the instance at mountpoint using info."""
#         instance_name = instance['name']
#         if instance_name not in self._mounts:
#             self._mounts[instance_name] = {}
#         self._mounts[instance_name][mountpoint] = connection_info

    def detach_volume(self, connection_info, instance, mountpoint,
                      encryption=None):
        """Detach the disk attached to the instance."""
#         try:
#             del self._mounts[instance['name']][mountpoint]
#         except KeyError:
#             pass

    def swap_volume(self, old_connection_info, new_connection_info,
                    instance, mountpoint, resize_to):
        """Replace the disk attached to the instance."""
#         instance_name = instance['name']
#         if instance_name not in self._mounts:
#             self._mounts[instance_name] = {}
#         self._mounts[instance_name][mountpoint] = new_connection_info

    def attach_interface(self, instance, image_meta, vif):
        pass
#         if vif['id'] in self._interfaces:
#             raise exception.InterfaceAttachFailed(
#                     instance_uuid=instance['uuid'])
#         self._interfaces[vif['id']] = vif

    def detach_interface(self, instance, vif):
        pass
#         try:
#             del self._interfaces[vif['id']]
#         except KeyError:
#             raise exception.InterfaceDetachFailed(
#                     instance_uuid=instance['uuid'])

    def get_info(self, instance):
        # if instance['name'] not in self.instances:
         #   raise exception.InstanceNotFound(instance_id=instance['name'])
        #i = self.instances[instance['name']]

        state = power_state.NOSTATE
        try:
            vapp_name = self._get_vcloud_vapp_name(instance)
            # the_vapp = self._get_vcloud_vapp(vapp_name)
            vapp_status = self._get_vcloud_vapp_status(vapp_name)
            state = status_dict_vapp_to_instance.get(vapp_status)
            # num_cpu = the_vapp.me.Children.Vm[0].Section[0].Item[6].VirtualQuantity.valueOf_
            # max_mem = the_vapp.me.Children.Vm[0].Section[0].Item[7].VirtualQuantity.valueOf_
        except:
            LOG.info('can not find the vapp')

        return {'state': state,
                'max_mem': 0,
                'mem': 0,
                'num_cpu': 1,
                'cpu_time': 0}

    def get_diagnostics(self, instance_name):
        pass
#         return {'cpu0_time': 17300000000,
#                 'memory': 524288,
#                 'vda_errors': -1,
#                 'vda_read': 262144,
#                 'vda_read_req': 112,
#                 'vda_write': 5778432,
#                 'vda_write_req': 488,
#                 'vnet1_rx': 2070139,
#                 'vnet1_rx_drop': 0,
#                 'vnet1_rx_errors': 0,
#                 'vnet1_rx_packets': 26701,
#                 'vnet1_tx': 140208,
#                 'vnet1_tx_drop': 0,
#                 'vnet1_tx_errors': 0,
#                 'vnet1_tx_packets': 662,
#         }

    def get_instance_diagnostics(self, instance_name):
        pass
#         diags = diagnostics.Diagnostics(state='running', driver='fake',
#                 hypervisor_os='fake-os', uptime=46664, config_drive=True)
#         diags.add_cpu(time=17300000000)
#         diags.add_nic(mac_address='01:23:45:67:89:ab',
#                       rx_packets=26701,
#                       rx_octets=2070139,
#                       tx_octets=140208,
#                       tx_packets = 662)
#         diags.add_disk(id='fake-disk-id',
#                        read_bytes=262144,
#                        read_requests=112,
#                        write_bytes=5778432,
#                        write_requests=488)
#         diags.memory_details.maximum = 524288
#         return diags

    def get_all_bw_counters(self, instances):
        """Return bandwidth usage counters for each interface on each
           running VM.
        """
        bw = []
        return bw

    def get_all_volume_usage(self, context, compute_host_bdms):
        """Return usage info for volumes attached to vms on
           a given host.
        """
        volusage = []
        return volusage

    def get_host_cpu_stats(self):
        pass
#         stats = {'kernel': 5664160000000L,
#                 'idle': 1592705190000000L,
#                 'user': 26728850000000L,
#                 'iowait': 6121490000000L}
#         stats['frequency'] = 800
#         return stats

    def block_stats(self, instance_name, disk_id):
        pass

    def interface_stats(self, instance_name, iface_id):
        pass

    def get_console_output(self, context, instance):
        return 'FAKE CONSOLE OUTPUT\nANOTHER\nLAST LINE'

    def get_vnc_console(self, context, instance):
        pass
#         return ctype.ConsoleVNC(internal_access_path='FAKE',
#                                 host='fakevncconsole.com',
#                                 port=6969)

    def get_spice_console(self, context, instance):
        pass
#         return ctype.ConsoleSpice(internal_access_path='FAKE',
#                                   host='fakespiceconsole.com',
#                                   port=6969,
#                                   tlsPort=6970)

    def get_rdp_console(self, context, instance):
        pass

    def get_serial_console(self, context, instance):
        pass

    def get_console_pool_info(self, console_type):
        pass

    def refresh_security_group_rules(self, security_group_id):
        return True

    def refresh_security_group_members(self, security_group_id):
        return True

    def refresh_instance_security_rules(self, instance):
        return True

    def refresh_provider_fw_rules(self):
        pass

    def get_available_resource(self, nodename):
        # XXX: get resources from vcloud

        the_vdc = self._get_vcloud_vdc()

        # compute_capacity = the_vdc.ComputeCapacity
        # cpu_res = the_vdc.ComputeCapacity.Cpu
        # ram_res = the_vdc.ComputeCapacity.Memory

        return {'vcpus': 32,
                'memory_mb': 164403,
                'local_gb': 5585,
                'vcpus_used': 0,
                'memory_mb_used': 69005,
                'local_gb_used': 3479,
                'hypervisor_type': 'vcloud',
                'hypervisor_version': 5005000,
                'hypervisor_hostname': nodename,
                'cpu_info': '{"model": ["Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz"], \
                        "vendor": ["Huawei Technologies Co., Ltd."], \
                        "topology": {"cores": 16, "threads": 32}}',
                'supported_instances': jsonutils.dumps(
                    [["i686", "vmware", "hvm"], ["x86_64", "vmware", "hvm"]]),
                'numa_topology': None,
                }

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        return

    def get_instance_disk_info(self, instance_name, block_device_info=None):
        return

    def live_migration(self, context, instance_ref, dest,
                       post_method, recover_method, block_migration=False,
                       migrate_data=None):
        post_method(context, instance_ref, dest, block_migration,
                    migrate_data)
        return

    def check_can_live_migrate_destination_cleanup(self, ctxt,
                                                   dest_check_data):
        return

    def check_can_live_migrate_destination(self, ctxt, instance_ref,
                                           src_compute_info, dst_compute_info,
                                           block_migration=False,
                                           disk_over_commit=False):
        return {}

    def check_can_live_migrate_source(self, ctxt, instance_ref,
                                      dest_check_data):
        return

    def finish_migration(self, context, migration, instance, disk_info,
                         network_info, image_meta, resize_instance,
                         block_device_info=None, power_on=True):
        return

    def confirm_migration(self, migration, instance, network_info):
        return

    def pre_live_migration(self, context, instance_ref, block_device_info,
                           network_info, disk, migrate_data=None):
        return

    def unfilter_instance(self, instance_ref, network_info):
        return

    def test_remove_vm(self, instance_name):
        """Removes the named VM, as if it crashed. For testing."""
        self.instances.pop(instance_name)

    def get_host_stats(self, refresh=False):
        """Return fake Host Status of ram, disk, network."""
#         stats = []
#         for nodename in _FAKE_NODES:
#             host_status = self.host_status_base.copy()
#             host_status['hypervisor_hostname'] = nodename
#             host_status['host_hostname'] = nodename
#             host_status['host_name_label'] = nodename
#             stats.append(host_status)
#         if len(stats) == 0:
#             raise exception.NovaException("FakeDriver has no node")
#         elif len(stats) == 1:
#             return stats[0]
#         else:
#             return stats

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        return action

    def host_maintenance_mode(self, host, mode):
        """Start/Stop host maintenance window. On start, it triggers
        guest VMs evacuation.
        """
        if not mode:
            return 'off_maintenance'
        return 'on_maintenance'

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        if enabled:
            return 'enabled'
        return 'disabled'

    def get_volume_connector(self, instance):
        # todo
        # pass
        return {'ip': '127.0.0.1', 'initiator': 'fake', 'host': 'fakehost'}

    def get_available_nodes(self, refresh=False):
        # NOTE(nkapotoxin) make vcenter session connective
        if not self.check_dvs_available(CONF.vcloud.vcloud_dvs_name):
            LOG.warn(
                'The dvs is not exsits, dvs:%s',
                CONF.vcloud.vcloud_dvs_name)

        # return self.vcloud_nodes.keys()
        return self._node_name

    def instance_on_disk(self, instance):
        return False

    def volume_snapshot_create(self, context, instance, volume_id,
                               create_info):
        # TODO(wangfeng)
        pass

        # # 1. get vmdk url
        # remote_vmdk_url = self._query_vmdk_url(instance.uuid)
        #
        # # 2. download vmdk
        # temp_dir = CONF.vcloud.vcloud_conversion_dir
        # vmdk_name = remote_vmdk_url.split('/')[-1]
        # local_file_name = '%s/%s.vmdk' % (temp_dir, volume_id)
        #
        # self._download_vmdk_from_vcloud(
        #     context,
        #     remote_vmdk_url,
        #     local_file_name)

        # # 3. convert vmdk to qcow2
        # converted_file_name = temp_dir +  '/converted-file.qcow2'
        # convert_commond = "qemu-img convert -f %s -O %s %s %s" % \
        #                         ('vmdk',
        #                         'qcow2',
        #                         local_file_name,
        #                         converted_file_name)
        # convert_result = subprocess.call([convert_commond],shell=True)
        #
        # if convert_result != 0:
        #     # do something, change metadata
        #     LOG.error('converting file failed')

        # 5. delete temporary files
        # todo


#         if instance['name'] not in self.instances:
#             raise exception.InstanceNotRunning(instance_id=instance['uuid'])
#         update_task_state(task_state=task_states.IMAGE_UPLOADING)

    def volume_snapshot_delete(self, context, instance, volume_id,
                               snapshot_id, delete_info):

        # TODO(wangfeng)
        pass

    def check_dvs_available(self, dvs_name):
        dvs_ref = self._vcenterapi.get_dvs_with_dvsname(dvs_name)
        return dvs_ref is not None

    def change_instance_metadata(self, context, instance, diff):
        """Applies a diff to the instance metadata.

        This is an optional driver method which is used to publish
        changes to the instance's metadata to the hypervisor.  If the
        hypervisor has no means of publishing the instance metadata to
        the instance, then this method should not be implemented.

        :param context: security context
        :param instance: nova.objects.instance.Instance
        """
        task_state = instance.metadata.get('task_state')
        if not task_state:
            self._update_vm_task_state(instance, None)
        else:
            self._update_vm_task_state(instance, task_state)


class VCloudAPISession(VCASession):

    """Sets up a session with the vcd and handles all
    the calls made to the host.
    """

    def __init__(self, host_ip=CONF.vcloud.vcloud_host_ip,
                 host_port=CONF.vcloud.vcloud_host_port,
                 host_username=CONF.vcloud.vcloud_host_username,
                 host_password=CONF.vcloud.vcloud_host_password,
                 org=CONF.vcloud.vcloud_org,
                 vdc=CONF.vcloud.vcloud_vdc,
                 version=CONF.vcloud.vcloud_version,
                 service=CONF.vcloud.vcloud_service,
                 verify=CONF.vcloud.vcloud_verify,
                 service_type=CONF.vcloud.vcloud_service_type,
                 retry_count=CONF.vcloud.vcloud_api_retry_count,
                 create_session=True,
                 scheme="https"):
        super(VCloudAPISession, self).__init__(host_ip=host_ip,
                                               host_port=host_port,
                                               server_username=host_username,
                                               server_password=host_password,
                                               org=org, vdc=vdc,
                                               version=version,
                                               service=service,
                                               verify=verify,
                                               service_type=service_type,
                                               retry_count=retry_count,
                                               create_session=create_session,
                                               scheme=scheme
                                               )

    def _call_method(self, module, method, *args, **kwargs):
        """Calls a method within the module specified with
        args provided.
        """
        return self.invoke_api(module, method, *args, **kwargs)

    def _wait_for_task(self, task_ref):
        """Return a Deferred that will give the result of the given task.
        The task is polled until it completes.
        """
        return self.wait_for_task(task_ref)
