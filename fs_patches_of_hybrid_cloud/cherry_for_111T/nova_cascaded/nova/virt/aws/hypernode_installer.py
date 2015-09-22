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

import sys
from threading import Thread, Event
import time

from contextlib import contextmanager
from libcloud.compute.base import NodeSize
from libcloud.common.types import LibcloudError
from libcloud.common.types import InvalidCredsError
from libcloud.common.types import MalformedResponseError
from nova import version
from nova.openstack.common import log as logging
from nova.openstack.common import uuidutils
from oslo.config import cfg

import adapter
from driver import NodeState
# from nova import exception as exception


LOG = logging.getLogger(__name__)


hypernode_api_opts = [
    cfg.StrOpt('cidr_vms',
               help='The virtual machines subnet CIDR',
               required=True),
    cfg.StrOpt('hn_image_id',
               default='ami-754a5c45',
               help='The image ID for the Hyper Node VM',
               required=True),
    cfg.StrOpt('hn_flavor',
               default='c4.large',
               help='The flavor name for the Hyper Node VM',
               required=True),
    cfg.StrOpt('rabbit_userid',
               required=True),
    cfg.StrOpt('rabbit_password_public',
               required=True),
    cfg.StrOpt('my_ip',
               required=True),
    cfg.StrOpt('vpc_id',
               help='The ID of the VPC to use'),
]

cfg.CONF.register_opts(hypernode_api_opts, 'hypernode_api')


@contextmanager
def libcloud_error_context():
    try:
        yield
    except InvalidCredsError as e:
        LOG.error('HyperNodeInstaller - LibcloudErrorContext: '
                  'InvalidCredsError: %s' % str(e))
        raise HyperNodeAPIException('libcloud authentication failed: ' + str(e))
    except MalformedResponseError as e:
        LOG.error('HyperNodeInstaller - LibcloudErrorContext: '
                  'MalformedResponseError: %s' % str(e))
        raise HyperNodeAPIException('libcloud malformed response: ' + str(e))
    except LibcloudError as e:
        LOG.error('HyperNodeInstaller - LibcloudErrorContext: '
                  'LibcloudError: %s' % str(e))
        raise HyperNodeAPIException('libcloud error: ' + str(e))
    except Exception as e:
        LOG.error('HyperNodeInstaller - LibcloudErrorContext: '
                  'Exception: %s' % str(e))
        raise e


class HyperNodeAPIException(Exception):
    # TODO (snapiri): use the nova exceptions instead of a custom exception
    def __init__(self, *args, **kwags):
        super(HyperNodeAPIException, self).__init__(*args, **kwags)


class HyperNodeInstallerState(object):
    def __init__(self):
        self.hypernode_name = None
        self.vm_subnet = None
        self.vm_security_group_id = None
        self.exception = None
        self.extra = {}
        self.event = Event()

    @property
    def is_complete(self):
        return self.event.is_set()

    def wait(self, timeout=None):
        return self.event.wait(timeout=timeout)

    def complete(self, exception=None):
        if self.is_complete:
            raise Exception('HyperNodeInstall event completed twice')
        self.exception = exception
        self.event.set()


def hypernode_background_install(installer, install_state):
    LOG.debug('HyperNodeBackgroundInstall: Strarting...')
    return Thread(target=installer.create_hypernode, args=(install_state,))


class Ec2AdapterProxy(object):
    def __init__(self, ec2adapter):
        self.__adapter = ec2adapter

    def __getattribute__(self, method):
        LOG.debug('HyperNodeInstaller - Ec2AdapterProxy: Calling %s' % method)
        my_adapter = object.__getattribute__(self, '_Ec2AdapterProxy__adapter')
        fn = getattr(my_adapter, method)

        def fn_proxy(*args, **kwargs):
            with libcloud_error_context():
                return fn(*args, **kwargs)

        return fn_proxy


class HyperNodeInstaller(object):
    # Default names for the security groups
    _hns_sg_name = 'hns-sg'
    _hns_sg_desc = 'Security group for HyperNodes'
    _vms_sg_name = 'vms-sg'
    _vms_sg_desc = 'Security group for HyperNodes VMs'

    @staticmethod
    def _get_availability_zone():
        """
        :returns: currently used availability zone
        :rtype: ``str``
        :raises: :class:`HyperNodeAPIException`
        """
        az = cfg.CONF.provider_opts.availability_zone
        if not az:
            raise HyperNodeAPIException('Could not get availability_zone %s '
                                        'from the configuration' % (az,))
        return az

    @staticmethod
    def _is_exist_sg_ingress_rule(rules, sg_id):
        """
        Check if a relevant ingress rule exists

        :param rules: All existing security group rules
        :type rules: ``list`` of :class:`OpenStackSecurityGroupRule`
        :param sg_id: ID of the source security group
        :type sg_id: ``str``
        :returns: True if such rule exists
        :rtype: ``bool``
        """
        for rule in rules:
            if (rule['from_port'] is None and
                rule['to_port'] is None and
                    rule['protocol'] in ('-1', 'all')):

                for pair in rule['group_pairs']:
                    if pair['group_id'] == sg_id:
                        return True
        return False

    @staticmethod
    def _get_hn_iface(hn_vm):
        """
        Find the interface connected to the HyperNode subnet

        :param hn_vm: the VM we want its interface
        :type hn_vm: :class:`libcloud.compute.base.Node`
        :returns: the network interface
        :rtype: :class:`EC2NetworkInterface`
        :raises: :class:`HyperNodeAPIException`
        """
        for iface in hn_vm.extra['network_interfaces']:
            for group in iface.extra['groups']:
                if group['group_name'] == HyperNodeInstaller._hns_sg_name:
                    return iface
        raise HyperNodeAPIException('Unable to find hn_iface for HyperNode')

    @staticmethod
    def _get_table_by_association(tables, subnet_id):
        for _table in tables:
            for association in _table.subnet_associations:
                if association.subnet_id == subnet_id:
                    return _table
        return None

    def __init__(self):
        self._compute_adapter = Ec2AdapterProxy(adapter.Ec2Adapter(
            cfg.CONF.provider_opts.access_key_id,
            secret=cfg.CONF.provider_opts.secret_key,
            region=cfg.CONF.provider_opts.region,
            secure=False))

        self._vpc = self._get_active_vpc()
        self._rabbit_userid = cfg.CONF.hypernode_api.rabbit_userid
        self._rabbit_password = cfg.CONF.hypernode_api.rabbit_password_public
        self._my_ip = cfg.CONF.hypernode_api.my_ip
        self._vms_sg = None
        self._hns_sg = None

    def _get_default_vpc(self):
        networks = self._compute_adapter.ex_list_networks()
        for network in networks:
            if network.extra['is_default'] == 'true':
                return network
        raise HyperNodeAPIException('Could not identify default VPC')

    def _get_active_vpc(self):
        """
        Reads the relevant active VPC and returns it

        :rtype: :class:`EC2Network`
        :raises: :class:`HyperNodeAPIException`
        """
        vpc_id = cfg.CONF.hypernode_api.vpc_id
        if vpc_id:
            networks = self._compute_adapter.ex_list_networks(
                network_ids=[vpc_id])
            if len(networks) > 0:
                return networks[0]
            else:
                LOG.warning('Could not find VPC %s, Using default VPC' %
                            (vpc_id,))

        return self._get_default_vpc()

    def _get_subnet_with_filters(self, filterz,
                                 allow_none=True):
        subnets = self._get_subnets_with_filters(filterz, allow_none, False)
        if len(subnets) > 0:
            return subnets[0]
        return None

    def _get_subnets_with_filters(self, filterz,
                                  allow_none=True,
                                  allow_multi=True):
        """
        Finds a subnet using a filter

        :param filterz: dictionary of filters
        :type filterz: ``dict``
        :param allow_none: do not throw exception if no matches are found
        :type allow_none: ``bool``
        :param allow_multi: do not throw exception if more than one result
        :type allow_multi: ``bool``
        :returns: all subnets matchine the filters
        :rtype: ``list`` of :class:`EC2NetworkSubnet`
        :raises: :class:`HyperNodeAPIException`
        """
        subnets = self._compute_adapter.ex_list_subnets(None, filterz)
        # If the subnet exists, return it
        if not allow_multi and len(subnets) > 1:
            raise HyperNodeAPIException('Too many networks match the '
                                        'filter: %s' % (filterz,))
        if not allow_none and len(subnets) == 0:
            raise HyperNodeAPIException('No subnet matches '
                                        'filter: %s' % (filterz,))
        return subnets

    def _get_subnet_by_id(self, subnet_id, allow_none=True):
        """
        Finds a subnet by ID if exists

        :param subnet_id: ID of the subnet
        :type subnet_id: ``str``
        :param allow_none: Allow empty list to be returned
        :returns: the network with the supplied ID
        :rtype: :class:`EC2NetworkSubnet`
        :raises: :class:`HyperNodeAPIException`
        """
        filterz = {'subnet-id': subnet_id}
        subnet = self._get_subnet_with_filters(filterz, allow_none)
        return subnet

    def _get_subnet_by_cidr(self, cidr_block, allow_none=True):
        """
        Finds a subnet by CIDR if exists

        :param cidr_block: CIDR of the subnet
        :type cidr_block: ``str``
        :returns: the network with given CIDR
        :rtype: :class:`EC2NetworkSubnet`
        :raises: HyperNodeAPIException
        """
        filterz = {'cidrBlock': cidr_block}
        subnets = self._get_subnets_with_filters(filterz, allow_none)
        if len(subnets) == 0:
            return None
        return subnets[0]

    def _create_subnet(self, cidr_block, name):
        """
        Creates a new subnet

        :param cidr_block: CIDR of the new subnet
        :type cidr_block: ``str``
        :param name: new subnet name
        :type name: ``str``
        :returns: the new (or existing) subnet
        :rtype: :class:`EC2NetworkSubnet`
        :raises: HyperNodeAPIException
        """
        subnet = self._get_subnet_by_cidr(cidr_block)
        if subnet:
            LOG.info('Subnet %s already exists' % cidr_block)
            return subnet

        # Our subnet does not exist, try to create it
        return self._compute_adapter.ex_create_subnet(
            self._vpc.id,
            cidr_block,
            self._get_availability_zone(),
            name=name)

    def _create_security_group(self, name, desc):
        """
        Creates a new security group

        :param name: new security group name
        :type name: ``str``
        :param desc: new security group description
        :type desc: ``str``
        :returns: the created security group
        :rtype: ``dict``
        :raises: :class:`HyperNodeAPIException`
        """
        sg = self._compute_adapter.ex_create_security_group(
            name, desc, self._vpc.id)
        return sg

    def get_security_group(self, group_name):
        """
        fetches a security group by its name

        :param group_name: the name of the security group
        :type group_name: ``str``
        :returns: the security group if it exists
        :rtype: :class:`EC2SecurityGroup`
        :raises: :class:`HyperNodeAPIException`
        """
        groups = self._compute_adapter.ex_get_security_groups(
            None, None, {'group-name': group_name, 'vpc-id': self._vpc.id})
        if len(groups) > 0:
            return groups[0]
        return None

    def _get_secuity_group(self,
                           current_security_groups,
                           group_name,
                           group_desc):
        """
        Search for security group and create it if required

        :param current_security_groups: names of all existing security groups
        :type current_security_groups: ``list`` of ``str``
        :param group_name: security group name
        :type group_name: ``str``
        :param group_desc: security group description
        :type group_desc: ``str``
        :returns: the existing (or new) security group
        :rtype: :class:`EC2SecurityGroup`
        :raises: :class:`HyperNodeAPIException`
        """
        if group_name in current_security_groups:
            return self.get_security_group(group_name)

        sgroup = self._create_security_group(group_name,
                                             group_desc)

        # Read the group to get all attributes
        group_id = sgroup['group_id']
        groups = self._compute_adapter.ex_get_security_groups([group_id],
                                                              None, None)

        assert (len(groups) > 0)
        return groups[0]

    def _add_sg_ingress_rule(self, group_id, source_group_id):
        """
        add default ingress rule

        :param group_id: security group to modify
        :type group_id: ``str``
        :param source_group_id: security group to allow access from
        :type source_group_id: ``str``
        :returns: list of the rules
        :rtype: ``list`` of ????
        :raises: :class:`HyperNodeAPIException`
        """
        return self._compute_adapter.ex_authorize_security_group_ingress(
            group_id,
            from_port=0,
            to_port=65535,
            cidr_ips=None,
            group_pairs=[{'group_id': source_group_id}],
            protocol=-1)

    def _create_security_groups(self):
        """
        Search for relevant security groups and create them if required

        :returns: True if create succeeded
        :rtype: ``bool``
        :raises: :class:`HyperNodeAPIException`
        """
        current_security_group_names = (
            self._compute_adapter.ex_list_security_groups())
        self._hns_sg = self._get_secuity_group(current_security_group_names,
                                               HyperNodeInstaller._hns_sg_name,
                                               HyperNodeInstaller._hns_sg_desc)
        self._vms_sg = self._get_secuity_group(current_security_group_names,
                                               HyperNodeInstaller._vms_sg_name,
                                               HyperNodeInstaller._vms_sg_desc)

        # Configure security groups
        if not self._is_exist_sg_ingress_rule(self._hns_sg.ingress_rules,
                                              self._vms_sg.id):
            self._add_sg_ingress_rule(self._hns_sg.id, self._vms_sg.id)
        if not self._is_exist_sg_ingress_rule(self._vms_sg.ingress_rules,
                                              self._hns_sg.id):
            self._add_sg_ingress_rule(self._vms_sg.id, self._hns_sg.id)
        return True

    def _get_current_location(self):
        """
        Find the current location we are using

        :returns: the current AWS location
        :rtype: :class:`NodeLocation`
        :raises: :class:`HyperNodeAPIException`
        """
        current_az = self._get_availability_zone()
        locations = [loc for loc in self._compute_adapter.list_locations()
                     if loc.name == current_az]
        # Make sure the list is not empty
        if len(locations) == 0:
            raise HyperNodeAPIException(
                'Could not find a matching location for %s' % (current_az,))
        return locations[0]

    def _get_current_hn(self, tenant_id):
        """
        Find the active HyperNode for the tenant

        :param tenant_id: ID of the tenant to use.
        :type tenant_id: ``str``
        :returns: the current HN VM and its HN interface
        :rtype: :class:`libcloud.compute.base.Node`,
                :class:`EC2NetworkInterface`
        :raises: :class:`HyperNodeAPIException`
        """
        hns = self._compute_adapter.list_nodes(
            ex_node_ids=None,
            ex_filters={'tag:is_hypernode': True,
                        'tag:tenant_id': tenant_id,
                        'instance-state-name': [
                            'pending', 'running']})
        # TODO (snapiri): Currently we only support one HN per tenant
        if len(hns) > 1:
            raise HyperNodeAPIException('More than one Hyoernode in '
                                        'single HN mode')
        if len(hns) > 0:
            hypernode = hns[0]
            # Get the hn_iface
            hn_iface = self._get_hn_iface(hypernode)
            return hypernode, hn_iface
        return None, None

    def _get_user_data(self, hypernode_name, vpngw_ip):
        """
        Construct user data for HyperNode VM

        :param hypernode_name: The UUID of the HyperNode machine
        :type hypernode_name: ``str``
        :param vpngw_ip: IP address of the VPN gateway on the cascading node
        :type vpngw_ip: ``str``
        :returns: the userdata for the VM
        :rtype: ``str``
        """
        return ('use_user_vars=true\n'
                'host=%s\n'
                'rabbit_host=%s\n'
                'rabbit_userid=%s\n'
                'rabbit_password=%s\n'
                'tunnel_bearing_interface=eth0\n'
                'vpngw_ip=%s\n'
                'internal_base_interface=eth1\n'
                'hypernode_interface=eth2' % (
                    hypernode_name, self._my_ip, self._rabbit_userid,
                    self._rabbit_password, vpngw_ip))

    def _create_route_table(self, vm_subnet, hn_iface):
        """
        Create a route table and associate it with the VM subnet

        :param vm_subnet: VM subnet object
        :type vm_subnet: :class:``EC2NetworkSubnet``
        :param hn_iface: HyperNode interface in the HN subnet
        :type hn_iface: :class:``EC2NetworkInterface``
        :returns: the full route table
        :rtype: :class:``EC2RouteTable``
        """
        tables = self._compute_adapter.ex_list_route_tables(
            route_table_ids=None, filters=None)
        # Try to find the relevant table if it exists
        # (Should be associated to the network)
        table = self._get_table_by_association(tables, vm_subnet.id)

        # Create the table if it does not exist
        if table is None:
            table = self._compute_adapter.ex_create_route_table(
                self._vpc, "HyperNode route table")
            self._compute_adapter.ex_associate_route_table(table, vm_subnet)

        # Check if the default route exists
        routes = [route for route in table.routes if route.cidr == "0.0.0.0/0"]

        # Create or modify the rule accordingly
        # Configure routing table: default GW - HN NIC in HN Net
        if len(routes) > 0:
            self._compute_adapter.ex_replace_route(
                table, '169.254.169.254/32',
                network_interface=hn_iface)
            self._compute_adapter.ex_replace_route(
                table, '0.0.0.0/0',
                network_interface=hn_iface)
        else:
            self._compute_adapter.ex_create_route(
                table, '169.254.169.254/32',
                network_interface=hn_iface)
            self._compute_adapter.ex_create_route(
                table, '0.0.0.0/0',
                network_interface=hn_iface)
        return table

    def _hypernode_interfaces(self,
                              tunnel_bearing_subnet_id,
                              internal_base_subnet_id,
                              hypernode_subnet_id):
        """
        return HyperNode interfaces to create

        :param tunnel_bearing_subnet_id: ID of the tunnel bearing subnet
        :type tunnel_bearing_subnet_id: ``str``
        :param internal_base_subnet_id: ID of the base subnet
        :type internal_base_subnet_id: ``str``
        :param hypernode_subnet_id:  ID of the HN subnet
        :type hypernode_subnet_id: ``str``
        :returns: the VM interfaces to create
        :rtype: ``list`` of :class:`NetworkInterface`
        """
        # Create 3 NICs (Primary in tunnel-bearing Net)
        provider_interface_data = adapter.NetworkInterface(
            name='eth_data',
            subnet_id=tunnel_bearing_subnet_id,
            device_index=0)

        provider_interface_api = adapter.NetworkInterface(
            name='eth_control',
            subnet_id=internal_base_subnet_id,
            device_index=1)

        provider_interface_hns = adapter.NetworkInterface(
            name='eth_hns',
            subnet_id=hypernode_subnet_id,
            security_groups=self._hns_sg.id,
            device_index=2)

        return [provider_interface_data,
                provider_interface_api,
                provider_interface_hns]

    def create_hypernode_vm(self, hypernode_subnet,
                            tunnel_bearing_subnet_id,
                            vpngw_ip,
                            internal_base_subnet_id,
                            hypernode_name,
                            tenant_id=None):
        """
        Create the HyperNode VM

        :param tunnel_bearing_subnet_id: ID of the tunnel bearing subnet
        :type tunnel_bearing_subnet_id: ``str``
        :param vpngw_ip: IP address of the VPN gateway on the cascading node
        :type vpngw_ip: ``str``
        :param internal_base_subnet_id: ID of the base subnet
        :type internal_base_subnet_id: ``str``
        :param hypernode_name: The UUID of the HyperNode machine
        :type hypernode_name: ``str``
        :param tenant_id:  ID of the current tenant (Currently must be None)
        :type tenant_id: ``str``
        :returns: the HN VM and its HN interface
        :rtype: :class:`libcloud.compute.base.Node`,
                :class:`EC2NetworkInterface`
        :raises: :class:`HyperNodeAPIException`
         """
        provider_node_name = "HyperNode"
        provider_image = self._compute_adapter.get_image(
            cfg.CONF.hypernode_api.hn_image_id)
        # noinspection PyTypeChecker
        provider_size = NodeSize(id=cfg.CONF.hypernode_api.hn_flavor,
                                 name=None,
                                 ram=None, disk=None,
                                 bandwidth=None, price=None,
                                 driver=self._compute_adapter)

        LOG.debug('HyperNodeInstaller.create_hypernode_vm: Creating interfaces')
        # Attach the NICs (Primary in tunnel-bearing Net)
        provider_interfaces = self._hypernode_interfaces(
            tunnel_bearing_subnet_id=tunnel_bearing_subnet_id,
            internal_base_subnet_id=internal_base_subnet_id,
            hypernode_subnet_id=hypernode_subnet.id)

        LOG.debug('HyperNodeInstaller.create_hypernode_vm: Finding location')
        current_location = self._get_current_location()

        LOG.debug('HyperNodeInstaller.create_hypernode_vm: Getting User Data')
        user_data = self._get_user_data(hypernode_name=hypernode_name,
                                        vpngw_ip=vpngw_ip)

        LOG.debug('HyperNodeInstaller.create_hypernode_vm: Creating '
                  'HyperNode VM')
        # Create ec2 vm on aws
        tags = {'is_hypernode': True,
                'hypernode_name': hypernode_name,
                'tenant_id': tenant_id}
        hn_vm = self._compute_adapter.create_node(
            name=provider_node_name,
            image=provider_image,
            size=provider_size,
            location=current_location,
            ex_blockdevicemappings=[],
            ex_network_interfaces=provider_interfaces,
            ex_userdata=user_data,
            ex_metadata=tags)

        LOG.debug('HyperNodeInstaller.create_hypernode_vm: '
                  'Getting HN interface')
        # Get hn_iface
        hn_iface = self._get_hn_iface(hn_vm)

        LOG.debug('HyperNodeInstaller.create_hypernode_vm: '
                  'Disable source/dest check')
        # Disable source/destination on HN NIC in HN Net
        self._compute_adapter.ex_modify_network_interface_attribute(
            iface_id=hn_iface.id, source_dest_check=False)

        LOG.debug('HyperNodeInstaller.create_hypernode_vm: '
                  'Done...')
        return hn_vm, hn_iface

    def _wait_for_hn_vm_to_start(self, vm, sleep_interval=10, retry_count=60):
        """
        Wait for the VM state to change to RUNNING.
        Timeout after 10 minutes

        :param vm: VM to wait for
        :type vm: :class:`libcloud.compute.base.Node`
        :returns: The VM with the updated state
        :rtype: :class:`libcloud.compute.base.Node`
        :raises: :class:`HyperNodeAPIException`
         """
        count = 1
        # wait for the instance to complete initialization
        # This means getting to RUNNING state or any other
        # final state (not pending or rebooting)
        while vm.state == NodeState.PENDING:
            time.sleep(sleep_interval)
            vm = self._compute_adapter.list_nodes(ex_node_ids=[vm.id])[0]
            count += 1
            if count > retry_count:  # Wait up to 10 minutes
                raise HyperNodeAPIException('HyperNode state unexpected after '
                                            'maximum period. Please check VM')
        if vm.state != NodeState.RUNNING:
            raise HyperNodeAPIException('Unexpected HyperNode state: %s' %
                                        str(vm.state))
        return vm

    def create_hypernode(self, install_state):
        """
        Create a HyperNode and route table if required.
        May be called in a separate thread

        :param install_state: state of the install thread
        :type install_state: :class:`HyperNodeInstallerState`
        :raises: :class:`HyperNodeAPIException`
         """
        try:
            if 'hn_vm' not in install_state.extra:
                LOG.debug('HyperNodeInstaller: Finding HyperNode')
                # Create HyperNode VM
                hn_vm, hn_iface = self.create_hypernode_vm(
                    hypernode_subnet=install_state.extra['hn_subnet'],
                    tunnel_bearing_subnet_id=install_state.extra[
                        'tunnel_bearing_subnet_id'],
                    vpngw_ip=install_state.extra['vpngw_ip'],
                    internal_base_subnet_id=install_state.extra['internal_base_subnet_id'],
                    hypernode_name=install_state.hypernode_name,
                    tenant_id=install_state.extra['tenant_id'])
            else:
                hn_vm = install_state.extra['hn_vm']
                hn_iface = install_state.extra['hn_iface']

            LOG.debug('HyperNodeInstaller: Waiting for HyperNode to be ready')
            # Wait for VM to start
            self._wait_for_hn_vm_to_start(hn_vm)

            LOG.debug('HyperNodeInstaller: Creating Routing Table')
            # Create routing table for the HN
            table = self._create_route_table(vm_subnet=install_state.vm_subnet,
                                             hn_iface=hn_iface)
            if table is None:
                raise HyperNodeAPIException('Error creating routing table')
        except HyperNodeAPIException as e:
            LOG.error('HyperNodeInstaller.create_hypernode: '
                      'HyperNodeAPIException: %s' % str(e))
            install_state.complete(e)
        except Exception as e:
            LOG.error('HyperNodeInstaller.create_hypernode: '
                      'Exception: %s' % str(e))
            install_state.complete(e)
        else:
            LOG.debug('HyperNodeInstaller: My work is done...')
            install_state.complete()

    def start_install(self,
                      hn_cidr_block,
                      tunnel_bearing_subnet_id,
                      vpngw_ip,
                      internal_base_subnet_id,
                      tenant_id=None):
        """
        Do the actual work. Create all required objects if needed
        Use current objects if exist

        :param hn_cidr_block: CIDR of the HN subnet
        :type hn_cidr_block: ``str``
        :param tunnel_bearing_subnet_id: ID of the tunnel bearing subnet
        :type tunnel_bearing_subnet_id: ``str``
        :param vpngw_ip: IP address of the VPN gateway on the cascading node
        :type vpngw_ip: ``str``
        :param internal_base_subnet_id: ID of the base subnet
        :type internal_base_subnet_id: ``str``
        :param tenant_id:  ID of the current tenant (Currently must be None)
        :type tenant_id: ``str``
        :returns: object representing the state of the creation thread
        :rtype: :class:`HyperNodeInstallerState`
        :raises: :class:`HyperNodeAPIException'
         """
        install_state = HyperNodeInstallerState()
        try:
#            install_state.hypernode_name = self._hypernode_name
            install_state.extra['tunnel_bearing_subnet_id'] = tunnel_bearing_subnet_id
            install_state.extra['vpngw_ip'] = vpngw_ip
            install_state.extra['internal_base_subnet_id'] = internal_base_subnet_id
            install_state.extra['tenant_id'] = tenant_id

            LOG.debug('HyperNodeInstaller: Creating HyperNode subnet')
            # Create HyperNode subnet if required
            hn_subnet = self._create_subnet(hn_cidr_block, "Hypernode_Subnet")
            install_state.extra['hn_subnet'] = hn_subnet

            vm_cidr_block = cfg.CONF.hypernode_api.cidr_vms

            LOG.debug('HyperNodeInstaller: Creating VM subnet')
            # Create HyperNode subnet if required
            vm_subnet = self._create_subnet(vm_cidr_block, "VM_Subnet")
            install_state.vm_subnet = vm_subnet

            LOG.debug('HyperNodeInstaller: Creating Security Groups')
            # Add HN and VM security groups
            self._create_security_groups()
            install_state.vm_security_group_id = self._vms_sg.id

            # Check if HyperNode exists
            LOG.debug('HyperNodeInstaller: Checking for existing HyperNode')
            # Currently we only support single HN
            hn_vm, hn_iface = self._get_current_hn(tenant_id=tenant_id)
            if hn_vm:
                LOG.debug('HyperNodeInstaller: HyperNode exists')
                install_state.extra['hn_vm'] = hn_vm
                install_state.extra['hn_iface'] = hn_iface
                install_state.hypernode_name = hn_vm.extra['tags']['hypernode_name']
            else:
                install_state.hypernode_name = uuidutils.generate_uuid()

            # Start a thread to do the rest of the work...
            LOG.debug('HyperNodeInstaller: Strating background job')
            thread = hypernode_background_install(self, install_state)
            thread.start()
            LOG.debug('HyperNodeInstaller: Background job started')

        except HyperNodeAPIException as e:
            LOG.error('HyperNodeInstaller.start_install: '
                      'HyperNodeAPIException: %s' % str(e))
            install_state.complete(e)
        except Exception as e:
            LOG.error('HyperNodeInstaller.start_install: '
                      'Exception: %s' % str(e))
            install_state.complete(e)
        finally:
            LOG.debug('HyperNode installer: Returning State')
            return install_state


def main():
    if len(sys.argv) < 2:
        print "insufficient arguments"
        exit()

    cfg.CONF(sys.argv[1:],
             project='nova',
             version=version.version_string(),
             default_config_files=None)

    test_api_opts = [
        cfg.StrOpt('cidr_hns',
                   help='The provider CIDR block for the HyperNode subnet',
                   required=True),
        cfg.StrOpt('subnet_tunnel_bearing',
                   help='The provider subnet ID of the Tunnel Bearing subnet',
                   required=True),
        cfg.StrOpt('ip_vpngw',
                   help='IP address of the VPN gateway on the cascading node',
                   required=True),
        cfg.StrOpt('subnet_internal_base',
                   help='The provider subnet ID of the Internal Base subnet',
                   required=True),
    ]

    cfg.CONF.register_opts(test_api_opts, 'hypernode_api')

    installer = HyperNodeInstaller()
    # Start everything.
    LOG.info("Installer initialized successfully, now running... ")
    hn_cidr_block = cfg.CONF.hypernode_api.cidr_hns
    tb_subnet_id = cfg.CONF.hypernode_api.subnet_tunnel_bearing
    vpngw_ip = cfg.CONF.hypernode_api.ip_vpngw
    ib_subnet_id = cfg.CONF.hypernode_api.subnet_internal_base
    opq = installer.start_install(
        hn_cidr_block=hn_cidr_block,
        tunnel_bearing_subnet_id=tb_subnet_id,
        vpngw_ip=vpngw_ip,
        internal_base_subnet_id=ib_subnet_id)

    opq.wait()

if __name__ == "__main__":
    main()
