__author__ = 'nash.xiejun'
import sys
import os
import traceback
import json
import os
import select
import socket
import time

import paramiko
import six

from keystoneclient.v2_0.endpoints import Endpoint
from novaclient import client as nova_client
from nova.proxy import clients
from nova.proxy import compute_context

# from install_tool import cps_server, fsutils, fs_system_util
# TODO:
sys.path.append('/usr/bin/install_tool')
import cps_server
import fsutils
import fs_system_util

LOG_INIT = 'ci_hybrid_cloud'

import log
log.init(LOG_INIT)

try:
    from glanceclient.v2 import client as glanceclient
except ImportError:
    glanceclient = None
    log.info('glanceclient not available')

class RefServices(object):

    def __init__(self, region_name=None, bypass_url=None):
        """

        :param region_name: use to specify service in which region want to reference
        :param bypass_url: use to specify url of service
        :return:
        """

        self.tenant = os.environ['OS_TENANT_NAME']
        self.user = os.environ['OS_USERNAME']
        self.pwd = os.environ['OS_PASSWORD']
        self.auth_url = os.environ['OS_AUTH_URL']
        self.bypass_url = bypass_url
        self.region_name = os.environ['OS_REGION_NAME']

        credentials = self.get_credentials_v2()
        self.keystone = self.get_keystone_client(credentials)
        self.nova = self.get_nova_sync_client(credentials)
        self.neutron = self.get_neutron_client(credentials)
        self.glance = self.get_glance_client(credentials)

    def get_credentials_v2(self):
        """
        d = {'version': '2', 'username' : os.environ['OS_USERNAME'], 'api_key' : os.environ['OS_PASSWORD'], 'auth_url' : os.environ['OS_AUTH_URL'], 'project_id' : os.environ['OS_TENANT_NAME']}
        :return:
        """

        d = {}
        d['version'] = '2'
        d['username'] = self.user
        d['password'] = self.pwd
        d['auth_url'] = self.auth_url
        d['tenant'] = self.tenant
        if self.region_name is not None:
            d['region_name'] = self.region_name
        else:
            d['region_name'] = None

        if self.bypass_url is not None:
            d['bypass_url'] = self.bypass_url
        else:
            d['bypass_url'] = None

        return d

    def get_neutron_client(self, kwargs):
        req_context = compute_context.RequestContext(**kwargs)
        openstack_clients = clients.OpenStackClients(req_context)
        return openstack_clients.neutron()

    def get_nova_sync_client(self, kwargs):
        """
        kwargs = {
            'username': CONF.nova_admin_username,
            'password': CONF.nova_admin_password,
            'tenant': CONF.nova_admin_tenant_name,
            'auth_url': CONF.keystone_auth_url,
            'region_name': CONF.proxy_region_name
        }

        :param args:
        :return:
        """

        req_context = compute_context.RequestContext(**kwargs)
        openstack_clients = clients.OpenStackClients(req_context)
        return openstack_clients.nova()

    def get_keystone_client(self, kwargs):
        """
        kwargs = {
            'username': CONF.nova_admin_username,
            'password': CONF.nova_admin_password,
            'tenant': CONF.nova_admin_tenant_name,
            'auth_url': CONF.keystone_auth_url,
            'region_name': CONF.proxy_region_name
        }

        :param args:
        :return:
        """

        req_context = compute_context.RequestContext(**kwargs)
        openstack_clients = clients.OpenStackClients(req_context)

        return openstack_clients.keystone().client_v2

    def get_glance_client(self, credentials):
        """
        kwargs = {
            'username': CONF.nova_admin_username,
            'password': CONF.nova_admin_password,
            'tenant': CONF.nova_admin_tenant_name,
            'auth_url': CONF.keystone_auth_url,
            'region_name': CONF.proxy_region_name
        }

        :param args:
        :return:
        """

        return self.glanceclient(version=credentials['version'],
                                 username=credentials['username'],
                                 password=credentials['password'],
                                 auth_url=credentials['auth_url'],
                                 tenant=credentials['tenant'],
                                 region_name=credentials['region_name'],
                                 bypass_url=credentials['bypass_url'])

    def glanceclient(self, **kwargs):
        endpoint = 'https://image.cascading.hybrid.huawei.com:443'
        client = glanceclient.Client(endpoint, **kwargs)

        self.glance = client
        return self.glance

    def nova_list(self, search_opts=None):
        return self.nova.servers.list(detailed=True, search_opts=search_opts)

    def nova_show(self, server):
        """
        :param server:
        :return:
        {'OS-EXT-STS:task_state': u'scheduling',
        'addresses': {},
        'links': [{u'href': u'https://compute.cascading.hybrid.huawei.com/v2/f1d64e22d48b46f7b807ac44d4078029/servers/607db231-fd00-418d-bb1c-560b48f16c08', u'rel': u'self'}, {u'href': u'https://compute.cascading.hybrid.huawei.com/f1d64e22d48b46f7b807ac44d4078029/servers/607db231-fd00-418d-bb1c-560b48f16c08', u'rel': u'bookmark'}],
        'image': {u'id': u'cfde0324-0ca6-4883-b160-bf06383ad466', u'links': [{u'href': u'https://compute.cascading.hybrid.huawei.com/f1d64e22d48b46f7b807ac44d4078029/images/cfde0324-0ca6-4883-b160-bf06383ad466', u'rel': u'bookmark'}]},
        'manager': <novaclient.v1_1.servers.ServerManager object at 0x22640d0>,
        'numaOpts': 0,
        'OS-EXT-STS:vm_state': u'building',
        'OS-EXT-SRV-ATTR:instance_name': u'instance-0000003e',
        'OS-SRV-USG:launched_at': None,
        'flavor': {u'id': u'1', u'links': [{u'href': u'https://compute.cascading.hybrid.huawei.com/f1d64e22d48b46f7b807ac44d4078029/flavors/1', u'rel': u'bookmark'}]},
        'id': u'607db231-fd00-418d-bb1c-560b48f16c08',
        'evsOpts': 0,
        'user_id': u'08a39e2715c24e36903400a39051268f',
        'OS-DCF:diskConfig': u'MANUAL',
        'accessIPv4': u'',
        'accessIPv6': u'',
        'progress': 0,
        'OS-EXT-STS:power_state': 0,
        'OS-EXT-AZ:availability_zone': u'az01.shenzhen--fusionsphere',
        'config_drive': u'',
        'status': u'BUILD',
        'updated': u'2015-07-31T00:50:22Z',
        'hostId': None,
        'OS-EXT-SRV-ATTR:host': None,
        'OS-SRV-USG:terminated_at': None,
        'key_name': None,
        'vcpuAffinity': [0],
        'hyperThreadAffinity': u'any',
        'OS-EXT-SRV-ATTR:hypervisor_hostname': None,
        'name': u'az01.shenzhen--fusionsphere-vm-01',
        'created': u'2015-07-31T00:50:22Z',
        'tenant_id': u'f1d64e22d48b46f7b807ac44d4078029',
        'OS-EXT-SERVICE:service_state': None,
        'os-extended-volumes:volumes_attached': [],
        '_info': {u'OS-EXT-STS:task_state': u'scheduling', u'addresses': {}, u'links': [{u'href': u'https://compute.cascading.hybrid.huawei.com/v2/f1d64e22d48b46f7b807ac44d4078029/servers/607db231-fd00-418d-bb1c-560b48f16c08', u'rel': u'self'}, {u'href': u'https://compute.cascading.hybrid.huawei.com/f1d64e22d48b46f7b807ac44d4078029/servers/607db231-fd00-418d-bb1c-560b48f16c08', u'rel': u'bookmark'}], u'image': {u'id': u'cfde0324-0ca6-4883-b160-bf06383ad466', u'links': [{u'href': u'https://compute.cascading.hybrid.huawei.com/f1d64e22d48b46f7b807ac44d4078029/images/cfde0324-0ca6-4883-b160-bf06383ad466', u'rel': u'bookmark'}]}, u'numaOpts': 0, u'OS-EXT-STS:vm_state': u'building', u'OS-EXT-SRV-ATTR:instance_name': u'instance-0000003e', u'OS-SRV-USG:launched_at': None, u'flavor': {u'id': u'1', u'links': [{u'href': u'https://compute.cascading.hybrid.huawei.com/f1d64e22d48b46f7b807ac44d4078029/flavors/1', u'rel': u'bookmark'}]}, u'id': u'607db231-fd00-418d-bb1c-560b48f16c08', u'OS-SRV-USG:terminated_at': None, u'user_id': u'08a39e2715c24e36903400a39051268f', u'OS-DCF:diskConfig': u'MANUAL', u'accessIPv4': u'', u'accessIPv6': u'', u'progress': 0, u'OS-EXT-STS:power_state': 0, u'OS-EXT-AZ:availability_zone': u'az01.shenzhen--fusionsphere', u'config_drive': u'', u'status': u'BUILD', u'updated': u'2015-07-31T00:50:22Z', u'hostId': None, u'OS-EXT-SRV-ATTR:host': None, u'evsOpts': 0, u'key_name': None, u'vcpuAffinity': [0], u'hyperThreadAffinity': u'any', u'OS-EXT-SRV-ATTR:hypervisor_hostname': None, u'name': u'az01.shenzhen--fusionsphere-vm-01', u'created': u'2015-07-31T00:50:22Z', u'tenant_id': u'f1d64e22d48b46f7b807ac44d4078029', u'OS-EXT-SERVICE:service_state': None, u'os-extended-volumes:volumes_attached': [], u'metadata': {}}, 'metadata': {}, '_loaded': True}
        """
        return self.nova.servers.get(server)

    def nova_create(self, name, image, flavor, meta=None, files=None,
               reservation_id=None, min_count=None,
               max_count=None, security_groups=None, userdata=None,
               key_name=None, availability_zone=None,
               block_device_mapping=None, block_device_mapping_v2=None,
               nics=None, scheduler_hints=None,
               config_drive=None, **kwargs):
        """
        :param name:
        :param image:
        :param flavor:
        :param meta:
        :param files:
        :param reservation_id:
        :param min_count:
        :param max_count:
        :param security_groups:
        :param userdata:
        :param key_name:
        :param availability_zone:
        :param block_device_mapping:
        :param block_device_mapping_v2:
        :param nics:
        :param scheduler_hints:
        :param config_drive:
        :param kwargs:
        :return:
        {
            'links': [
                {
                    u'href': u'https: //compute.cascading.hybrid.huawei.com/v2/f1d64e22d48b46f7b807ac44d4078029/servers/e8d93567-eceb-41e4-b412-0498de57cb77',
                    u'rel': u'self'
                },
                {
                    u'href': u'https: //compute.cascading.hybrid.huawei.com/f1d64e22d48b46f7b807ac44d4078029/servers/e8d93567-eceb-41e4-b412-0498de57cb77',
                    u'rel': u'bookmark'
                }
            ],
            'adminPass': u'TGTrBbvJ3P4b',
            'OS-DCF: diskConfig': u'MANUAL',
            'manager': <novaclient.v1_1.servers.ServerManagerobjectat0x22640d0>,
            '_info': {
                u'links': [
                    {
                        u'href': u'https: //compute.cascading.hybrid.huawei.com/v2/f1d64e22d48b46f7b807ac44d4078029/servers/e8d93567-eceb-41e4-b412-0498de57cb77',
                        u'rel': u'self'
                    },
                    {
                        u'href': u'https: //compute.cascading.hybrid.huawei.com/f1d64e22d48b46f7b807ac44d4078029/servers/e8d93567-eceb-41e4-b412-0498de57cb77',
                        u'rel': u'bookmark'
                    }
                ],
                u'OS-DCF: diskConfig': u'MANUAL',
                u'id': u'e8d93567-eceb-41e4-b412-0498de57cb77',
                u'security_groups': [
                    {
                        u'name': u'default'
                    }
                ],
                u'adminPass': u'TGTrBbvJ3P4b'
            },
            'id': u'e8d93567-eceb-41e4-b412-0498de57cb77',
            'security_groups': [
                {
                    u'name': u'default'
                }
            ],
            '_loaded': False
        }
        """
        return self.nova.servers.create(name, image, flavor, meta, files,
               reservation_id, min_count,
               max_count, security_groups, userdata,
               key_name, availability_zone,
               block_device_mapping, block_device_mapping_v2,
               nics, scheduler_hints,
               config_drive, **kwargs)

    def nova_delete(self, server):
        return self.nova.servers.delete(server)

    def availability_zones_list(self):
        return self.nova.availability_zones.list()

    def nova_aggregate_create(self, name, availability_zone):
        result = None

        try:
            aggregate_result = self.nova.aggregates.create(name, availability_zone)

            log.info('created Aggregate result is : %s ' % aggregate_result)

            if aggregate_result.name == name:
                result = aggregate_result
        except Exception, e:
            log.error('Exception when create AG for %s, Exception: %s' % (name, traceback.format_exc()))
            print(e.message)

        return result

    def nova_host_list(self):
        result = False

        return result

    def nova_aggregate_add_host(self, aggregate, host):
        result = False

        try:
            add_result = self.nova.aggregates.add_host(aggregate, host)
            log.info('Add host<%s> to aggregate<%s>, result : %s ' % (host, aggregate, add_result))
            result = True
        except:
            log.error('Exception when add host<%s> to aggregate<%s>, Exception : %s ' %
                      (host, aggregate, traceback.format_exc()))

        return result

    def nova_aggregate_exist(self, name, availability_zone):
        result = False
        try:
            aggregates = self.nova.aggregates.list()
            for aggregate in aggregates:
                if aggregate.availability_zone == availability_zone:
                    result = True
        except nova_client.exceptions.NotFound:
            return result
        except:
            log.error('Exception when exec nova_aggregate_exist, Exception: %s' % traceback.format_exc())
            print traceback.format_exc()
            result = True

        return result

    def nova_floating_ip_create(self, name_floating_pool):
        """

        :param name_floating_pool:
        :return:
        {
            'ip': u'162.3.130.101',
            'fixed_ip': None,
            'instance_id': None,
            'manager': <novaclient.v1_1.floating_ips.FloatingIPManagerobjectat0x2162390>,
            '_info': {
                u'instance_id': None,
                u'ip': u'162.3.130.101',
                u'fixed_ip': None,
                u'id': u'07bea4ba-3082-4bf1-8e0d-673c6fd6a72a',
                u'pool': u'ci-ext-net'
            },
            'id': u'07bea4ba-3082-4bf1-8e0d-673c6fd6a72a',
            'pool': u'ci-ext-net',
            '_loaded': False
        }
        """
        return self.nova.floating_ips.create(name_floating_pool)

    def nova_floating_ip_delete(self, floating_ip):
        return self.nova.floating_ips.delete(floating_ip)

    def nova_floating_ip_associate(self, server, address, fixed_address=None):
        """
        Add a floating ip to an instance

        :param server: The :class:`Server` (or its ID) to add an IP to.
        :param address: The FloatingIP or string floating address to add.
        :param fixed_address: The FixedIP the floatingIP should be
                              associated with (optional)
        """

        return self.nova.servers.add_floating_ip(server, address, fixed_address=None)

    def nova_floating_ip_disassociate(self, server, address):
        """
        Remove a floating IP address.

        :param server: The :class:`Server` (or its ID) to remove an IP from.
        :param address: The FloatingIP or string floating address to remove.
        """

        return self.nova.servers.remove_floating_ip( server, address)

    def get_tenant_id_for_service(self):
        """
        To get tenant id by tenant name 'service'.

        step1: use list() to get all tenants:
            [<Tenant {u'enabled': True, u'description': None, u'name': u'admin', u'id': u'f7851684a9894e5a9590a97789552879'}>,
            <Tenant {u'enabled': True, u'description': None, u'name': u'service', u'id': u'04720946e4f34cf4afed11752b1f5136'}>]
        step2: then filter the one which name is 'service'

        :return: string, tenant id of tenant named 'service'
        """

        tenant_name = 'service'
        return self.get_tenant_id_by_tenant_name(tenant_name)

    def get_tenant_id_for_admin(self):
        return self.get_tenant_id_by_tenant_name('admin')

    def get_tenant_id_by_tenant_name(self, tenant_name):
        tenant_id = None
        tenants = self.keystone.tenants.list()

        if tenants is None:
            log.info('No any tenant in keystone.')
        else:
            for tenant in tenants:
                if tenant.name == tenant_name:
                    tenant_id = tenant.id
                    break
                else:
                    continue

        return tenant_id

    def get_service_id(self, service_type):
        service_id = None
        services = self.keystone.services.list()
        for service in services:
            if service.type == service_type:
                service_id = service.id
                break
            else:
                continue

        return service_id

    def create_endpoint(self, region, service_id, publicurl, adminurl=None,
                        internalurl=None):
        result = False
        create_result = self.keystone.endpoints.create(region, service_id, publicurl, adminurl, internalurl)
        if isinstance(create_result, Endpoint):
            result = True

        return result

    def create_endpoint_for_service(self, service_type, region, url):
        public_url = url
        admin_url = url
        internal_url = url
        try:
            service_id = self.get_service_id(service_type)

            if self.endpoint_exist(service_id, region):
                log.info('Endpoint for service<%s> region <%s> is exist, no need to create again.' %
                            (service_type, region))
                return

            if service_id is None:
                raise ValueError('Service id of type <%s> is None.' % service_type)

            create_result = self.create_endpoint(region, service_id, public_url, admin_url, internal_url)
            if create_result is True:
                log.info('SUCCESS to create endpoint for type <%s> region: <%s>' % (service_type, region))
            else:
                log.info('FAILED to create endpoint for type <%s> region: <%s>' % (service_type, region))
        except:
            err_info = 'Exception occur when create endpoint for type<%s> region <%s>, EXCEPTION %s' % \
                       (service_type, region, traceback.format_exc())
            log.info(err_info)

    def endpoint_exist(self, service_id, region):
        result = False
        endpoints = self.keystone.endpoints.list()
        for endpoint in endpoints:
            if endpoint.service_id == service_id and endpoint.region == region:
                result = True
                break
            else:
                continue
        return result

    def del_endpoint(self, regions):
        """

        :param regions: [], list of regions
        :return:
        """
        result = False
        endpoints = self.keystone.endpoints.list()
        for endpoint in endpoints:
            if endpoint.region in regions:
                self.keystone.endpoints.delete(endpoint.id)
            else:
                continue
        return result

    def neutron_create_net(self, name, shared=None, network_type=None, physical_network=None, router_external=None,
                           segment_id = None):
        """

        :param name:
        :param shared:
        :param network_type:
        :param physical_network:
        :return:
        {u'network':
            {
                u'status': u'ACTIVE',
                u'subnets': [],
                u'name': u'my-test-net-01',
                u'provider:physical_network': None,
                u'admin_state_up': True,
                u'tenant_id': u'f1d64e22d48b46f7b807ac44d4078029',
                u'provider:network_type': u'vxlan',
                u'router:external': False,
                u'shared': False,
                u'id': u'e2c83227-6d61-4776-9069-da1e368ba8eb',
                u'provider:segmentation_id': 5001
            }
        }
        """
        NETWORK = 'network'
        body = {NETWORK: {'name': name}}
        if shared is not None:
            body['network']['shared'] = shared
        if network_type is not None:
            body[NETWORK]['provider:network_type'] = network_type
        if physical_network is not None:
            body[NETWORK]['provider:physical_network'] = physical_network
        if router_external is not None:
            body[NETWORK]['router:external'] = router_external
        if segment_id is not None:
            body[NETWORK]['provider:segmentation_id'] = segment_id

        net_data = self.neutron.create_network(body)

        return net_data

    def neutron_delete_net(self, net_id):
        return self.neutron.delete_network(net_id)

    def neutron_show_net(self, net_id):
        """

        :param net_id:
        :return:
        {
            u'network':
            {
                u'status': u'ACTIVE',
                u'subnets': [],
                u'name': u'my-test-net-01',
                u'provider:physical_network': None,
                u'admin_state_up': True,
                u'tenant_id': u'f1d64e22d48b46f7b807ac44d4078029',
                u'provider:network_type': u'vxlan',
                u'router:external': False,
                u'shared': False,
                u'id': u'221933bf-56d8-407f-a237-beedb44d74c0',
                u'provider:segmentation_id': 5002
            }
        }
        """
        return self.neutron.show_network(net_id)

    def neutron_create_subnet(self, network_id, name, ip_version=4,
                              allocation_pools=None,
                              gateway_ip=None,
                              enable_dhcp=None,
                              cidr=None):
        """
        '{
            "subnet":
                {
                    "ip_version": 4,
                    "allocation_pools": [{"start": "182.3.145.10", "end": "182.3.145.30"}],
                    "gateway_ip": "182.3.110.1",
                    "name": "my-test-subnet01",
                    "enable_dhcp": false,
                    "network_id": "1d5589ac-feed-43bd-be6f-bb7556453c72",
                    "cidr": "182.3.0.0/16"
                }
        }'
        :return:
        {
            "subnet":
            {
                "name": "my-test-subnet01",
                "enable_dhcp": false,
                "network_id": "1d5589ac-feed-43bd-be6f-bb7556453c72",
                "tenant_id": "f1d64e22d48b46f7b807ac44d4078029",
                "dns_nameservers": [],
                "gateway_ip": "182.3.110.1",
                "ipv6_ra_mode": null,
                "allocation_pools": [{"start": "182.3.145.10", "end": "182.3.145.30"}],
                "host_routes": [],
                "ipv6_address_mode": null,
                "cidr": "182.3.0.0/16",
                "id": "904f6d22-3b03-4f40-9b51-2e8a6f542866"
            }
        }
        """
        SUBNET = 'subnet'
        body = {SUBNET: {'name': name, 'network_id': network_id}}

        if ip_version is not None:
            body[SUBNET]['ip_version'] = ip_version
        if allocation_pools is not None:
            body[SUBNET]['allocation_pools']=allocation_pools
        if gateway_ip is not None:
            body[SUBNET]['gateway_ip'] = gateway_ip
        if enable_dhcp is not None:
            body[SUBNET]['enable_dhcp'] = enable_dhcp
        if cidr is not None:
            body[SUBNET]['cidr'] = cidr

        subnet_data = self.neutron.create_subnet(body)

        return subnet_data

    def neutron_delete_subnet(self, subnet_id):
        return self.neutron.delete_subnet(subnet_id)

    def neutron_create_router(self, name):
        """

        :param name:
        :return:
        {"router": {
                    "status": "ACTIVE",
                    "external_gateway_info": null,
                    "name": "my-router",
                    "admin_state_up": true,
                    "tenant_id": "f1d64e22d48b46f7b807ac44d4078029",
                    "distributed": false,
                    "routes": [],
                    "ha": false,
                    "id": "77259208-b9e2-4598-bb23-9765b9d2b285"
                    }
        }
        """
        ROUTER = 'router'
        body = {ROUTER: {'distributed': 'False', 'name' : name, 'admin_state_up': True}}
        return self.neutron.create_router(body)

    def neutron_delete_router(self, router_id):
        return self.neutron.delete_router(router_id)

    def neutron_router_gateway_set(self, router_id, net_id):
        """

        :param router_id:
        :param net_id:
        :return:
        {"router":
            {"status": "ACTIVE",
            "external_gateway_info":
                {"network_id": "a65caeda-dfcd-4ce5-8023-fa4063b54a79",
                "enable_snat": true,
                "external_fixed_ips":
                        [{"subnet_id": "a4e05935-5aab-4dd3-b898-45cd69343c14", "ip_address": "162.3.130.105"}]
                },
            "name": "ci-ext-router",
            "admin_state_up": true,
            "tenant_id": "f1d64e22d48b46f7b807ac44d4078029",
            "distributed": false,
            "routes": [],
            "ha": false,
            "id": "a2825c15-b804-480f-a9f0-1d85a1202775"
            }
        }
        """
        body = {"network_id": net_id}
        return self.neutron.add_gateway_router(router_id, body)

    def neutron_router_gateway_clear(self, router_id):
        """

        :param router_id:
        :return:
        {"router":
            {"status": "ACTIVE",
            "external_gateway_info": null,
            "name": "ci-ext-router",
            "admin_state_up": true,
            "tenant_id": "f1d64e22d48b46f7b807ac44d4078029",
            "distributed": false,
            "routes": [],
            "ha": false,
            "id": "a2825c15-b804-480f-a9f0-1d85a1202775"
            }
        }
        """

        return self.neutron.remove_gateway_router(router_id)

    def neutron_router_interface_add(self, router_id, subnet_id):
        """

        :param router_id:
        :param subnet_id:
        :return:
         {
            "subnet_id": "029a1d41-58e4-4001-946e-be70dfaadb6e",
            "tenant_id": "f1d64e22d48b46f7b807ac44d4078029",
            "port_id": "22e33e8e-bbe2-4d66-b09a-2a55da4e45f2",
            "id": "a2825c15-b804-480f-a9f0-1d85a1202775"
        }
        """
        body = {"subnet_id": subnet_id}

        return self.neutron.add_interface_router(router_id, body)

    def neutron_router_interface_delete(self, router_id, subnet_id):
        """

        :param router_id:
        :param subnet_id:
        :return:
         {
            "subnet_id": "029a1d41-58e4-4001-946e-be70dfaadb6e",
            "tenant_id": "f1d64e22d48b46f7b807ac44d4078029",
            "port_id": "22e33e8e-bbe2-4d66-b09a-2a55da4e45f2",
            "id": "a2825c15-b804-480f-a9f0-1d85a1202775"
        }
        """
        body = {"subnet_id": subnet_id}
        return self.neutron.remove_interface_router(router_id, body)

    def glance_image_create(self):
        pass

    def glance_image_delete(self):
        pass

class RefCPSService(object):

    @staticmethod
    def update_template_params(service_name, template_name, params):
        return cps_server.update_template_params(service_name, template_name, params)

    @staticmethod
    def get_template_params(server, template):
        return cps_server.get_template_params(server, template)

    @staticmethod
    def cps_commit():
        return cps_server.cps_commit()

    @staticmethod
    def get_cps_http(url):
        return cps_server.get_cps_http(url)

    @staticmethod
    def post_cps_http(url, body):
        return cps_server.post_cps_http(url, body)

    @staticmethod
    def get_local_domain():
        return cps_server.get_local_domain()

    @staticmethod
    def host_list():
        """

        :return:
        """
        return cps_server.cps_host_list()

    @staticmethod
    def role_host_add(role_name, hosts):
        """

        :param role_name: string of role name, e.g. nova-proxy001
        :param hosts: list of hosts, e.g. ['9A5A2614-D21D-B211-83F3-000000821800', EF1503DA-AEC8-119F-8567-000000821800]
        :return:
        """
        return cps_server.role_host_add(role_name, hosts)

    @staticmethod
    def role_host_list(role):
        """

        :param role: string of role name, e.g. nova-proxy001
        :return:
        """
        return cps_server.get_role_host_list(role)


class RefCPSServiceExtent(object):
    @staticmethod
    def list_template_instance(service, template):
        url = '/cps/v1/instances?service=%s&template=%s' % (service, template)
        res_text = RefCPSService.get_cps_http(url)
        if not res_text is None:
            return json.loads(res_text)
        return None

    @staticmethod
    def host_template_instance_operate(service, template, action):
        url = '/cps/v1/instances?service=%s&template=%s' % (service, template)
        body = {'action': action}
        return RefCPSService.post_cps_http(url, body)


class CPSServiceBusiness(object):
    def __init__(self):
        self.NOVA = 'nova'
        self.NEUTRON = 'neutron'
        self.NEUTRON_l2 = 'neutron-l2'
        self.NEUTRON_l3 = 'neutron-l3'
        self.CINDER = 'cinder'
        self.OPT_STOP = 'STOP'
        self.OPT_START = 'START'
        self.STATUS_ACTIVE = 'active'
        self.DNS = 'dns'
        self.DNS_SERVER_TEMPLATE = 'dns-server'
        self.region_match_ip = {}

    def get_nova_proxy_template(self, proxy_number):
        return '-'.join([self.NOVA, proxy_number])

    def get_neutron_l2_proxy_template(self, proxy_number):
        return '-'.join([self.NEUTRON_l2, proxy_number])

    def get_neutron_l3_proxy_template(self, proxy_number):
        return '-'.join([self.NEUTRON_l3, proxy_number])

    def get_cinder_template(self, proxy_number):
        return '-'.join([self.CINDER, proxy_number])

    def stop_nova_proxy(self, proxy_number):
        nova_proxy_template = self.get_nova_proxy_template(proxy_number)
        RefCPSServiceExtent.host_template_instance_operate(self.NOVA, nova_proxy_template, self.OPT_STOP)

    def start_nova_proxy(self, proxy_number):
        nova_proxy_template = self.get_nova_proxy_template(proxy_number)
        RefCPSServiceExtent.host_template_instance_operate(self.NOVA, nova_proxy_template, self.OPT_START)

    def stop_cinder_proxy(self, proxy_number):
        cinder_proxy_template = self.get_cinder_template(proxy_number)
        RefCPSServiceExtent.host_template_instance_operate(self.CINDER, cinder_proxy_template, self.OPT_STOP)

    def start_cinder_proxy(self, proxy_number):
        cinder_proxy_template = self.get_cinder_template(proxy_number)
        RefCPSServiceExtent.host_template_instance_operate(self.CINDER, cinder_proxy_template, self.OPT_START)

    def stop_neutron_l2_proxy(self, proxy_number):
        neutron_proxy_template = self.get_neutron_l2_proxy_template(proxy_number)
        RefCPSServiceExtent.host_template_instance_operate(self.NEUTRON, neutron_proxy_template, self.OPT_STOP)

    def start_neutron_l2_proxy(self, proxy_number):
        neutron_proxy_template = self.get_neutron_l2_proxy_template(proxy_number)
        RefCPSServiceExtent.host_template_instance_operate(self.NEUTRON, neutron_proxy_template, self.OPT_START)

    def stop_neutron_l3_proxy(self, proxy_number):
        neutron_proxy_template = self.get_neutron_l3_proxy_template(proxy_number)
        RefCPSServiceExtent.host_template_instance_operate(self.NEUTRON, neutron_proxy_template, self.OPT_STOP)

    def start_neutron_l3_proxy(self, proxy_number):
        neutron_proxy_template = self.get_neutron_l3_proxy_template(proxy_number)
        RefCPSServiceExtent.host_template_instance_operate(self.NEUTRON, neutron_proxy_template, self.OPT_START)

    def stop_all(self, proxy_number):
        self.stop_cinder_proxy(proxy_number)
        self.stop_neutron_l2_proxy(proxy_number)
        self.stop_neutron_l3_proxy(proxy_number)
        self.stop_nova_proxy(proxy_number)

    def start_all(self, proxy_number):
        self.start_cinder_proxy(proxy_number)
        self.start_neutron_l2_proxy(proxy_number)
        self.start_neutron_l3_proxy(proxy_number)
        self.start_nova_proxy(proxy_number)

    def check_status_for_template(self, service, template, aim_status):
        template_instance_info = RefCPSServiceExtent.list_template_instance(service, template)
        if template_instance_info is None or len(template_instance_info.get('instances')) < 1:
            print('Template instance info of Service<%s> Template<%s> is None.' % (service, template))
            log.error('Template instance info of Service<%s> Template<%s> is None.' % (service, template))
            log.error('template_instance_info: %s' % template_instance_info)
            return False
        status = template_instance_info.get('instances')[0].get('hastatus')
        if status == aim_status:
            log.info('Status of service<%s>, template<%s> is: %s' % (service, template, status))
            print('Status of service<%s>, template<%s> is: %s' % (service, template, status))
            return True
        else:
            log.error('Status of service<%s>, template<%s> is: %s' % (service, template, status))
            print('Status of service<%s>, template<%s> is: %s' % (service, template, status))
            return False

    def check_nova_template(self, proxy_number):
        nova_template = self.get_nova_proxy_template(proxy_number)
        self.check_status_for_template(self.NOVA, nova_template, self.STATUS_ACTIVE)

    def check_neutron_l2_template(self, proxy_number):
        neutron_l2_template = self.get_neutron_l2_proxy_template(proxy_number)

        self.check_status_for_template(self.NEUTRON, neutron_l2_template, self.STATUS_ACTIVE)

    def check_neutron_l3_template(self, proxy_number):
        neutron_l3_template = self.get_neutron_l3_proxy_template(proxy_number)
        self.check_status_for_template(self.NEUTRON, neutron_l3_template, self.STATUS_ACTIVE)

    def check_cinder_template(self, proxy_number):
        cinder_template = self.get_cinder_template(proxy_number)
        self.check_status_for_template(self.CINDER, cinder_template, self.STATUS_ACTIVE)

    def check_all_service_template_status(self, proxy_number):
        self.check_cinder_template(proxy_number)
        self.check_neutron_l2_template(proxy_number)
        self.check_neutron_l3_template(proxy_number)
        self.check_nova_template(proxy_number)

    def get_dns_info(self):
        """
        by "cps template-params-show --service dns dns-server", it will get following result:
        {u'cfg':
            {
            u'address': u'/cascading.hybrid.huawei.com/162.3.120.50,
                        /identity.cascading.hybrid.huawei.com/162.3.120.50,
                        /image.cascading.hybrid.huawei.com/162.3.120.50,
                        /az01.shenzhen--fusionsphere.huawei.com/162.3.120.52,
                        /az11.shenzhen--vcloud.huawei.com/162.3.120.58,
                        /az31.singapore--aws.vodafone.com/162.3.120.64',
            u'network': u'[]',
            u'server': u''
            }
        }
        :return:
        """
        dns_info = RefCPSService.get_template_params(self.DNS, self.DNS_SERVER_TEMPLATE)
        return dns_info

    def get_region_match_ip(self):
        dns_info = self.get_dns_info()
        addresses = dns_info['cfg']['address']
        if not addresses:
            log.info('address is none in dns info')
            return {}
        region_match_ip = {}
        address_list = addresses.split(',')
        for address in address_list:
            if address is not None:
                tmp_address_content = address.split('/')[1:]
                if len(tmp_address_content) == 2:
                    region_match_ip[tmp_address_content[0]] = tmp_address_content[1]

        return region_match_ip

    def get_az_ip(self, az):
        """
        if the region is "az01.shenzhen--fusionsphere.huawei.com", the az is "az01"
        :param az: string, the full name of az, e.g. az01, az11 and so on.
        :return: array list, array list of ip address, e.g. ['162.3.120.52', '162.3.120.53', ...]
        """
        if not self.region_match_ip:
            self.region_match_ip = self.get_region_match_ip()
        ip_list = []
        for region, ip in self.region_match_ip.items():
            if region.startswith(az):
                ip_list.append(ip)

        return ip_list

    def get_cascading_ip(self):
        """

        :return: array list, array list of ip address, e.g. ['162.3.120.52', '162.3.120.53', ...]
        """
        return self.get_az_ip('cascading')

    def get_openstack_hosts(self):
        """

        :return: array list, array list of ip address, e.g. ['162.3.120.52', '162.3.120.53', ...]
        """
        return self.get_az_ip('az0')

    def get_vcloud_node_hosts(self):
        """

        :return: array list, array list of ip address, e.g. ['162.3.120.52', '162.3.120.53', ...]
        """
        return self.get_az_ip('az1')

    def get_aws_node_hosts(self):
        """

        :return: array list, array list of ip address, e.g. ['162.3.120.52', '162.3.120.53', ...]
        """
        return self.get_az_ip('az3')

    def get_os_region_name(self):
        region = RefCPSService.get_local_domain()
        os_region_name = '.'.join([RefFsSystemUtils.get_az_by_domain(region),
                                   RefFsSystemUtils.get_dc_by_domain(region)])

        return os_region_name

class RefFsUtils(object):

    @staticmethod
    def get_local_dc_az():
        return fsutils.get_local_dc_az()

class RefFsSystemUtils(object):

    @staticmethod
    def get_az_by_domain(proxy_matched_region):
        domain_url = "".join(['https://service.', proxy_matched_region, ':443'])
        return fs_system_util.get_az_by_domain(domain_url)

    @staticmethod
    def get_dc_by_domain(proxy_matched_region):
        domain_url = "".join(['https://service.', proxy_matched_region, ':443'])
        return fs_system_util.get_dc_by_domain(domain_url)


class SSHError(Exception):
    pass


class SSHTimeout(SSHError):
    pass


class SSH(object):
    """Represent ssh connection."""

    def __init__(self, user, host, port=22, pkey=None,
                 key_filename=None, password=None):
        """Initialize SSH client.

        :param user: ssh username
        :param host: hostname or ip address of remote ssh server
        :param port: remote ssh port
        :param pkey: RSA or DSS private key string or file object
        :param key_filename: private key filename
        :param password: password
        """

        self.user = user
        self.host = host
        self.port = port
        self.pkey = self._get_pkey(pkey) if pkey else None
        self.password = password
        self.key_filename = key_filename
        self._client = False

    def _get_pkey(self, key):
        if isinstance(key, six.string_types):
            key = six.moves.StringIO(key)
        errors = []
        for key_class in (paramiko.rsakey.RSAKey, paramiko.dsskey.DSSKey):
            try:
                return key_class.from_private_key(key)
            except paramiko.SSHException as e:
                errors.append(e)
        raise SSHError("Invalid pkey: %s" % (errors))

    def _get_client(self):
        if self._client:
            return self._client
        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._client.connect(self.host, username=self.user,
                                 port=self.port, pkey=self.pkey,
                                 key_filename=self.key_filename,
                                 password=self.password, timeout=1)
            return self._client
        except Exception as e:
            message = ("Exception %(exception_type)s was raised "
                        "during connect to %(user)s@%(host)s:%(port)s. "
                        "Exception value is: %(exception)r")
            self._client = False
            raise SSHError(message % {"exception": e,
                                      "user": self.user,
                                      "host": self.host,
                                      "port": self.port,
                                      "exception_type": type(e)})

    def close(self):
        self._client.close()
        self._client = False

    def run(self, cmd, stdin=None, stdout=None, stderr=None,
            raise_on_error=True, timeout=3600):
        """Execute specified command on the server.

        :param cmd:             Command to be executed.
        :param stdin:           Open file or string to pass to stdin.
        :param stdout:          Open file to connect to stdout.
        :param stderr:          Open file to connect to stderr.
        :param raise_on_error:  If False then exit code will be return. If True
                                then exception will be raized if non-zero code.
        :param timeout:         Timeout in seconds for command execution.
                                Default 1 hour. No timeout if set to 0.
        """

        client = self._get_client()

        if isinstance(stdin, six.string_types):
            stdin = six.moves.StringIO(stdin)

        return self._run(client, cmd, stdin=stdin, stdout=stdout,
                         stderr=stderr, raise_on_error=raise_on_error,
                         timeout=timeout)

    def _run(self, client, cmd, stdin=None, stdout=None, stderr=None,
             raise_on_error=True, timeout=3600):

        if isinstance(cmd, (list, tuple)):
            cmd = " ".join(six.moves.shlex_quote(str(p)) for p in cmd)

        transport = client.get_transport()
        session = transport.open_session()
        session.exec_command(cmd)
        start_time = time.time()

        data_to_send = ""
        stderr_data = None

        # If we have data to be sent to stdin then `select' should also
        # check for stdin availability.
        if stdin and not stdin.closed:
            writes = [session]
        else:
            writes = []

        while True:
            # Block until data can be read/write.
            r, w, e = select.select([session], writes, [session], 1)

            if session.recv_ready():
                data = session.recv(4096)
                #LOG.debug("stdout: %r" % data)
                if stdout is not None:
                    stdout.write(data)
                continue

            if session.recv_stderr_ready():
                stderr_data = session.recv_stderr(4096)
                #LOG.debug("stderr: %r" % stderr_data)
                if stderr is not None:
                    stderr.write(stderr_data)
                continue

            if session.send_ready():
                if stdin is not None and not stdin.closed:
                    if not data_to_send:
                        data_to_send = stdin.read(4096)
                        if not data_to_send:
                            stdin.close()
                            session.shutdown_write()
                            writes = []
                            continue
                    sent_bytes = session.send(data_to_send)
                    #LOG.debug("sent: %s" % data_to_send[:sent_bytes])
                    data_to_send = data_to_send[sent_bytes:]

            if session.exit_status_ready():
                break

            if timeout and (time.time() - timeout) > start_time:
                args = {"cmd": cmd, "host": self.host}
                raise SSHTimeout(("Timeout executing command "
                                   "'%(cmd)s' on host %(host)s") % args)
            if e:
                raise SSHError("Socket error.")

        exit_status = session.recv_exit_status()
        if 0 != exit_status and raise_on_error:
            fmt = ("Command '%(cmd)s' failed with exit_status %(status)d.")
            details = fmt % {"cmd": cmd, "status": exit_status}
            if stderr_data:
                details += (" Last stderr data: '%s'.") % stderr_data
            raise SSHError(details)
        return exit_status

    def execute(self, cmd, stdin=None, timeout=3600):
        """Execute the specified command on the server.

        :param cmd:     Command to be executed, can be a list.
        :param stdin:   Open file to be sent on process stdin.
        :param timeout: Timeout for execution of the command.

        :returns: tuple (exit_status, stdout, stderr)
        """
        stdout = six.moves.StringIO()
        stderr = six.moves.StringIO()

        exit_status = self.run(cmd, stderr=stderr,
                               stdout=stdout, stdin=stdin,
                               timeout=timeout, raise_on_error=False)
        stdout.seek(0)
        stderr.seek(0)
        return (exit_status, stdout.read(), stderr.read())

    def wait(self, timeout=120, interval=1):
        """Wait for the host will be available via ssh."""
        start_time = time.time()
        while True:
            try:
                return self.execute("uname")
            except (socket.error, SSHError) as e:
                #LOG.debug("Ssh is still unavailable: %r" % e)
                time.sleep(interval)
            if time.time() > (start_time + timeout):
                raise SSHTimeout(("Timeout waiting for '%s'") % self.host)

    def _put_file_sftp(self, localpath, remotepath, mode=None):
        client = self._get_client()

        sftp = client.open_sftp()
        sftp.put(localpath, remotepath)
        if mode is None:
            mode = 0o777 & os.stat(localpath).st_mode
        sftp.chmod(remotepath, mode)

    def _put_file_shell(self, localpath, remotepath, mode=None):
        cmd = ["cat > %s" % remotepath]
        if mode is not None:
            cmd.append("chmod 0%o %s" % (mode, remotepath))

        with open(localpath, "rb") as localfile:
            cmd = "; ".join(cmd)
            self.run(cmd, stdin=localfile)

    def put_file(self, localpath, remotepath, mode=None):
        """Copy specified local file to the server.

        :param localpath:   Local filename.
        :param remotepath:  Remote filename.
        :param mode:        Permissions to set after upload
        """

        try:
            self._put_file_sftp(localpath, remotepath, mode=mode)
        except paramiko.SSHException:
            self._put_file_shell(localpath, remotepath, mode=mode)



if __name__ == '__main__':
    cps = RefServices()
    # net_data = cps.neutron_create_net('my-test-net-01')
    # print net_data
    # net_id = net_data['network']['id']
    # print net_id
    # net_get_data = cps.neutron_show_net(net_id)
    # print net_get_data
    # print('create subnet')
    # subnet_data = cps.neutron_create_subnet(net_id,
    #                                         'my-test-subnet01',
    #                                         allocation_pools=[{"start": "182.3.145.10", "end": "182.3.145.30"}],
    #                                         cidr='182.3.145.0/24'
    #                                         )
    # print('Subnet: %s' % subnet_data)
    # subnet_id = subnet_data['subnet']['id']
    # print('subnet id: %s' % subnet_id)
    # cps.neutron_delete_subnet(subnet_id)
    # cps.neutron_delete_net(net_id)
    router_data = cps.neutron_create_router('my-router01')
    router_id = router_data['router']['id']
    subnet_id = '029a1d41-58e4-4001-946e-be70dfaadb6e'
    cps.neutron_router_interface_add(router_id, subnet_id)
    cps.neutron_router_interface_delete(router_id, subnet_id)

    cps.neutron_delete_router(router_id)
