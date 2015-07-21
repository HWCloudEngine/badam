__author__ = 'nash.xiejun'
import sys
import os
import traceback
import json

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

import log

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
        keystone_credentials = self.get_keystone_credentials()
        self.keystone = self.get_keystone_client(keystone_credentials)
        nova_credentials = self.get_nova_credentials_v2()
        self.nova = self.get_nova_sync_client(nova_credentials)
        self.neutron = self.get_neutron_client(nova_credentials)

    def get_keystone_credentials(self):
        d = {}
        d['version'] = '2'
        d['username'] = self.user
        d['password'] = self.pwd
        d['auth_url'] = self.auth_url
        d['tenant'] = self.tenant
        if self.region_name is not None:
            d['region_name'] = self.region_name

        d['bypass_url'] = self.bypass_url

        return d

    def get_nova_credentials_v2(self):
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

        if self.bypass_url is not None:
            d['bypass_url'] = self.bypass_url

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

    def nova_list(self, search_opts=None):
        return self.nova.servers.list(detailed=True, search_opts=search_opts)

    def nova_show(self, server):
        return self.nova.servers.get(server)

    def nova_create(self, name, image, flavor, meta=None, files=None,
               reservation_id=None, min_count=None,
               max_count=None, security_groups=None, userdata=None,
               key_name=None, availability_zone=None,
               block_device_mapping=None, block_device_mapping_v2=None,
               nics=None, scheduler_hints=None,
               config_drive=None, **kwargs):
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

if __name__ == '__main__':
    cps = CPSServiceBusiness()
    print(cps.get_dns_info())