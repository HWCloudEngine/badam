__author__ = 'nash.xiejun'

import os
import logging
import traceback
import sys
import json

from keystoneclient.v2_0.endpoints import Endpoint
from utils import print_log, ELog
from novaclient import client as nova_client

from nova.proxy import clients
from nova.proxy import compute_context

from install_tool import cps_server, fsutils, fs_system_util
# TODO:
# import cps_server
# import fsutils
# import fs_system_util

logger_name = __name__
logger_module = logging.getLogger(__name__)
logger = ELog(logger_module)


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

    def nova_list(self):
        return self.nova.servers.list(detailed=True)

    def nova_aggregate_create(self, name, availability_zone):
        result = None

        try:
            aggregate_result = self.nova.aggregates.create(name, availability_zone)

            print_log('created Aggregate result is : %s ' % aggregate_result, logging.INFO)

            if aggregate_result.name == name:
                result = aggregate_result
        except Exception, e:
            logger_module.error('Exception when create AG for %s, Exception: %s' % (name, traceback.format_exc()),
                         logging.ERROR)
            print(e.message)

        return result

    def nova_host_list(self):
        result = False
        # try:
        #     add_result = self.nova.hosts.
        #     print_log('Add host<%s> to aggregate<%s>, result : %s ' % (host, aggregate, add_result), logging.INFO)
        #     result = True
        # except:
        #     print_log('Exception when add host<%s> to aggregate<%s>, Exception : %s ' %
        #               (host, aggregate, traceback.format_exc()), logging.ERROR)

        return result

    def nova_aggregate_add_host(self, aggregate, host):
        result = False

        try:
            add_result = self.nova.aggregates.add_host(aggregate, host)
            print_log('Add host<%s> to aggregate<%s>, result : %s ' % (host, aggregate, add_result), logging.INFO)
            result = True
        except:
            print_log('Exception when add host<%s> to aggregate<%s>, Exception : %s ' %
                      (host, aggregate, traceback.format_exc()), logging.ERROR)

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
            logger.error('Exception when exec nova_aggregate_exist, Exception: %s' % traceback.format_exc())
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
            logger.info('No any tenant in keystone.')
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
                logger.info('Endpoint for service<%s> region <%s> is exist, no need to create again.' %
                            (service_type, region))
                return

            if service_id is None:
                raise ValueError('Service id of type <%s> is None.' % service_type)

            create_result = self.create_endpoint(region, service_id, public_url, admin_url, internal_url)
            if create_result is True:
                logger.info('SUCCESS to create endpoint for type <%s> region: <%s>' % (service_type, region))
            else:
                logger.info('FAILED to create endpoint for type <%s> region: <%s>' % (service_type, region))
        except:
            err_info = 'Exception occur when create endpoint for type<%s> region <%s>, EXCEPTION %s' % \
                       (service_type, region, traceback.format_exc())
            logger.info(err_info)

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