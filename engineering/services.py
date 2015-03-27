__author__ = 'nash.xiejun'

import os
import logging
import traceback
import sys
from utils import get_hybrid_cloud_badam_path

sys.path.append(get_hybrid_cloud_badam_path())

from keystoneclient.v2_0 import client as keystone_client
from keystoneclient.v2_0.endpoints import Endpoint
from utils import print_log, ELog
from common.econstants import EndpointType, EndpointURL
from common.engineering_logging import log_for_func_args_of_class
from novaclient import client as nova_client

logger_name = __name__
logger_module = logging.getLogger(__name__)
logger = ELog(logger_module)


class RefServices(object):
    def __init__(self):
        self.tenant = os.environ['OS_TENANT_NAME']
        self.user = os.environ['OS_USERNAME']
        self.pwd = os.environ['OS_PASSWORD']
        self.url = os.environ['OS_AUTH_URL']
        self.keystone = keystone_client.Client(username=self.user, password=self.pwd,
                                               tenant_name=self.tenant, auth_url=self.url)
        credentials = self.get_nova_credentials_v2()
        self.nova = nova_client.Client(**credentials)

    def nova_list(self):
        print(self.nova.servers.list())

    def nova_aggregate_create(self, name, availability_zone):
        result = None

        try:
            aggregate_result = self.nova.aggregates.create(name, availability_zone)

            print_log('created Aggregate result is : %s ' % aggregate_result, logging.INFO)

            if aggregate_result.name == name:
                result = aggregate_result
        except:
            print_log('Exception when create AG for %s, Exception: %s' % (name, traceback.format_exc()), logging.ERROR)

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
            aggregate = self.nova.aggregates.get(name)
            if aggregate.availability_zone == availability_zone:
                result = True
        except nova_client.exceptions.NotFound:
            return result
        except:
            logger.error('Exception when exec nova_aggregate_exist, Exception: %s' % traceback.format_exc())
            result = True

        return result

    def get_nova_credentials_v2(self):
        """
        d = {'version': '2', 'username' : os.environ['OS_USERNAME'], 'api_key' : os.environ['OS_PASSWORD'], 'auth_url' : os.environ['OS_AUTH_URL'], 'project_id' : os.environ['OS_TENANT_NAME']}
        :return:
        """
        d = {}
        d['version'] = '2'
        d['username'] = os.environ['OS_USERNAME']
        d['api_key'] = os.environ['OS_PASSWORD']
        d['auth_url'] = os.environ['OS_AUTH_URL']
        d['project_id'] = os.environ['OS_TENANT_NAME']
        return d

    @log_for_func_args_of_class(logger_name)
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
        create_result = self.keystone.endpoints.create(region, service_id, publicurl, adminurl=None, internalurl=None)
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

    def create_endpoint_for_nova(self, region, ip):
        self.create_endpoint_for_service(EndpointType.COMPUTE, region, EndpointURL.COMPUTE % ip)

    def create_endpoint_for_cinder(self, region, ip):
        self.create_endpoint_for_service(EndpointType.VOLUME, region, EndpointURL.VOLUME % ip)
        self.create_endpoint_for_service(EndpointType.VOLUME2, region, EndpointURL.VOLUME2 % ip)

    def create_endpoint_for_glance(self, region, ip):
        self.create_endpoint_for_service(EndpointType.IMAGE, region, EndpointURL.IMAGE % ip)

    def create_endpoint_for_ec2(self, region, ip):
        self.create_endpoint_for_service(EndpointType.EC2, region, EndpointURL.EC2 % ip)

    def create_endpoint_for_network(self, region, ip):
        self.create_endpoint_for_service(EndpointType.NETWORK, region, EndpointURL.NETWORK % ip)

    def create_endpoint_for_heat(self, region, ip):
        self.create_endpoint_for_service(EndpointType.ORCHESTRATION, region, EndpointURL.ORCHESTRATION % ip)

    def create_endpoint_for_ceilometer(self, region, ip):
        self.create_endpoint_for_service(EndpointType.METERING, region, EndpointURL.METERING % ip)

    def create_endpoints(self, region, ip):
        self.create_endpoint_for_nova(region, ip)
        self.create_endpoint_for_cinder(region, ip)
        self.create_endpoint_for_glance(region, ip)
        self.create_endpoint_for_network(region, ip)
        self.create_endpoint_for_heat(region, ip)
        self.create_endpoint_for_ceilometer(region, ip)
        self.create_endpoint_for_ec2(region, ip)


if __name__ == '__main__':
    print('Start Create Endpoint...')

    region = 'sz-az-31'
    ip = '162.3.110.83'
    services = RefServices()
    # services.del_endpoint(['sz_az_01', 'sz_az_02'])
    # services.create_endpoints(region, ip)
    services.nova_aggregate_create('AG-AZ-01', 'wla-cascading-host01')
    services.nova_aggregate_exist('AG-AZ-01', 'AZ-01')
