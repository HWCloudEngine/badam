__author__ = 'nash.xiejun'

import logging
import traceback

from keystoneclient.v2_0 import client as keystone_client
from keystoneclient.v2_0.endpoints import Endpoint
from utils import print_log
from common.econstants import EndpointType, EndpointURL

from common.config import CONF


logger = logging.getLogger(__name__)

class RefServices(object):

    def __init__(self):
        self.tenant = 'admin'
        self.user = 'admin'
        self.pwd = 'openstack'
        self.url = 'http://162.3.110.99:5000/v2.0'
        self.keystone = keystone_client.Client(username=self.user, password=self.pwd, tenant_name=self.tenant, auth_url=self.url)

    def get_tenant_id_for_service(self):
        """
        To get tenant id by tenant name 'service'.

        step1: use list() to get all tenants:
            [<Tenant {u'enabled': True, u'description': None, u'name': u'admin', u'id': u'f7851684a9894e5a9590a97789552879'}>,
            <Tenant {u'enabled': True, u'description': None, u'name': u'service', u'id': u'04720946e4f34cf4afed11752b1f5136'}>]
        step2: then filter the one which name is 'service'

        :return: string, tenant id of tenant named 'service'
        """
        tenant_id = None
        tenants = self.keystone.tenants.list()

        if tenants is None:
            logger.info('No any tenant in keystone.')
        else:
            for tenant in tenants:
                if tenant.name == 'service':
                    tenant_id = tenant.id
                    break
                else:
                    continue

        return tenant_id

    def get_service_id(self, service_type):
        services = self.keystone.services.list()
        for service in services:
            if service.type == service_type:
                return id
            else:
                return None

    def create_endpoint(self, region, service_id, publicurl, adminurl=None,
               internalurl=None):
        result = False
        create_result = self.keystone.endpoints.create(region, service_id, publicurl, adminurl=None, internalurl=None)
        if  isinstance(create_result, Endpoint):
            result = True

        return result

    def create_endpoint_for_service(self, service_type, region, url):
        public_url = url
        admin_url = url
        internal_url = url
        try:
            service_id = self.get_service_id(service_type)
            create_result = self.create_endpoint(region, service_id, public_url, admin_url, internal_url)
            if create_result is True:
                print_log('SUCCESS to create endpoint for %s.' % service_type, logging.INFO)
            else:
                print_log('FAILED to create endpoint for %s.' % service_type, logging.ERROR)
        except:
            err_info = 'Exception occur when create endpoint for %s, EXCEPTION %s' % (service_type, traceback.format_exc())
            print_log(err_info, logging.ERROR)

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
        self.create_endpoint_for_service(EndpointType.ORCHESTRATION, region, EndpointURL.METERING % ip)
