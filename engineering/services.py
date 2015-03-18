__author__ = 'nash.xiejun'

import logging

from keystoneclient.v2_0 import client as keystone_client
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
