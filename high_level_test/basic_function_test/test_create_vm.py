__author__ = 'nash.xiejun'
import time
import unittest
import os

from services import RefServices


def export_env():
    os.environ['OS_AUTH_URL'] = 'https://identity.cascading.hybrid.huawei.com:443/identity/v2.0'
    os.environ['OS_USERNAME'] = 'cloud_admin'
    os.environ['OS_TENANT_NAME'] = 'admin'
    os.environ['OS_REGION_NAME'] = 'cascading.hybrid'
    os.environ['NOVA_ENDPOINT_TYPE'] = 'publicURL'
    os.environ['CINDER_ENDPOINT_TYPE'] = 'publicURL'
    os.environ['OS_ENDPOINT_TYPE'] = 'publicURL'
    os.environ['OS_VOLUME_API_VERSION'] = '2'
    os.environ['OS_PASSWORD'] = 'FusionSphere123'
export_env()

class TestNova(unittest.TestCase):

    def test_create_vm_in_az01(self):
        ACTIVE_STATUS = 'ACTIVE'
        SERVER_NAME = 'test-ci-vm-01'
        nics = [{'net-id': '43ec660c-0687-4be4-a781-700ce81931d2'}]
        services = RefServices()
        created_server = services.nova_create(name=SERVER_NAME,
                         image='8d7fa38b-6991-4761-a990-adf02995defc',
                         flavor=1,
                         availability_zone='az01.shenzhen--fusionsphere',
                         nics=nics)
        status_last_check = ''
        # wait for 60 seconds, every 10 seconds check one times, if status is active, pass.
        for i in range(6):
            servers = services.nova_list()

            for server in servers:

                if server.name == SERVER_NAME:
                    status_last_check = server.status
                    if status_last_check == ACTIVE_STATUS:
                        break
                    else:
                        time.sleep(10)
                        continue
                else:
                    continue
        # if exceed 60 seconds, status is still not active, failed.
        self.assertEqual(ACTIVE_STATUS, status_last_check)

        if status_last_check == ACTIVE_STATUS:
            services.nova_delete(created_server)

    def test_create_vm_in_az11(self):
        self.assertEqual('test', 'test')

    def test_create_vm_in_az31(self):
        self.assertEqual('test', 'test')


suite = unittest.TestLoader().loadTestsFromTestCase(TestNova)
unittest.TextTestRunner(verbosity=2).run(suite)