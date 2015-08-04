__author__ = 'nash.xiejun'
import time
import unittest2
import os
import traceback

from services import RefServices, SSH, LOG_INIT, CommonUtils
import log
log.init(LOG_INIT)

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

class TestNova(unittest2.TestCase):

    def setUp(self):
        """
        The setUp() and tearDown() methods allow you to define instructions that will be executed
        before and after each test method.
        :return:
        """
        pass

    def tearDown(self):
        """
        The setUp() and tearDown() methods allow you to define instructions that will be executed
        before and after each test method.
        :return:
        """
        pass

    @classmethod
    def setUpClass(cls):
        """
        The setUpClass() and tearDownClass() methods allow you to define instructions that will be executed
        before and after each test class.
        :return:
        """
        cls.ref_services = RefServices()
        cls.image_id_emall_backend = 'cfde0324-0ca6-4883-b160-bf06383ad466'
        cls.image_id_emall_web = '78576f89-95cc-4228-9301-9d59cc2705c1'
        cls.region_az01 = 'az01.shenzhen--fusionsphere'
        cls.region_az11 = 'az11.shenzhen--vcloud'
        cls.region_az31 = 'az31.singapore--aws'
        cls.ext_router = 'ext-router'
        cls.name_ci_ext_net = 'ci-ext-net'
        cls.name_floating_ip_pool = 'ci-ext-net'


        # neutron net-create ci-ext-net --router:external True --provider:physical_network physnet1
        # --provider:network_type vlan --provider:segmentation_id 1000
        cls.ci_ext_net = \
            cls.ref_services.neutron_create_net('ci-ext-net',
                                                      router_external=True,
                                                      network_type='vlan',
                                                      physical_network='physnet1',
                                                      segment_id='1000')
        cls.ci_ext_net_id = cls.ci_ext_net['network']['id']

        # neutron subnet-create  ci-ext-net --name ci-ext-subnet
        # --allocation-pool start=162.3.130.100,end=162.3.130.130 --disable-dhcp --gateway 162.3.110.1 162.3.0.0/16
        cls.ci_ext_subnet = \
            cls.ref_services.neutron_create_subnet(cls.ci_ext_net_id,
                                             'ci-ext-subnet01',
                                             allocation_pools=[{"start": "162.3.130.100", "end": "162.3.130.130"}],
                                             enable_dhcp=False,
                                             gateway_ip='162.3.110.1',
                                             cidr='162.3.0.0/16')
        cls.ci_ext_subnet_id = cls.ci_ext_subnet['subnet']['id']

        # neutron net-create ci-net01 --router:external False --provider:network_type vxlan
        cls.ci_net01 = \
            cls.ref_services.neutron_create_net('ci-net01',
                                                      router_external=False,
                                                      network_type='vxlan')
        cls.ci_net01_id = cls.ci_net01['network']['id']

        # neutron subnet-create ci-net01 --name ci-subnet01  --allocation-pool start=192.168.145.2,end=192.168.145.50
        # --disable-dhcp --gateway 192.168.145.1 192.168.145.0/24
        cls.ci_subnet01 = \
            cls.ref_services.neutron_create_subnet(cls.ci_net01_id,
                                             'ci-subnet01',
                                             allocation_pools=[{"start": "192.168.145.2", "end": "192.168.145.50"}],
                                             enable_dhcp=True,
                                             gateway_ip='192.168.145.1',
                                             cidr='192.168.145.0/24')
        cls.ci_subnet01_id = cls.ci_subnet01['subnet']['id']

        cls.ext_router_data = cls.ref_services.neutron_create_router(cls.ext_router)
        cls.ext_router_id = cls.ext_router_data['router']['id']

        cls.ref_services.neutron_router_gateway_set(cls.ext_router_id, cls.ci_ext_net_id)

        cls.ref_services.neutron_router_interface_add(cls.ext_router_id, cls.ci_subnet01_id)

    @classmethod
    def tearDownClass(cls):
        """
        The setUpClass() and tearDownClass() methods allow you to define instructions that will be executed
        before and after each test class.
        :return:
        :return:
        """

        CommonUtils.circle_call(cls.ref_services.neutron_router_interface_delete, 60, 1,
                                router_id=cls.ext_router_id,
                                subnet_id=cls.ci_subnet01_id)
        CommonUtils.circle_call(cls.ref_services.neutron_router_gateway_clear, 60, 1,
                                router_id=cls.ext_router_id)
        CommonUtils.circle_call(cls.ref_services.neutron_delete_router, 60, 1, router_id=cls.ext_router_id)

        CommonUtils.circle_call(cls.ref_services.neutron_delete_subnet, 60, 1, subnet_id=cls.ci_ext_subnet_id)
        CommonUtils.circle_call(cls.ref_services.neutron_delete_net, 60, 1, net_id=cls.ci_ext_net_id)

        CommonUtils.circle_call(cls.ref_services.neutron_delete_subnet, 60, 1, subnet_id=cls.ci_subnet01_id)
        CommonUtils.circle_call(cls.ref_services.neutron_delete_net, 60, 1, net_id=cls.ci_net01_id)

    def _check_vm_status(self, created_server, aim_status, check_times, check_interval):
        status_last_check = ''
        # wait for 60 seconds, every 10 seconds check one times, if status is active, pass.
        for i in range(check_times):
            server = self.ref_services.nova_show(created_server)
            status_last_check = server.status

            if status_last_check == aim_status:
                break
            else:
                time.sleep(check_interval)
                continue

        # if exceed 60 seconds, status is still not active, failed.
        self.assertEqual(aim_status, status_last_check)

        return status_last_check

    def _check_server_exist(self, created_server, times, interval):
        for i in range(times):
            try:
                server = self.ref_services.nova_show(created_server)
                time.sleep(interval)
            except Exception, e:
                return 'not exist'
        return 'exist'

    def remote_execute(self, host, cmd):
        ssh = SSH('root', host, password='magento')
        try:
            exit_status, stdout, stderr = ssh.execute(cmd)
            return exit_status, stdout, stderr
        except Exception, e:
            log.error('Exception: %s' % traceback.format_exc())
        finally:
            ssh.close()

    #@unittest2.skip("demonstrating skipping")
    def test_create_vm_in_az01(self):
        ACTIVE_STATUS = 'ACTIVE'
        SERVER_NAME = 'ci-az01-vm-01'
        nics = [{'net-id': self.ci_net01_id}]
        created_server = self.ref_services.nova_create(name=SERVER_NAME,
                         image=self.image_id_emall_backend,
                         flavor=1,
                         availability_zone=self.region_az01,
                         nics=nics)

        status_last_check = self._check_vm_status(created_server, ACTIVE_STATUS, 36, 5)

        # if status_last_check == ACTIVE_STATUS:
        self.ref_services.nova_delete(created_server)

        result_server_exist = self._check_server_exist(created_server, 60, 5)
        self.assertEqual('not exist', result_server_exist)

    @unittest2.skip("demonstrating skipping")
    def test_create_vm_in_az11(self):
        ACTIVE_STATUS = 'ACTIVE'
        SERVER_NAME = 'ci-az11-vm-01'
        nics = [{'net-id': self.ci_net01_id}]
        created_server = self.ref_services.nova_create(name=SERVER_NAME,
                         image=self.image_id_emall_backend,
                         flavor=1,
                         availability_zone=self.region_az11,
                         nics=nics)
        status_last_check = self._check_vm_status(created_server, ACTIVE_STATUS, 120, 5)

        # if status_last_check == ACTIVE_STATUS:
        self.ref_services.nova_delete(created_server)
        result_server_exist = self._check_server_exist(created_server, 60, 5)
        self.assertEqual('not exist', result_server_exist)

    @unittest2.skip("demonstrating skipping")
    def test_create_vm_in_az31(self):
        ACTIVE_STATUS = 'ACTIVE'
        SERVER_NAME = 'ci-az31-vm-01'
        nics = [{'net-id': self.ci_net01_id}]
        created_server = self.ref_services.nova_create(name=SERVER_NAME,
                         image=self.image_id_emall_backend,
                         flavor=1,
                         availability_zone=self.region_az31,
                         nics=nics)
        status_last_check = self._check_vm_status(created_server, ACTIVE_STATUS, 120, 5)

        self.ref_services.nova_delete(created_server)
        result_server_exist = self._check_server_exist(created_server, 60, 5)
        self.assertEqual('not exist', result_server_exist)

    @unittest2.skip("demonstrating skipping")
    def test_l2_connection_between_az01_az11(self):
        self._test_l2_connection_between_two_az(self.region_az01, self.region_az11, 36, 60, 120)

    @unittest2.skip("demonstrating skipping")
    def test_l2_connection_between_az01_az01(self):
        self._test_l2_connection_between_two_az(self.region_az01, self.region_az01, 36, 36, 120)

    @unittest2.skip("demonstrating skipping")
    def test_l2_connection_between_az01_az31(self):
        self._test_l2_connection_between_two_az(self.region_az01, self.region_az31, 24, 120, 120)

    @unittest2.skip("demonstrating skipping")
    def test_l2_connection_between_az11_az31(self):
        self._test_l2_connection_between_two_az(self.region_az11, self.region_az31, 60, 120, 120)

    def _test_l2_connection_between_two_az(self, az1, az2, check_times_az1, check_times_az2, wait_times_for_ping):
        ACTIVE_STATUS = 'ACTIVE'
        AZ1_SERVER_NAME = '%s-vm-01' % az1
        nics = [{'net-id': self.ci_net01_id}]
        az1_server = self.ref_services.nova_create(name=AZ1_SERVER_NAME,
                         image=self.image_id_emall_backend,
                         flavor=1,
                         availability_zone=az1,
                         nics=nics)
        status_az1_server_last_check = self._check_vm_status(az1_server, ACTIVE_STATUS, check_times_az1, 5)

        AZ2_SERVER_NAME = '%s-vm-01' % az2
        az2_server = self.ref_services.nova_create(name=AZ2_SERVER_NAME,
                         image=self.image_id_emall_backend,
                         flavor=1,
                         availability_zone=az2,
                         nics=nics)

        status_az2_server_last_check = self._check_vm_status(az2_server, ACTIVE_STATUS, check_times_az2, 5)
        az2_server_data = self.ref_services.nova_show(az2_server)
        az2_server_internal_ip = az2_server_data.addresses['ci-net01'][0]['addr']

        if status_az1_server_last_check == ACTIVE_STATUS and status_az2_server_last_check == ACTIVE_STATUS:
            floating_ip_1 = self.ref_services.nova_floating_ip_create(self.name_floating_ip_pool)
            floating_ip_2 = self.ref_services.nova_floating_ip_create(self.name_floating_ip_pool)

            self.ref_services.nova_floating_ip_associate(az1_server.id, floating_ip_1.ip)
            self.ref_services.nova_floating_ip_associate(az2_server.id, floating_ip_2.ip)

            # time.sleep(30)
            # cmd_ping = 'ping -c 4 %s' % az2_server_internal_ip
            # exit_status, stdout, stderr = self.remote_execute(floating_ip_1.ip, cmd_ping)
            ping_result = self._check_internal_panel_connection(floating_ip_1.ip,
                                                                az2_server_internal_ip,
                                                                wait_times_for_ping,
                                                                5)

            self.assertEqual(ping_result, 0)

            self.ref_services.nova_floating_ip_disassociate(az1_server.id, floating_ip_1.ip)
            self.ref_services.nova_floating_ip_delete(floating_ip_1.id)

            self.ref_services.nova_floating_ip_disassociate(az2_server.id, floating_ip_2.ip)
            self.ref_services.nova_floating_ip_delete(floating_ip_2.id)

        try:
            self.ref_services.nova_delete(az1_server)
            self.ref_services.nova_delete(az2_server)
        except Exception, e:
            log.error('Exception when delete server: %s' % traceback)

        check_result = self._check_server_exist(az1_server, 60, 5)
        self.assertEqual('not exist', check_result)

        check_result = self._check_server_exist(az2_server, 60, 5)
        self.assertEqual('not exist', check_result)

    def _check_internal_panel_connection(self, floating_ip, internal_ip_address, times_for_check, interval):
        exit_status = 1

        for i in range(times_for_check):
            cmd_ping = 'ping -c 4 %s' % internal_ip_address
            time.sleep(interval)
            exit_status, stdout, stderr = self.remote_execute(floating_ip, cmd_ping)
            if exit_status == 0:
                break
            else:
                continue

        return exit_status

    def test_migrate_vm_from_az01_to_az31(self):
        pass

    def test_migrate_vm_from_az31_to_az01(self):
        pass

    def test_migrate_vm_from_az01_to_az11(self):
        pass

    def test_migrage_vm_from_az11_to_az01(self):
        pass


suite = unittest2.TestLoader().loadTestsFromTestCase(TestNova)
unittest2.TextTestRunner(verbosity=2).run(suite)