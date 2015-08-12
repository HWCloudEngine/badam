# -*- coding:utf-8 -*-
'''
Created on 2015年8月10日

@author: Administrator
'''

import time
import unittest2
import os
import traceback

from services import RefServices, SSH, LOG_INIT, CommonUtils
import log
from __main__ import SERVER_NAME
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

class Performance_test(unittest2.TestCase):

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
            except Exception as e:
                return 'not exist'
        return 'exist'

    def remote_execute(self, host, cmd):
        ssh = SSH('root', host, password='magento')
        try:
            exit_status, stdout, stderr = ssh.execute(cmd)
            return exit_status, stdout, stderr
        except Exception as e:
            log.error('Exception: %s' % traceback.format_exc())
        finally:
            ssh.close()
            
   
    def _test_batch_create_vm_in_az(self,az,nums):
        server_list=[]
        ACTIVE_STATUS = 'ACTIVE' 
        BASE_SERVER_NAME='ci-' + az +'vm-'
        nics = [{'net-id': self.ci_net01_id}]
        region_list = [self.region_az01,self.region_az11,self.region_az31]
        test_server_name='test_'
        test_server_list =[]
        region_list.remove(az)
        for region in  region_list:
            
            test_server = self.ref_services.nova_create(name=test_server_name + region,
                             image=self.image_id_emall_backend,
                             flavor=1,
                             availability_zone=region,
                             nics=nics)
            status_last_check = self._check_vm_status(test_server, ACTIVE_STATUS, 120, 5)
            test_server_list.append(test_server)
        
        for i in range(nums):
            SERVER_NAME = BASE_SERVER_NAME +i
            created_server = self.ref_services.nova_create(name=SERVER_NAME,
                         image=self.image_id_emall_backend,
                         flavor=1,
                         availability_zone=az,
                         nics=nics)
            server_list.append(created_server)
            
        for server in server_list:
            status_last_check = self._check_vm_status(server, ACTIVE_STATUS, 120, 5)
            for server2 in test_server_list:
                self._test_l2_connection_between_two_server(server, server2)
            
            self.ref_services.nova_delete(server)
            result_server_exist = self._check_server_exist(server, 60, 5)
            self.assertEqual('not exist', result_server_exist) 
        
        for  test_server in  test_server_list:
            self.ref_services.nova_delete(test_server)
            result_server_exist = self._check_server_exist(test_server, 60, 5)
            self.assertEqual('not exist', result_server_exist) 
      
    def test_batch_create_vm_in_az01(self): 
        while True:
            self._test_batch_create_vm_in_az(self.region_az01, 10) 
            time.sleep(600)
        
    
    def test_batch_create_vm_in_az11(self): 
        while True:
            self._test_batch_create_vm_in_az(self.region_az11, 5) 
            time.sleep(600)
        
    def test_batch_create_vm_in_az31(self): 
        while True:
            self._test_batch_create_vm_in_az(self.region_az31, 10) 
            time.sleep(600)

   
   
    def _test_l2_connection_between_two_server(self,az1_server,az2_server):
        az2_server_data = self.ref_services.nova_show(az2_server)
        az2_server_internal_ip = az2_server_data.addresses['ci-net01'][0]['addr']

        
        floating_ip_1 = self.ref_services.nova_floating_ip_create(self.name_floating_ip_pool)
        floating_ip_2 = self.ref_services.nova_floating_ip_create(self.name_floating_ip_pool)

        self.ref_services.nova_floating_ip_associate(az1_server.id, floating_ip_1.ip)
        self.ref_services.nova_floating_ip_associate(az2_server.id, floating_ip_2.ip)

        
        ping_result = self._check_internal_panel_connection(floating_ip_1.ip,
                                                            az2_server_internal_ip,
                                                            120,
                                                            5)

        self.assertEqual(ping_result, 0)

        self.ref_services.nova_floating_ip_disassociate(az1_server.id, floating_ip_1.ip)
        self.ref_services.nova_floating_ip_delete(floating_ip_1.id)

        self.ref_services.nova_floating_ip_disassociate(az2_server.id, floating_ip_2.ip)
        self.ref_services.nova_floating_ip_delete(floating_ip_2.id)
        

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
        except Exception as e:
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
    
    def _test_migrate_vm(self, az1, az2):
        az_servers = []
        for server_name in ["test-vm", "test-migrate-vm"]:
            az_servers += [self.ref_services.nova_create(name=server_name,
                       image=self.image_id_emall_backend,
                       flavor=1,
                       availability_zone=az1,
                       nics=[{'net-id': self.ci_net01_id}])]

            self._check_vm_status(az_servers[-1], 'ACTIVE', 36, 5)
            
        az1_server, az2_server = az_servers
        az2_server_data = self.ref_services.nova_show(az2_server)
        
        # ping these two vm
        az2_server_internal_ip = az2_server_data.addresses['ci-net01'][0]['addr']
        floating_ip_1 = self.ref_services.nova_floating_ip_create(self.name_floating_ip_pool)
        floating_ip_2 = self.ref_services.nova_floating_ip_create(self.name_floating_ip_pool)
        
        self.ref_services.nova_floating_ip_associate(az1_server.id, floating_ip_1.ip)
        self.ref_services.nova_floating_ip_associate(az2_server.id, floating_ip_2.ip)
        
        # time.sleep(30)
        # cmd_ping = 'ping -c 4 %s' % az2_server_internal_ip
        # exit_status, stdout, stderr = self.remote_execute(floating_ip_1.ip, cmd_ping)
        wait_times_for_ping = 120
        ping_result = self._check_internal_panel_connection(floating_ip_1.ip,
                                                            az2_server_internal_ip,
                                                            wait_times_for_ping,
                                                            5)
        
        self.assertEqual(ping_result, 0)
        
        # migrate 
        self.ref_services.nova_migrate(az2_server_data, az2, False)

        time.sleep(5*60)
        
        server_data = self.ref_services.nova_show(az2_server_data)
        self.assertEqual(server_data.display_name, az2_server_data.display_name)
        self.assertEqual(server_data.access_ip_v4, az2_server_data.access_ip_v4)
        self.assertEqual(server_data.availability_zone, az2)
        
        floating_ip_2 = self.ref_services.nova_floating_ip_create(self.name_floating_ip_pool)
        
        self.ref_services.nova_floating_ip_associate(server_data.id, floating_ip_2.ip)
        ping_result = self._check_internal_panel_connection(floating_ip_1.ip,
                                                            server_data.addresses['ci-net01'][0]['addr'],
                                                            wait_times_for_ping,
                                                            5)
        
        self.assertEqual(ping_result, 0)
           
        az_servers[-1] = server_data
        
        for created_server in az_servers:
            self.ref_services.nova_delete(created_server)
    
            result_server_exist = self._check_server_exist(created_server, 60, 5)
            self.assertEqual('not exist', result_server_exist)

        pass

   
        

suite = unittest2.TestLoader().loadTestsFromTestCase(Performance_test)
unittest2.TextTestRunner(verbosity=2).run(suite)