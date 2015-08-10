#!/etc/bin/env python
__author__ = 'nash.xiejun'
import sys
sys.path.append('/usr/bin/install_tool')
import os
import traceback
from oslo.config import cfg
from constants import FileName
import socket
import shutil
import errno

import log
import utils
from utils import CommonCMD, SSHConnection
from services import RefServices, RefCPSService, RefCPSServiceExtent, RefFsUtils, RefFsSystemUtils, CPSServiceBusiness
from constants import CfgFilePath, SysUserInfo, SysPath, ScriptFilePath
from dispatch import DispatchPatchTool

module_logger = log
print_logger = log

CONF = cfg.CONF
global_opts = [
    cfg.StrOpt('file_hosts',
               default='/etc/hosts'),
    cfg.StrOpt('file_hostname',
               default='/etc/hostname'),
    cfg.StrOpt('self_config_file', default= os.path.sep.join([os.path.split(os.path.realpath(__file__))[0],
                                                              FileName.PATCHES_TOOL_CONFIG_FILE])),
]
CONF.register_opts(global_opts)


default_group = cfg.OptGroup(name='DEFAULT',
                               title='default config')
default_opts = [
    cfg.DictOpt('proxy_match_host', default=None),
    cfg.DictOpt('proxy_match_region', default=None),
    cfg.StrOpt('current_node', default='proxy001'),
    cfg.DictOpt('cascaded_add_route', default=None),
    cfg.DictOpt('cascaded_add_table_external_api', default=None),
    cfg.StrOpt('cascading_region', default='cascading.hybrid.huawei.com'),
    cfg.StrOpt('openstack_bak_path', default='/home/openstack_bak')
]

CONF.register_group(default_group)
CONF.register_opts(default_opts, default_group)


env_group = cfg.OptGroup(name='ENV',
                               title='environment for openstack')
env_opts = [
    cfg.StrOpt('OS_AUTH_URL', default="https://identity.cascading.hybrid.huawei.com:443/identity/v2.0"),
    cfg.StrOpt('OS_USERNAME', default="cloud_admin"),
    cfg.StrOpt('OS_TENANT_NAME', default="admin"),
    cfg.StrOpt('NOVA_ENDPOINT_TYPE', default="publicURL"),
    cfg.StrOpt('CINDER_ENDPOINT_TYPE', default="publicURL"),
    cfg.StrOpt('OS_ENDPOINT_TYPE', default="publicURL"),
    cfg.StrOpt('OS_VOLUME_API_VERSION', default="2"),
    cfg.StrOpt('OS_PASSWORD', default=""),
]
CONF.register_group(env_group)
CONF.register_opts(env_opts, env_group)

absolute_config_file = os.path.join(utils.get_patches_tool_path(), FileName.PATCHES_TOOL_CONFIG_FILE)
CONF(['--config-file=%s' % absolute_config_file])


class ConfigCascading(object):

    def __init__(self):
        self.proxy_match_host = CONF.DEFAULT.proxy_match_host
        self.proxy_match_region = CONF.DEFAULT.proxy_match_region
        self.proxies = self.proxy_match_host.keys()
        self.current_proxy = CONF.DEFAULT.current_node

        # cascading.hybrid.huawei.com
        self.cascading_region = RefCPSService.get_local_domain()
        log.info('cascading region is: %s' % self.cascading_region)
        local_dc, local_az = RefFsUtils.get_local_dc_az()
        # cascading.hybrid
        self.cascading_os_region_name = '.'.join([local_az, local_dc])

    def check_service_status(self):
        print('****Start to check service status...')

        cps_service = CPSServiceBusiness()
        for proxy in self.proxies:
            cps_service.check_all_service_template_status(proxy)

        print('****End to check service status.')

    def restart_services(self):
        print('****Start to restart services...')

        cps_service = CPSServiceBusiness()
        for proxy in self.proxies:
            cps_service.stop_all(proxy)

        for proxy in self.proxies:
            cps_service.start_all(proxy)

        print('****Finish to restart services.')

    def add_role_for_proxies(self):
        for proxy_number in self.proxies:
            print('****  Start to add role for Proxy:<<%s>>  ****' % proxy_number)
            log.info('****  Start to add role for Proxy:<<%s>>  ****' % proxy_number)
            role_nova_proxy = self._get_nova_role_name(proxy_number)
            role_neutron_proxy = self._get_neutron_role_name(proxy_number)
            role_cinder_proxy = self._get_cinder_role_name(proxy_number)
            host_proxy_in = self.proxy_match_host[proxy_number]

            self._add_proxy_role(host_proxy_in, role_nova_proxy)
            # self._check_service_proxy_status('nova', self._get_nova_template_name(proxy_number), 'fault')
            self._add_proxy_role(host_proxy_in, role_neutron_proxy)
            # self._check_service_proxy_status('neutron', self._get_neutron_l2_template_name(proxy_number), 'fault')
            self._add_proxy_role(host_proxy_in, role_cinder_proxy)
            # self._check_service_proxy_status('cinder', self._get_cinder_template_name(proxy_number), 'fault')

            log.info('****  End to add role for Proxy:<<%s>>  ****' % proxy_number)
            print('****  End to add role for Proxy:<<%s>>  ****' % proxy_number)

    def _add_proxy_role(self, host, role_name):
        """
        Commands used to add role for host:
        cps role-host-add --host  **  nova-proxy001
        cps commit

        Commands used to check if add successful:
        cps template-instance-list --service nova nova-proxy001
        If get proxy info, then it is add successfully, no mater the status of proxy is fault.
        :param role_name:
        :return:
        """
        log.info('Start to add proxy role in host: %s, for role: %s' % (host, role_name))
        add_result = RefCPSService.role_host_add(role_name, [host])
        RefCPSService.cps_commit()
        log.info('Finish to add proxy role in host: %s, for role: %s' % (host, role_name))

    def _get_nova_role_name(self, proxy_number):
        service_nova = 'compute'
        return '-'.join([service_nova, proxy_number])

    def _get_neutron_role_name(self, proxy_number):
        return '-'.join(['network', proxy_number])

    def _get_cinder_role_name(self, proxy_number):
        return '-'.join(['blockstorage', proxy_number])

    def _get_nova_template_name(self, proxy_name):
        return '-'.join(['nova', proxy_name])

    def _get_neutron_l2_template_name(self, proxy_name):
        return '-'.join(['neutron', 'l2', proxy_name])

    def _get_neutron_l3_template_name(self, proxy_name):
        return '-'.join(['neutron', 'l3', proxy_name])

    def _get_cinder_template_name(self, proxy_name):
        return '-'.join(['cinder', proxy_name])

    def config_nova_scheduler(self):
        updated_params = {'scheduler_default_filters':'AvailabilityZoneFilter'
        }
        service = 'nova'
        template = 'nova-scheduler'
        self._update_template_params_for_proxy(service, template, updated_params)
        self._commit_config()

    def config_neutron_server(self):
        updated_params = {'lbaas_vip_create_port':'True'
        }
        service = 'neutron'
        template = 'neutron-server'
        self._update_template_params_for_proxy(service, template, updated_params)
        self._commit_config()

    def config_proxy_to_connect_with_cascaded(self):
        for proxy in self.proxies:
            log.info('Start to config cascading connection for proxy: %s' % proxy)
            print('Start to config cascading connection for proxy: %s' % proxy)
            self._config_service_for_nova_proxy(proxy)
            self._config_for_neutron_l2_proxy(proxy)
            self._config_for_neutron_l3_proxy(proxy)
            self._config_cinder_proxy(proxy)
            print('Finish to config cascading connection for proxy: %s' % proxy)
            log.info('Finish to config cascading connection for proxy: %s' % proxy)

    def config_big_l2_layer_in_proxy_node(self):
        self._config_big_l2_layer_in_proxy(self.current_proxy)
        host_list = RefCPSService.host_list()
        if host_list is not None:
            self._replace_neutron_l2_proxy_json(host_list)

    def config_big_l2_layer_in_cascaded_node(self):
        self._config_big_l2_layer_in_cascaded_node()
        self._restart_neutron_openvswitch_agent()

    def create_aggregate_in_cascading_node(self):
        """
        nova aggregate-create az31.singapore--aws az31.singapore--aws
        nova aggregate-add-host az31.singapore--aws az31.singapore--aws
        Check status of proxy in az31:
        nova service-list | grep az31
        :return:
        """
        pass

    def create_aggregate_in_cascaded_node(self):
        """
        nova aggregate-create az31.singapore--aws az31.singapore--aws
        nova host-list
        nova aggregate-add-host az31.singapore--aws 42114FD9-D446-9248-3A05-23CF474E3C68

        :return:
        """
        ref_service = RefServices()
        host_id = socket.gethostname()
        region = RefCPSService.get_local_domain()
        os_region_name = '.'.join([RefFsSystemUtils.get_az_by_domain(region), RefFsSystemUtils.get_dc_by_domain(region)])
        if not ref_service.nova_aggregate_exist(os_region_name, os_region_name):
            create_result = ref_service.nova_aggregate_create(os_region_name, os_region_name)
            if create_result is not None:
                ref_service.nova_aggregate_add_host(create_result, host_id)
        print('Success to create region<%s> for host<%s>' % (os_region_name, host_id))

    def create_route_table_in_cascaded_node(self):
        """
        ip route add 172.29.0.0/24 via 162.3.120.247
        ip route add 172.29.1.0/24 via 172.28.48.1
        ip route add table external_api 172.29.0.0/24 via 162.3.120.247
        :return:
        """
        cascaded_add_route = CONF.DEFAULT.cascaded_add_route
        cascaded_add_router_table_external_api = CONF.DEFAULT.cascaded_add_table_external_api
        for net, ip in cascaded_add_route.items():
            CommonCMD.create_route(net, ip)

        for net, ip in cascaded_add_router_table_external_api.items():
            table = 'external_api'
            CommonCMD.create_route_for_table(table, net, ip)

    def _config_big_l2_layer_in_proxy(self, proxy_name):
        print('Start to config big l2 layer.')
        self._update_neutron_machanism_drivers_for_cascading()
        for proxy in self.proxies:
            self._enable_for_l2_remote_port(proxy)
        self._commit_config()
        print('End to config big l2 layer.')

    def _update_neutron_machanism_drivers_for_cascading(self):
        updated_params = {
            'mechanism_drivers': 'openvswitch,l2populationcascading,basecascading,evs,sriovnicswitch,netmapnicswitch'
        }
        service = 'neutron'
        template = 'neutron-server'
        self._update_template_params_for_proxy(service, template,updated_params)

    def _enable_for_l2_remote_port(self, proxy_name):
        service='neutron'
        # e.g. 'neutron-l2-proxy003'
        template = '-'.join(['neutron-l2', proxy_name])
        updated_params = {
            'remote_port_enabled': 'True'
        }
        self._update_template_params_for_proxy(service, template,updated_params)

    def _config_big_l2_layer_in_cascaded_node(self):
        updated_params = {
            'mechanism_drivers': 'openvswitch,l2populationcascaded,evs,sriovnicswitch,netmapnicswitch'
        }
        service = 'neutron'
        template = 'neutron-server'
        self._update_template_params_for_proxy(service, template,updated_params)

        self._commit_config()

    def _restart_neutron_openvswitch_agent(self):
        """
        cps host-template-instance-operate --action STOP --service neutron neutron-openvswitch-agent
        cps host-template-instance-operate --action START --service neutron neutron-openvswitch-agent
        :return:
        """
        self._stop_neutron_openvswitch_agent()
        self._start_neutron_openvswitch_agent()

    def _stop_neutron_openvswitch_agent(self):
        service = 'neutron'
        template = 'neutron-openvswitch-agent'
        action_stop = 'STOP'

        RefCPSServiceExtent.host_template_instance_operate(service, template, action_stop)

    def _start_neutron_openvswitch_agent(self):
        service = 'neutron'
        template = 'neutron-openvswitch-agent'
        action_stop = 'START'

        RefCPSServiceExtent.host_template_instance_operate(service, template, action_stop)

    def _replace_neutron_l2_proxy_json(self, host_info):
        """
        TODO: to get host ip of proxies, and scp config file of json to these proxies.
        :return:
        """
        log.info('Start to replace neutron l2 proxy json in proxy nodes..')
        print('Start to replace neutron l2 proxy json..')
        for proxy in self.proxies:
            neutron_network_role = self._get_neutron_role_name(proxy)
            for host in host_info['hosts']:
                roles_list = host['roles']
                local_path_of_neutron_l2_proxy = os.path.join(utils.get_patches_tool_path(), CfgFilePath.NEUTRON_L2_PROXY_PATH_TEMPLATE)
                if neutron_network_role in roles_list:
                    proxy_host_ip = host['manageip']
                    log.info('Start remote copy neutron l2 proxy json to host: %s' % proxy_host_ip)
                    try:
                        utils.remote_open_root_permit_for_host(proxy_host_ip)
                        ssh = SSHConnection(proxy_host_ip, SysUserInfo.ROOT , SysUserInfo.ROOT_PWD)
                        ssh.put(local_path_of_neutron_l2_proxy, CfgFilePath.NEUTRON_L2_PROXY_PATH)
                        ssh.close()
                    except Exception, e:
                        log.error('Exception when remote copy neutron l2 proxy json to host: %s' % proxy_host_ip)
                        log.error('Exception: %s' % traceback.format_exc())

                    log.info('Finish remote copy neutron l2 proxy json to host: %s' % proxy_host_ip)
        print('Finish to replace neutron l2 proxy json..')
        log.info('Finish to replace neutron l2 proxy json  in proxy nodes..')

    def _get_proxy_region_and_host_region_name(self, proxy_matched_region):
        return '.'.join([RefFsSystemUtils.get_az_by_domain(proxy_matched_region),
                                                   RefFsSystemUtils.get_dc_by_domain(proxy_matched_region)])

    def _config_service_for_nova_proxy(self, proxy_name):
        proxy_matched_region = self.proxy_match_region.get(proxy_name)
        proxy_matched_host_region_name = self._get_proxy_region_and_host_region_name(proxy_matched_region)

        updated_params = {'cascaded_cinder_url': 'https://volume.%s:443/v2' % proxy_matched_region,
                     'cascaded_neutron_url': 'https://network.%s:443' % proxy_matched_region,
                     'cascaded_nova_url': 'https://compute.%s:443/v2' % proxy_matched_region,
                     'cascaded_glance_url': 'https://image.%s' % self.cascading_region,
                     'glance_host': 'https://image.%s' % self.cascading_region,
                     'cascading_nova_url': 'https://compute.%s:443/v2' % self.cascading_region,
                     'cinder_endpoint_template': "".join(['https://volume.%s:443'% self.cascading_region, '/v2/%(project_id)s']),
                     'neutron_admin_auth_url': 'https://identity.%s:443/identity/v2.0' % self.cascading_region,
                     'keystone_auth_url':'https://identity.%s:443/identity/v2.0' % self.cascading_region,
                     'os_region_name':self.cascading_os_region_name,
                     'host': proxy_matched_host_region_name,
                     'proxy_region_name': proxy_matched_host_region_name,
                     'default_availability_zone': proxy_matched_host_region_name,
                     'default_schedule_zone': proxy_matched_host_region_name
        }
        service = 'nova'
        template = '-'.join([service, proxy_name])
        self._update_template_params_for_proxy('nova', template, updated_params)
        self._commit_config()
        # self._check_service_proxy_status(service, template, 'active')

    def _update_template_params_for_proxy(self, service, template_name, dict_params):
        result = RefCPSService.update_template_params(service, template_name, dict_params)

        return result

    def _commit_config(self):
        RefCPSService.cps_commit()

    def _config_for_neutron_l2_proxy(self, proxy_name):
        neutron_proxy_type = 'l2'
        self._config_for_neutron_proxy(proxy_name, neutron_proxy_type)

    def _config_for_neutron_l3_proxy(self, proxy_name):
        neutron_proxy_type = 'l3'
        self._config_for_neutron_proxy(proxy_name, neutron_proxy_type)

    def _config_for_neutron_proxy(self, proxy_name, neutron_proxy_type):
        """

        :param proxy_name: str, 'proxy001', 'proxy002', ...
        :param neutron_proxy_type: str, 'l2' or 'l3'
        :return:
        """

        proxy_matched_region = self.proxy_match_region.get(proxy_name)
        proxy_matched_host_region_name = self._get_proxy_region_and_host_region_name(proxy_matched_region)
        updated_params = {
            'host':proxy_matched_host_region_name,
            'neutron_region_name': proxy_matched_host_region_name,
            'region_name': self.cascading_os_region_name,
            'neutron_admin_auth_url': 'https://identity.%s:443/identity-admin/v2.0' % self.cascading_region
        }
        service = 'neutron'
        # e.g. 'neutron-l2-proxy001'
        template = '-'.join([service, neutron_proxy_type, proxy_name])
        self._update_template_params_for_proxy(service, template, updated_params)
        self._commit_config()
        # self._check_service_proxy_status(service, template, 'active')

    def _config_cinder_proxy(self, proxy_name):
        try:
            service = 'cinder'
            template = '-'.join([service, proxy_name])
            proxy_matched_region = self.proxy_match_region.get(proxy_name)
            proxy_matched_host_region_name = self._get_proxy_region_and_host_region_name(proxy_matched_region)
            cinder_tenant_id = RefServices().get_tenant_id_for_admin()
            log.info('cinder_tenant_id: %s' % cinder_tenant_id)

            updated_params = {'cascaded_cinder_url': ''.join(['https://volume.%s:443'%proxy_matched_region,'/v2/%(project_id)s']),
                         'cascaded_neutron_url': 'https://network.%s:443' % proxy_matched_region,
                         'cascaded_region_name': proxy_matched_host_region_name,
                         'cinder_tenant_id': cinder_tenant_id,
                         'host': proxy_matched_host_region_name,
                         'keystone_auth_url': 'https://identity.%s:443/identity/v2.0' % self.cascading_region,
                         'storage_availability_zone': proxy_matched_host_region_name
            }
            self._update_template_params_for_proxy(service, template, updated_params)
            self._commit_config()
            #self._check_service_proxy_status(service, template, 'active')
            template_cinder_api = 'cinder-api'
            template_cinder_scheduler = 'cinder-scheduler'
            template_cinder_cinder_volume = 'cinder-scheduler'
            #self._check_service_proxy_status(service, template_cinder_api, 'active')
            #self._check_service_proxy_status(service, template_cinder_scheduler, 'active')
            #self._check_service_proxy_status(service, template_cinder_cinder_volume, 'active')
        except:
            print 'Exception when cinder proxy config. e: %s' % traceback.format_exc()
            log.error('e: %s' % traceback.format_exc())

    def _check_service_proxy_status(self, service, template, aim_status):
        template_instance_info = RefCPSServiceExtent.list_template_instance(service, template)
        print template_instance_info
        if template_instance_info is None:
            print('Template instance info of Service<%s> Template<%s> is None.' % (service, template))
            return False
        status = template_instance_info.get('instances')[0].get('hastatus')
        if status == aim_status:
            print_logger.info('SUCCESS to update template for service<%s>, template<%s>' % (service, template))
            return True
        else:
            print_logger.error('FAILED to update template for service<%s>, template<%s>' % (service, template))
            return False

    def add_role_for_cascading_node(self):
        start_info = 'Start to add role for cascading node. Include: nova-api, nova-scheduler, neutron-server, loadbalancer'
        print(start_info)
        log.info(start_info)
        host_name_of_cascading_node = socket.gethostname()
        RefCPSService.role_host_add('nova-api', [host_name_of_cascading_node])
        RefCPSService.role_host_add('nova-scheduler', [host_name_of_cascading_node])
        RefCPSService.role_host_add('neutron-server', [host_name_of_cascading_node])
        RefCPSService.role_host_add('loadbalancer', [host_name_of_cascading_node])
        RefCPSService.cps_commit()
        finish_info = 'Finish to add role for cascading node. Include: nova-api, nova-scheduler, neutron-server, loadbalancer'
        print(finish_info)
        log.info(finish_info)

    def config_cascading_nodes(self):
        self.add_role_for_cascading_node()
        self.config_nova_scheduler()
        self.config_neutron_server()
        self.add_role_for_proxies()
        self.config_proxy_to_connect_with_cascaded()
        self.config_big_l2_layer_in_proxy_node()

    def config_cascaded_nodes(self):
        print('****Start to config big l2 layer...')
        config_cascading.config_big_l2_layer_in_cascaded_node()
        print('****End to config big l2 layer...')

        print('****Start to create aggregate...')
        config_cascading.create_aggregate_in_cascaded_node()
        print('****End to create aggregate...')

        print('****Start to create route table...')
        config_cascading.create_route_table_in_cascaded_node()
        print('****End to create route table...')


class BackupRecoverFS(object):
    def __init__(self):
        self._init_paths_need_to_backup()
        self.path_fs_code_backup = SysPath.PATH_FS_CODE_BACKUP

    def _init_paths_need_to_backup(self):
        nova = 'nova'
        self.openstack_installed_path = utils.get_openstack_installed_path()
        nova_path = os.path.join(self.openstack_installed_path, nova)
        neutron = 'neutron'
        neutron_path = os.path.join(self.openstack_installed_path, neutron)
        cinder = 'cinder'
        cinder_path = os.path.join(self.openstack_installed_path, cinder)

        self.paths_need_to_backup = [nova_path, neutron_path, cinder_path]
        log.info('paths_need_to_backup: %s' % str(self.paths_need_to_backup))

    def back_fs_code(self):
        log.info('Start to backup fs code.')
        if os.path.isdir(self.path_fs_code_backup):
            shutil.rmtree(self.path_fs_code_backup)

        for source_path in self.paths_need_to_backup:
            try:
                dist_path = os.path.join(self.path_fs_code_backup, os.path.basename(source_path))
                if os.path.isdir(dist_path):
                    #clear backup code before.
                    shutil.rmtree(dist_path)
                    log.info('remove old backup code.')

                self.copy_anything(source_path, dist_path)
            except Exception, e:
                log.error('Exception occur when backup service<%s>' % os.path.basename(source_path))
                log.error('Exception: %s' % traceback.format_exc())
            log.info('Finish to backup for code<%s>' % os.path.basename(source_path))

        log.info('Finish to backup fs code.')

    def recover_fs_code(self):
        log.info('Start to recover fs code.')
        # services_dirs, e.g. ['nova', 'cinder', 'neutron']
        services_dirs = os.listdir(self.path_fs_code_backup)
        for service_dir in services_dirs:

            path_backup_service_code = os.path.join(self.path_fs_code_backup, service_dir)
            if os.path.isdir(path_backup_service_code):
                # remove openstack service code in sites-package.
                service_dir_to_be_remove = os.path.join(self.openstack_installed_path, service_dir)
                if os.path.isdir(service_dir_to_be_remove):
                    shutil.rmtree(service_dir_to_be_remove)
                    log.info('remove code from site-package of service<%s>' % service_dir)

                dest_path = os.path.join(self.openstack_installed_path, service_dir)
                # copy backup files of openstack service to openstack installed path(/usr/lib64/python2.6/site-package/).
                self.copy_anything(path_backup_service_code, dest_path)
                log.info('Finish to recover code of service<%s>' % service_dir)
            else:
                log.error('No backup code for service:<%s> in path: %s' % (service_dir, path_backup_service_code))

        log.info('Finish to recover fs code')

    def copy_anything(self, src, dst):
        try:
            shutil.copytree(src, dst)
        except OSError as exc:
            if exc.errno == errno.ENOTDIR:
                shutil.copy(src, dst)
            else:
                raise

def get_all_hosts():
    cps_business = CPSServiceBusiness()
    openstack_az_hosts = cps_business.get_openstack_hosts()
    aws_az_hosts = cps_business.get_aws_node_hosts()
    vcloud_az_hosts = cps_business.get_vcloud_node_hosts()
    all_proxy_host = cps_business.get_all_proxy_nodes(proxy_match_region=CONF.DEFAULT.proxy_match_region)
    return openstack_az_hosts + aws_az_hosts + vcloud_az_hosts + all_proxy_host

def get_all_cascaded_hosts():
    cps_business = CPSServiceBusiness()
    openstack_az_hosts = cps_business.get_openstack_hosts()
    aws_az_hosts = cps_business.get_aws_node_hosts()
    vcloud_az_hosts = cps_business.get_vcloud_node_hosts()
    return openstack_az_hosts + aws_az_hosts + vcloud_az_hosts

def get_all_proxy_hosts():
    cps_business = CPSServiceBusiness()
    all_proxy_hosts = cps_business.get_all_proxy_nodes(proxy_match_region=CONF.DEFAULT.proxy_match_region)
    return all_proxy_hosts

def get_os_region_name():
    cps_business = CPSServiceBusiness()
    return cps_business.get_os_region_name()

def export_region():
    os_region_name = get_os_region_name()
    os.environ['OS_REGION_NAME'] = os_region_name

def export_env():
    os.environ['OS_AUTH_URL'] = CONF.ENV.OS_AUTH_URL
    os.environ['OS_USERNAME'] = CONF.ENV.OS_USERNAME
    os.environ['OS_TENANT_NAME'] = CONF.ENV.OS_TENANT_NAME
    os.environ['NOVA_ENDPOINT_TYPE'] = CONF.ENV.NOVA_ENDPOINT_TYPE
    os.environ['CINDER_ENDPOINT_TYPE'] = CONF.ENV.CINDER_ENDPOINT_TYPE
    os.environ['OS_ENDPOINT_TYPE'] = CONF.ENV.OS_ENDPOINT_TYPE
    os.environ['OS_VOLUME_API_VERSION'] = CONF.ENV.OS_VOLUME_API_VERSION
    os.environ['OS_PASSWORD'] = CONF.ENV.OS_PASSWORD
export_env()

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print('Please select mode, options is: 1.prepare; 2. cascading; 3. check; 4. restart; 5.remote-backup; 6.remote-recover')
        print('Option <prepare> is use to copy patches_tool to proxy nodes and az nodes.')
        print('Option <cascading> is use to config cascading node and proxy node. Only need to execute once in cascading node.')
        print('Option <check> is use to check status of services in cascading and proxy node.')
        print('Option <restart> is use to restart services in cascading and proxy node.')
        print('Option <remote-backup> is use to backup fs code(nova, cinder, neutron) in /home/fsp/fs_code_backup dir.')
        print('Option <remote-recover> is use to ')
        exit(0)
    print('Start to config cascading....')
    log.init('patches_tool_config')
    log.info('Start to config cascading....')
    mode = sys.argv[1]
    export_region()
    config_cascading = ConfigCascading()
    dispatch_patch_tool = DispatchPatchTool(proxy_match_region=CONF.DEFAULT.proxy_match_region)

    #first to dispatch patch_tool to all cascaded node.
    if mode == 'prepare':
        all_cascaded_hosts = get_all_cascaded_hosts()
        all_proxy_hosts = get_all_proxy_hosts()
        utils.remote_open_root_permit_for_hosts(all_cascaded_hosts + all_proxy_hosts)
        utils.add_auto_route_for_fs(all_cascaded_hosts + all_proxy_hosts)
        dispatch_patch_tool.dispatch_patches_tool_to_remote_nodes()

    #Second to config cascading node to add proxy roles and config proxy nodes connect with cascaded nodes.
    elif mode == 'cascading':
        config_cascading.config_cascading_nodes()

        #Thrid to Config cascaded node to connect with cascading node.
        dispatch_patch_tool.remote_config_cascaded_for_all_type_node()

    elif mode == 'remote-backup':
        executed_cmd = 'python %s %s' % (ScriptFilePath.PATCH_REMOTE_HYBRID_CONFIG_PY, 'local-backup')
        dispatch_patch_tool.dispatch_cmd_to_all_proxy_nodes(executed_cmd)
        dispatch_patch_tool.dispatch_cmd_to_all_az_nodes(executed_cmd)

    elif mode == 'remote-recover':
        executed_cmd = 'python %s %s' % (ScriptFilePath.PATCH_REMOTE_HYBRID_CONFIG_PY, 'local-recover')
        dispatch_patch_tool.dispatch_cmd_to_all_proxy_nodes(executed_cmd)
        dispatch_patch_tool.dispatch_cmd_to_all_az_nodes(executed_cmd)

    #this mode cascaded is use to be called in cascaded node remotely in cascading node.
    elif mode == 'cascaded':
        config_cascading.config_cascaded_nodes()
    elif mode == 'check':
        config_cascading.check_service_status()
    elif mode == 'restart':
        config_cascading.restart_services()

    elif mode == 'local-backup':
        backup_recover_service = BackupRecoverFS()
        backup_recover_service.back_fs_code()

    elif mode == 'local-recover':
        backup_recover_service = BackupRecoverFS()
        backup_recover_service.recover_fs_code()

    print('End to config')
    log.info('End to config')
