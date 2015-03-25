__author__ = 'nash.xiejun'

import logging
import traceback
import os

from oslo.config import cfg

from common import config, engineering_logging
from common.engineering_logging import log_for_func_of_class
import utils
from utils import AllInOneUsedCMD
from common.config import ConfigCommon

from services import RefServices
from common.econstants import ConfigReplacement

logger_name = __name__
logger = logging.getLogger(__name__)

CONF = cfg.CONF

class ValidateBase(object):
    @log_for_func_of_class(logger_name)
    def validate(self):
        return True

class ConfiguratorBase(object):
    @log_for_func_of_class(logger_name)
    def config(self):
        return True

class InstallerBase(object):
    @log_for_func_of_class(logger_name)
    def install(self):
        return True

class CheckBase(object):
    @log_for_func_of_class(logger_name)
    def check(self):
        return True

class EnginneringFactory(object):

    def __init__(self, factory_name, validator=ValidateBase(), installer=InstallerBase(), configurator=ConfiguratorBase(), checker=CheckBase()):
        self.factory_name = factory_name
        self.validator = validator
        self.installer = installer
        self.configurator = configurator
        self.checker = checker

    def instance(self):
        return self

    def execute(self):
        logger.info('Start to execute for %s' % self.factory_name)

        execute_result = True

        validate_result = self.validator.validate()

        install_result = self.installer.install()

        config_result = self.configurator.config()

        check_result = self.checker.check()

        logger.info('End to execute for %s, result is %s' , self.factory_name, execute_result)

class HostnameConfigurator(ConfiguratorBase):

    def config(self):
        try:
            self._config_etc_hostname()
            self._config_etc_hosts()
            AllInOneUsedCMD.reboot()
        except:
            logger.error('Exception occur when config hostname. EXCEPTION: %s' % traceback.format_exc())

    def _config_etc_hostname(self):
        logger.info('Start to config hostname file')
        with open(config.CONF.file_hostname, 'w') as hostname_file:
            hostname_file.truncate()
            hostname_file.write(config.CONF.sysconfig.hostname)
        logger.info('Success to config hostname file, /etc/hostname')

    def _config_etc_hosts(self):
        logger.info('Start to config hosts file')
        modified_contents = ''
        with open(config.CONF.file_hosts, 'r') as hosts_file:
            for line in hosts_file:
                if modified_contents == '':
                    modified_contents = line.replace('openstack', config.CONF.sysconfig.hostname)
                else:
                    modified_contents = ''.join([modified_contents, line.replace('openstack',
                                                                                 config.CONF.sysconfig.hostname)])

        with open(config.CONF.file_hosts, 'w') as hosts_file:
            hosts_file.truncate()
            hosts_file.write(modified_contents)

        logger.info('Config hosts file success, /etc/hosts')

class AllInOneConfigurator(ConfiguratorBase):

    @log_for_func_of_class(logger_name)
    def config(self):
        try:
            # AllInOneUsedCMD.rabbitmq_changed_pwd()
            self._config_rc_local()
            self._config_nova_conf()
            self._config_neutron_conf()
            self._copy_self_define_ml2()
            self._config_ml2_ini()
            self._config_sysctl()
            self._config_l3_agent()
            self._config_dhcp_agent()
            self._config_metadata_agent()
        except:
            logger.error('Exception occur when All-In-One Config. EXCEPTION: %s' % traceback.format_exc())

    @log_for_func_of_class(logger_name)
    def _config_rc_local(self):
        result = False
        try:
            contents = ['service nova-cert restart\n',
                        'service nova-scheduler restart\n',
                        'ifconfig br-ex:0 %s netmask 255.255.255.0\n' % config.CONF.sysconfig.ml2_local_ip,
                        'exit 0']

            with open(config.CONF.rc_local_file, 'w') as rc_local_file:
                rc_local_file.truncate()
                rc_local_file.writelines(contents)
                result = True
        except:
            logger.error('Exception occur when config rc.local. EXCEPTION: %s' % traceback.format_exc())
        return result

    @log_for_func_of_class(logger_name)
    def _config_nova_conf(self):
        result = False
        try:
            vncserver_listen = '0.0.0.0'
            path_nova_conf_file = config.CONF.path_nova_conf
            section_default = config.CONF.section_default

            config_common = ConfigCommon(path_nova_conf_file)
            config_common.set_option(section_default, 'vncserver_listen', vncserver_listen)
            config_common.set_option(section_default, 'service_metadata_proxy', 'False')
            config_common.set_option(section_default, 'metadata_proxy_shared_secret', 'openstack')
            config_common.write_commit()
            result = True
        except:
            logger.error('Exception occur when config nova.conf. EXCEPTION: %s' % traceback.format_exc())

        return result

    @log_for_func_of_class(logger_name)
    def _config_neutron_conf(self):
        result = False
        path_neutron_conf = config.CONF.path_neutron_conf
        try:
            self._config_tenant_id_in_neutron_conf(path_neutron_conf)
            result = True
        except:
            logger.error('Exception occur when config neutron conf, EXCEPTION: %s' % traceback.format_exc())

        return result

    def _config_tenant_id_in_neutron_conf(self, path_neutron_conf):
        option_nova_admin_tenant_id = 'nova_admin_tenant_id'
        # get tenant id
        value_nova_admin_tenant_id = RefServices().get_tenant_id_for_service()
        config_common = ConfigCommon(path_neutron_conf)
        config_common.set_option(config.CONF.section_default, option_nova_admin_tenant_id, value_nova_admin_tenant_id)
        config_common.write_commit()

    @log_for_func_of_class
    def _copy_self_define_ml2(self):
        result = False
        try:
            self_define_ml2_file = os.path.split(os.path.realpath(__file__))[0] +'/config/ml2_conf.ini'
            destiny = config.CONF.path_ml2_ini
            result = AllInOneUsedCMD.cp_to(self_define_ml2_file, str(destiny))
        except:
            err_info = 'Exception occur when copy self define ml2 file. Exception: %s' % traceback.format_exc()
            print err_info
            logger.error(err_info)
        return result

    @log_for_func_of_class(logger_name)
    def _config_ml2_ini(self):
        result = False
        try:
            ml2_section_ovf = 'ovf'
            option_local_ip = 'local_ip'
            config_common = ConfigCommon(config.CONF.path_ml2_ini)
            config_common.set_option(ml2_section_ovf, option_local_ip, config.CONF.sysconfig.ml2_local_ip)
            config_common.write_commit()
            result = True
        except:
            err_info = 'Exception occur when config ml2_conf.ini. Exception: %s' % traceback.format_exc()
            print err_info
            logger.error(err_info)
        return result

    @log_for_func_of_class(logger_name)
    def _config_sysctl(self):
        result = False
        try:
            option_all_rp_filter = 'net.ipv4.conf.all.rp_filter=0'
            option_default_rp_filter = 'net.ipv4.conf.default.rp_filter=0'
            contents = [option_all_rp_filter,
                        option_default_rp_filter]

            with open(config.CONF.path_sys_ctl, 'w') as sysctl_file:
                sysctl_file.writelines(contents)
            result = True
        except:
            err_info = 'Exception occur when config sysctl.conf. Exception: %s' % traceback.format_exc()
            logger.error(err_info)
            print(err_info)

        return result

    @log_for_func_of_class(logger_name)
    def _config_l3_agent(self):
        """
        write external_network_bridge=br-ex to /etc/neutron/l3_agent.ini.

        [DEFAULT]
        external_network_bridge = br-ex
        :return: boolean
        """
        result = False

        try:
            option_external_network_bridge = 'external_network_bridge'
            value_external_network_bridge = 'br-ex'
            config_common = ConfigCommon(config.CONF.path_l3_agent)
            config_common.set_option(config.CONF.section_default, option_external_network_bridge, value_external_network_bridge)
            result = True
        except:
            err_info = 'Exception occur when config l3_agent.ini. Exception: %s' % traceback.format_exc()
            logger.error(err_info)
            print(err_info)

        return result

    @log_for_func_of_class(logger_name)
    def _config_dhcp_agent(self):
        """
        config /etc/neutron/dhcp_agent.ini,
        set following:
        #vi /etc/neutron/dhcp_agent.ini
        [DEFAULT]
        dhcp_driver = neutron.agent.linux.dhcp.Dnsmasq
        use_namespaces = False

        :return:
        """
        result = False
        try:
            option_dhcp_driver = 'dhcp_driver'
            value_dhcp_driver = 'neutron.agent.linux.dhcp.Dnsmasq'
            option_use_namespaces = 'use_namespace'
            value_use_namespaces = 'False'
            common_config = ConfigCommon(config.CONF.path_dhcp_agent_ini)
            common_config.set_option(config.CONF.section_default, option_dhcp_driver, value_dhcp_driver)
            common_config.set_option(config.CONF.section_default, option_use_namespaces, value_use_namespaces)
            common_config.write_commit()
            result = True
        except:
            err_info = 'Exception occur when config dhcp_agent.ini. Exception: %s' % traceback.format_exc()
            logger.error(err_info)
            print(err_info)

        return result

    @log_for_func_of_class(logger_name)
    def _config_metadata_agent(self):
        """
        # vi /etc/neutron/metadata_agent.ini
        [DEFAULT]
        nova_metadata_ip = 162.3.110.71
        metadata_proxy_shared_secret = openstack

        :return:
        """
        result = True
        try:
            option_nova_metadata_ip = 'nova_metadata_ip'
            value_nova_metadata_ip = config.CONF.sysconfig.local_host_ip
            option_metadata_proxy_shared_secret = 'metadata_proxy_shared_secret'
            value_metadata_proxy_shared_secret = 'openstack'
            config_common = ConfigCommon(config.CONF.path_metadata_agent_ini)
            config_common.set_option(config.CONF.section_default,
                                     option_nova_metadata_ip,
                                     value_nova_metadata_ip)
            config_common.set_option(config.CONF.section_default,
                                     option_metadata_proxy_shared_secret,
                                     value_metadata_proxy_shared_secret)
            config_common.write_commit()

            result = True
        except:
            err_info = 'Exception occur when config dhcp_agent.ini. Exception: %s' % traceback.format_exc()
            logger.error(err_info)
            print(err_info)

        return result

class PatchInstaller(InstallerBase):

    def __init__(self, patch_path, openstack_install_path, filters):
        """

        :param patch_path:
            for example: /root/tricircle-master/novaproxy/
                        /root/tricircle-master/juno-patches/nova_scheduling_patch/
        :param openstack_install_path:
            for example: '/usr/lib/python2.7/dist-packages/'
        :param filters:
            for example: ['.py']
        :return:
        """
        # patch_path is /root/tricircle-master/juno-patches/nova/nova_scheduling_patch/
        self.patch_path = patch_path
        # install_path is  openstack installed path'/usr/lib/python2.7/dist-packages/'
        self.openstack_install_path = openstack_install_path
        # filter is valid suffix of files, for example: ['.py']
        self.filters = filters
        self.bak_openstack_path = config.CONF.openstack_bak_path

    def get_patch_files(self, patch_path, filters):
        """

        :param patch_path: path of patch's source code
        :param filters: [] array of valid suffix of file. for example: ['.py']
        :return: (absolute path, relative path)
            for example:
            [(/root/tricircle-master/novaproxy/nova/compute/clients.py,
            nova/compute/clients.py), ..]
        """
        return utils.get_files(patch_path, filters)

    def bak_patched_files(self, patch_file, relative_path):
        """

        :param patch_file:  one file of patch's source code files,
            for example: /root/tricircle-master/juno-patches/nova/nova_scheduling_patch/nova/conductor/manager.py
        :param relative_path:
            for example: nova/conductor/manager.py
        :return:
        """
        logger.info('Start bak_patched_files, ')
        # relative_path is relative to this path(self.patch_path),
        # for example: if self.patch_path = "/root/tricircle-master/juno-patches/nova/nova_scheduling_patch/"
        # then relative_path of manager.py is "/nova/nova_scheduling_patch/nova/conductor/manager.py"
        relative_path = patch_file.split(self.patch_path)[0]

        installed_path = os.path.sep.join([self.openstack_install_path, relative_path])
        if os.path.isdir(self.bak_openstack_path):
            AllInOneUsedCMD.cp_to(installed_path, self.bak_openstack_path)
        else:
            err_info = 'Bak path of openstack <%s> is not exist' % self.bak_openstack_path
            logger.error(err_info)
            raise ValueError(err_info)

    @log_for_func_of_class(logger_name)
    def install(self):
        try:
            patch_files = self.get_patch_files(self.patch_path, self.filters)
            if not patch_files:
                utils.print_log('No files in %s' % self.patch_path, logging.ERROR)

            for absolute_path, relative_path in patch_files:

                # installed_path is full install path,
                # for example: /usr/lib/python2.7/dist-packages/nova/conductor/manager.py
                install_path = os.path.join(self.openstack_install_path, relative_path)
                self.bak_patched_files(absolute_path, relative_path)
                AllInOneUsedCMD.cp_to(absolute_path, install_path)
        except:
            utils.print_log('Exception occur when install patch: %s, Exception: %s' %
                                (self.patch_path, traceback.format_exc()),
                            logging.ERROR)

class PatchConfigurator(ConfiguratorBase):
    """
    we make the structure of each patch follow the original source code structure.
    and config file structure is the same as the original config file structure of openstack.
    so when we need to add this patch, we can read all config files and config in the system config file directly.
    for example: novaproxy, the structure of patch novaproxy is as following.
    novaproxy/
        etc/
            nova/
                nova.conf
                nova-compute.conf
        nova/
            compute/
                clients.py
                compute_context.py
    """
    def __init__(self, absolute_path_of_patch, filter):
        """

        :param absolute_path_of_patch:  path of patches config file.
            for example: /root/tricircle-master/novaproxy/
                        /root/tricircle-master/juno-patches/nova_scheduling_patch/
        :param filter:  ['.conf', '.ini']
        :return:
        """
        self.absolute_path_of_patch = absolute_path_of_patch
        self.filter = filter
        self.system_replacement = {
            ConfigReplacement.AVAILABILITY_ZONE : config.CONF.node_cfg.availability_zone,
            ConfigReplacement.CASCADED_NODE_IP : config.CONF.node_cfg.cascaded_node_ip,
            ConfigReplacement.CASCADING_NODE_IP : config.CONF.node_cfg.cascading_node_ip,
            ConfigReplacement.CINDER_TENANT_ID : RefServices().get_tenant_id_for_admin(),
            ConfigReplacement.REGION_NAME : config.CONF.node_cfg.region_name,
            ConfigReplacement.CASCADING_OS_REGION_NAME : config.CONF.node_cfg.cascading_os_region_name,
            ConfigReplacement.ML2_LOCAL_IP : config.CONF.sysconfig.ml2_local_ip
        }

    def _get_all_config_files(self):
        """

        :return:[(<absolute_path>, <relative_path>), ..]

        """
        return utils.get_files(self.absolute_path_of_patch, self.filter)

    def config(self):
        try:
            config_files = self._get_all_config_files()
            if not config_files:
                utils.print_log('There is no config file in %s ' % self.absolute_path_of_patch, logging.ERROR)
                return
            for absolute_path, relative_path in config_files:
                user_config = ConfigCommon(absolute_path)
                openstack_config_file = os.path.join(os.path.sep, absolute_path)
                sys_config = ConfigCommon(openstack_config_file)
                user_sections = user_config.get_sections()
                for section in user_sections:
                    user_options = user_config.get_options(section)
                    for option in user_options:
                        user_defined_value = user_config.get_value(section, option)
                        for replace_symbol in self.system_replacement:
                            if replace_symbol in user_defined_value:
                                user_defined_value = user_defined_value % \
                                                     {replace_symbol : self.system_replacement[replace_symbol]}
                        sys_config.set_option(section, option, user_defined_value)
        except:
            utils.print_log('Exception occur when config : %s, Exception: %s' %
                                (self.absolute_path_of_patch, traceback.format_exc()),
                            logging.ERROR)