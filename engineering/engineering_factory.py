__author__ = 'nash.xiejun'

import logging
import traceback
import os

from oslo.config import cfg

from common import config
from common.engineering_logging import log_for_func_of_class
import utils
from utils import AllInOneUsedCMD, print_log, ELog
from common.config import ConfigCommon

from services import RefServices
from common.econstants import ConfigReplacement

logger_name = __name__
module_logger = logging.getLogger(__name__)
logger = ELog(module_logger)

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
        big_sep = '*********************************************************'
        logger.info('')
        logger.info(big_sep)
        logger.info('**** Start to deploy for >>>> %s <<<< ****' % self.factory_name)
        logger.info(big_sep)
        execute_result = True
        sep = '****************************'

        logger.info(sep)
        validate_result = self.validator.validate()
        logger.info(sep)

        logger.info(sep)
        install_result = self.installer.install()
        logger.info(sep)

        logger.info(sep)
        config_result = self.configurator.config()
        logger.info(sep)

        logger.info(sep)
        check_result = self.checker.check()
        logger.info(sep)

        logger.info(big_sep)
        logger.info('**** SUCCESS to deploy for >>>> %s <<<< ****' % self.factory_name)
        logger.info(big_sep)

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
        result = 'SUCCESS'
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
            result = 'FAILED'
        return result

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

            config_common = ConfigCommon(path_nova_conf_file)
            config_common.set_default('vncserver_listen', vncserver_listen)
            config_common.set_default('service_metadata_proxy', 'False')
            config_common.set_default('metadata_proxy_shared_secret', 'openstack')
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
        logger.info('tenant id of service is <%s>' % (value_nova_admin_tenant_id))
        config_common = ConfigCommon(path_neutron_conf)
        config_common.set_default(option_nova_admin_tenant_id, value_nova_admin_tenant_id)
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
            ml2_section_ovf = 'ovs'
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

            with open(config.CONF.path_sysctl, 'w') as sysctl_file:
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
            config_common.set_default( option_external_network_bridge, value_external_network_bridge)
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
            common_config.set_default(option_dhcp_driver, value_dhcp_driver)
            common_config.set_default(option_use_namespaces, value_use_namespaces)
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
            config_common.set_default(option_nova_metadata_ip,
                                     value_nova_metadata_ip)
            config_common.set_default(option_metadata_proxy_shared_secret,
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
        self.bak_openstack_path = config.CONF.sysconfig.openstack_bak_path

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

    def bak_patched_file(self, bak_file_path, relative_path):
        """

        :param patch_file:  one file of patch's source code files,
            for example: /root/tricircle-master/juno-patches/nova/nova_scheduling_patch/nova/conductor/manager.py
        :param relative_path:
            for example: nova/conductor/manager.py
        :return:
        """
        logger.info('Start bak_patched_file, bak_file_path:%s, relative_path:%s' % (bak_file_path, relative_path))
        # relative_path is relative to this path(self.patch_path),
        # for example: if self.patch_path = "/root/tricircle-master/juno-patches/nova/nova_scheduling_patch/"
        # then relative_path of manager.py is "/nova/nova_scheduling_patch/nova/conductor/manager.py"
        if not os.path.isdir(self.bak_openstack_path):
            AllInOneUsedCMD.mkdir(self.bak_openstack_path)
        bak_dir = os.path.join(self.bak_openstack_path, os.path.dirname(relative_path))
        if not os.path.isdir(bak_dir):
            AllInOneUsedCMD.mkdir(bak_dir)

        if os.path.isfile(bak_file_path):
            AllInOneUsedCMD.cp_to(bak_file_path, bak_dir)
        else:
            info = 'file: <%s> is a new file, no need to bak.' % bak_file_path
            logger.info(info)
        logger.info('Success to bak_patched_file, bak_file_path:%s' % bak_file_path)

    @log_for_func_of_class(logger_name)
    def install(self):
        result = 'FAILED'
        try:
            patch_files = self.get_patch_files(self.patch_path, self.filters)
            if not patch_files:
                logger.error('No files in %s' % self.patch_path)
            for absolute_path, relative_path in patch_files:
                # installed_path is full install path,
                # for example: /usr/lib/python2.7/dist-packages/nova/conductor/manager.py
                openstack_installed_file = os.path.join(self.openstack_install_path, relative_path)
                self.bak_patched_file(openstack_installed_file, relative_path)

                copy_dir = os.path.dirname(openstack_installed_file)
                if not os.path.isdir(copy_dir):
                    AllInOneUsedCMD.mkdir(copy_dir)

                cp_result = AllInOneUsedCMD.cp_to(absolute_path, openstack_installed_file)
                if cp_result:
                    logger.info('Success to copy source file:%s' % absolute_path)
                else:
                    logger.info('Failed to copy source file:%s' % absolute_path)
                result = 'SUCCESS'
        except:
            logger.error('Exception occur when install patch: %s, Exception: %s' %
                                (self.patch_path, traceback.format_exc()))
        return result


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
        self.exclude_replacement = ['project_id']
        self.bak_openstack_path = config.CONF.sysconfig.openstack_bak_path

    def _get_all_config_files(self):
        """

        :return:[(<absolute_path>, <relative_path>), ..]

        """
        return utils.get_files(self.absolute_path_of_patch, self.filter)

    @log_for_func_of_class(logger_name)
    def config(self):
        result = 'FAILED'
        try:
            config_files = self._get_all_config_files()
            if not config_files:
                logger.info('There is no config file in %s ' % self.absolute_path_of_patch)
                return 'No config file, no need to config.'
            for absolute_path, relative_path in config_files:
                user_config = ConfigCommon(absolute_path)
                openstack_config_file = os.path.join(os.path.sep, relative_path)
                self.bak_cfg_file(openstack_config_file, relative_path)
                sys_config = ConfigCommon(openstack_config_file)
                default_options = user_config.get_options_dict_of_default()
                for key, value in default_options.items():
                    value = self.replace_value_for_sysconfig(key, value)
                    sys_config.set_default(key, value)

                user_sections = user_config.get_sections()
                for section in user_sections:
                    section_options = user_config.get_options_dict_of_section(section)
                    for key, value in section_options.items():
                        value = self.replace_value_for_sysconfig(key, value)
                        sys_config.set_option(section, key, value)

                sys_config.write_commit()
            result = 'SUCCESS'
        except:
            logger.error('Exception occur when config : %s, Exception: %s' %
                                (self.absolute_path_of_patch, traceback.format_exc()))
        return result

    def replace_value_for_sysconfig(self, key, value):
        try:
            if key == 'cinder_endpoint_template':
                value = 'http://%(cascading_node_ip)s:8776/v2/'
            if key == 'cascaded_cinder_url':
                value = 'http://%(cascaded_node_ip)s:8776/v2/'

            for replace_symbol in self.system_replacement.keys():
                add_brasces_symbol = ''.join(['(', replace_symbol, ')'])
                if add_brasces_symbol in value:
                    replace_value = self.system_replacement.get(replace_symbol)
                    value = value % {replace_symbol : replace_value}

            if key == 'cinder_endpoint_template':
                value = ''.join([value, '%(project_id)s'])
            if key == 'cascaded_cinder_url':
                value = ''.join([value, '%(project_id)s'])
        except:
            logger.error('Exception occur when replace value for key: %s, value: %s, Exception is: %s' %
                         (key, value, traceback.format_exc()))
        return value

    def bak_cfg_file(self, bak_file_path, relative_path):
        """

        :param patch_file:  one file of patch's source code files,
            for example: /root/tricircle-master/juno-patches/nova/nova_scheduling_patch/nova/conductor/manager.py
        :param relative_path:
            for example: nova/conductor/manager.py
        :return:
        """
        logger.info('Start bak cfg file, bak_file_path:%s, relative_path:%s' % (bak_file_path, relative_path))
        # relative_path is relative to this path(self.patch_path),
        # for example: if self.patch_path = "/root/tricircle-master/juno-patches/nova/nova_scheduling_patch/"
        # then relative_path of manager.py is "/nova/nova_scheduling_patch/nova/conductor/manager.py"
        if not os.path.isdir(self.bak_openstack_path):
            AllInOneUsedCMD.mkdir(self.bak_openstack_path)
        bak_dir = os.path.join(self.bak_openstack_path, os.path.dirname(relative_path))
        if not os.path.isdir(bak_dir):
            AllInOneUsedCMD.mkdir(bak_dir)

        if os.path.isfile(bak_file_path):
            AllInOneUsedCMD.cp_to(bak_file_path, bak_dir)
        else:
            info = 'file: <%s> is a new file, no need to bak.' % bak_file_path
            logger.info(info)
        logger.info('Success to bak cfg file, bak cfg file from %s to %s' % (bak_file_path, bak_dir))