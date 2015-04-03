__author__ = 'nash.xiejun'

import logging
import os
import traceback

from common import config
from services import RefServices
from engineering_factory import EnginneringFactory, PatchInstaller, PatchConfigurator
from common.econstants import PathTriCircle, PathHybridCloud
import utils
from utils import ELog

module_logger = logging.getLogger(__name__)
logger = ELog(module_logger)

class CascadingDeploy(object):

    def deploy_cascading_modules(self):
        seps = '##################'
        seps_short = '============='
        logger.info('%s Start to deploy cascading modules %s' % (seps, seps))
        logger.info('')

        if config.CONF.node_cfg.cascading_node is True:
            logger.info('')
            logger.info('%s Start to deploy CASCADING NODE %s' % (seps_short, seps_short))
            self.create_endpoints_in_cascading_node()
            self.deploy_nova_scheduling_patch()
            self.deploy_neutron_cascading_big2layer_patch()
            self.deploy_neutron_cascading_l3_patch_patch()
            logger.info('%s SUCCESS to deploy CASCADING NODE %s' % (seps_short, seps_short))
        else:
            logger.info('  ##')
            logger.info('####cascading node config on-off is off, do not cfg.')
            logger.info('  ##')

        if config.CONF.node_cfg.cascaded_node is True:
            logger.info('')
            logger.info('%s Start to deploy CASCADED NODE %s' % (seps_short, seps_short))
            self.create_ag_az_for_cascaded_node()
            self.deploy_neutron_cascaded_big2layer_patch()
            self.deploy_neutron_cascaded_l3_patch()
            self.deploy_neutron_timestamp_cascaded_patch()
            self.deploy_cinder_cascaded_cinder_timestamp_query_patch()
            logger.info('%s SUCCESS to deploy CASCADED NODE %s' % (seps_short, seps_short))
        else:
            logger.info('  ##')
            logger.info('####cascaded node config on-off is off, do not cfg.')
            logger.info('  ##')

        if config.CONF.node_cfg.proxy_node is True:
            logger.info('')
            logger.info('%s Start to deploy PROXY NODE %s' % (seps_short, seps_short))
            self.deploy_nova_proxy()
            self.deploy_cinder_proxy()
            self.deploy_neutron_l2_proxy()
            self.deploy_neutron_l3_proxy()
            logger.info('%s SUCCESS to deploy PROXY NODE %s' % (seps_short, seps_short))
        else:
            logger.info('  ##')
            logger.info('####proxy node config on-off is off, do not cfg.')
            logger.info('  ##')

        logger.info('')
        logger.info('%s Success to deploy cascading modules %s' % (seps, seps))

    def create_endpoints_in_cascading_node(self):
        #endpoints_info = {sz_az_01: 162.3.110.95,  sz_az_02: 162.3.110.96, sz_az_11: 162.3.110.98}
        endpoint_infos = config.CONF.cascading_node_plugins.endpoints_info
        for region, ip in endpoint_infos.items():
            self._create_endpoints(region, ip)

    def _create_endpoints(self, region, ip):
        logger.info('@@@@ Start to create endpoints for region <%s> ip <%s> @@@@' % (region, ip))
        reference_service = RefServices()
        reference_service.create_endpoint_for_nova(region, ip)
        reference_service.create_endpoint_for_cinder(region, ip)
        reference_service.create_endpoint_for_glance(region, ip)
        reference_service.create_endpoint_for_network(region, ip)
        reference_service.create_endpoint_for_heat(region, ip)
        reference_service.create_endpoint_for_ceilometer(region, ip)
        reference_service.create_endpoint_for_ec2(region, ip)
        logger.info('@@@@ End to create endpoints for region <%s> ip <%s> @@@@' % (region, ip))

    def create_ag_az_for_cascaded_node(self):
        reference_service = RefServices()
        name_aggregate = config.CONF.cascaded_node_plugins.aggregate_name
        az = config.CONF.node_cfg.availability_zone
        host = config.CONF.sysconfig.hostname
        logger.info('@@@@ Start to create aggregate for aggregate <%s> availability_zone <%s> @@@@' %
                    (name_aggregate, az))

        if reference_service.nova_aggregate_exist(name_aggregate, az):
            logger.info('aggregate<%s> availability_zone<%s> is exist, no need to create.')
        else:
            aggregate_obj = reference_service.nova_aggregate_create(name_aggregate, az)
            reference_service.nova_aggregate_add_host(aggregate_obj.id, host)

        logger.info('@@@@ End to create aggregate for aggregate <%s> availability_zone <%s> @@@@' %
                    (name_aggregate, az))

    def deploy_patch(self, patch_on_off, patch_name, install_file_filter, config_file_filter):
        """

        :param patch_on_off: boolean, option value of specified patch in configuration.conf
        :param patch_name: string, name of patch
        :param install_file_filter: [], array of suffix of files which will be install. for example: ['.py']
        :param config_file_filter: [], suffix array of files which will be config. for example: ['.conf', '.ini']
        :return:
        """
        if  patch_on_off== False:
            logger.info('*********************************************************')
            logger.info('**** Config for %s is False, no need to install. ****' % patch_name)
            logger.info('*********************************************************')
            return False
        elif patch_on_off == True:
            absolute_path_of_patch = os.path.join(utils.get_hybrid_cloud_badam_parent_path(), PathTriCircle.PATCH_TO_PATH[patch_name])
            openstack_install_path = utils.get_openstack_installed_path()
            installer = PatchInstaller(absolute_path_of_patch, openstack_install_path, install_file_filter)
            configurator = PatchConfigurator(absolute_path_of_patch, config_file_filter)
            patch_deploy_factory = EnginneringFactory(patch_name,
                                                      installer=installer,
                                                      configurator=configurator)
            patch_deploy_factory.execute()
        else:
            logger.error('Config for cascading node <%s> is invalid, value is: %s' % (patch_name, patch_on_off))
            return False

    def deploy_nova_scheduling_patch(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.cascading_node_plugins.nova_scheduling_patch,
                          PathTriCircle.PATCH_NOVA_SCHEDULING, install_filter, config_filter)

    def deploy_neutron_cascading_big2layer_patch(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.cascading_node_plugins.neutron_cascading_big2layer_patch,
                          PathTriCircle.PATCH_NEUTRON_CASCADING_BIG2LAYER, install_filter, config_filter)

    def deploy_neutron_cascading_l3_patch_patch(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.cascading_node_plugins.neutron_cascading_l3_patch,
                          PathTriCircle.PATCH_NEUTRON_CASCADING_L3, install_filter, config_filter)

    def deploy_neutron_cascaded_big2layer_patch(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.cascaded_node_plugins.neutron_cascaded_big2layer_patch,
                          PathTriCircle.PATCH_NEUTRON_CASCADED_BIG2LAYER, install_filter, config_filter)

    def deploy_neutron_cascaded_l3_patch(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.cascaded_node_plugins.neutron_cascaded_l3_patch,
                          PathTriCircle.PATCH_NEUTRON_CASCADED_L3, install_filter, config_filter)

    def deploy_cinder_cascaded_cinder_timestamp_query_patch(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.cascaded_node_plugins.cinder_timestamp_query_patch,
                          PathTriCircle.PATCH_CINDER_CASCADED_TIMESTAMP, install_filter, config_filter)

    def deploy_neutron_timestamp_cascaded_patch(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.cascaded_node_plugins.neutron_timestamp_cascaded_patch,
                          PathTriCircle.PATCH_NEUTRON_CASCADED_TIMESTAMP, install_filter, config_filter)

    def deploy_nova_proxy(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.proxy_node_plugins.nova_proxy,
                          PathTriCircle.NOVA_PROXY, install_filter, config_filter)

    def deploy_cinder_proxy(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.proxy_node_plugins.cinder_proxy,
                          PathTriCircle.CINDER_PROXY, install_filter, config_filter)

    def deploy_neutron_l2_proxy(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.proxy_node_plugins.neutron_l2_proxy,
                          PathTriCircle.L2_PROXY, install_filter, config_filter)

    def deploy_neutron_l3_proxy(self):
        install_filter = ['.py']
        config_filter = ['.conf', '.ini']
        self.deploy_patch(config.CONF.proxy_node_plugins.neutron_l3_proxy,
                          PathTriCircle.L3_PROXY, install_filter, config_filter)

class HybridDeploy(object):

    def deploy_hybrid_cloud(self):
        self.deploy_python_patches()
        self.deploy_wsgi_patches()

    def deploy_python_patches(self):
        try:
            patch_name = 'hybrid_python_patches'
            install_file_filter = ['.py']
            config_file_filter = ['.conf', '.filters']

            absolute_path_of_patch = os.path.join(utils.get_hybrid_cloud_badam_path(), PathHybridCloud.PATH_PATCHES_PYTHON)
            openstack_install_path = utils.get_openstack_installed_path()
            installer = PatchInstaller(absolute_path_of_patch, openstack_install_path, install_file_filter)

            configurator = PatchConfigurator(absolute_path_of_patch, config_file_filter)
            patch_deploy_factory = EnginneringFactory(patch_name,
                                                      installer=installer,
                                                      configurator=configurator)
            patch_deploy_factory.execute()
        except:
            err_info = 'Exception occur when deploy python patches for hybrid cloud, Exception: %s' %traceback.format_exc()
            logger.error(err_info)

    def deploy_wsgi_patches(self):
        try:
            patch_name = 'openstack_dashboard'
            install_file_filter = ['.py', '.html', '.po']
            absolute_path_of_patch = os.path.join(utils.get_hybrid_cloud_badam_path(),
                                                  PathHybridCloud.PATH_PATCHES_OPENSTACK_DASHBOARD)
            install_path = PathHybridCloud.PATH_INSTALL_PATCH_OPENSTACK_DASHBOARD
            installer = PatchInstaller(absolute_path_of_patch, install_path, install_file_filter)
            patch_deploy_factory = EnginneringFactory(patch_name,
                                                      installer=installer)
            patch_deploy_factory.execute()

        except:
            err_info = 'Exception occur when deploy python patches for WSGI openstack dashboard, Exception: %s' %traceback.format_exc()
            logger.error(err_info)

    def deploy_java_patches(self):
        try:
            absolute_3rd_java_path = os.path.join(utils.get_hybrid_cloud_badam_path(),
                                                  PathHybridCloud.PATH_THIRD_LIB_JAVA)
            pass
        except:
            pass