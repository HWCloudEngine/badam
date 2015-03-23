__author__ = 'nash.xiejun'

import logging

from common import config
from services import RefServices

logger = logging.getLogger(__name__)

class CascadingDeploy(object):

    def deploy_cascading_modules(self):
        result_deploy = False

        if config.CONF.node_cfg.cascading_node == True:
            self.create_endpoints_in_cascading_node()
            self.deploy_nova_scheduling_patch()
            self.deploy_neutron_cascading_big2layer_patch()
            self.deploy_neutron_cascading_l3_patch_patch()

        if config.CONF.node_cfg.cascaded_node == True:
            self.creat_ag_az_for_cascaded_node()
            self.deploy_neutron_cascaded_big2layer_patch()
            self.deploy_neutron_cascaded_l3_patch()
            self.deploy_neutron_timestamp_cascaded_patch()

        if config.CONF.node_cfg.proxy_node == True:
            self.deploy_nova_proxy()
            self.deploy_cinder_proxy()
            self.deploy_neutron_l2_proxy()
            self.deploy_neutron_l3_proxy()

    def deploy_patch(self, patch_option_value, patch_option_name, patch_deploy_factory):
        if  patch_option_value== False:
            logger.info('Config for %s is False, no need to install.' % patch_option_name)
            return False
        elif patch_option_value == True:
            patch_deploy_factory.execute()
        else:
            logger.warning('Config for cascading node <%s> is invalid, value is: %s',
                           patch_option_name, patch_option_value)
            return False

    def deploy_nova_scheduling_patch(self):
        patch_deploy_factory = None
        self.deploy_patch(config.CONF.cascading_node_plugins.nova_scheduling_patch,
                          'nova_scheduling_patch',
                          patch_deploy_factory)

    def deploy_neutron_cascading_big2layer_patch(self):
        patch_deploy_factory = None
        self.deploy_patch(config.CONF.cascading_node_plugins.neutron_cascading_big2layer_patch,
                          'neutron_cascading_big2layer_patch',
                          patch_deploy_factory)

    def deploy_neutron_cascading_l3_patch_patch(self):
        pass

    def create_endpoints_in_cascading_node(self):
        #endpoints_info = {sz_az_01: 162.3.110.95,  sz_az_02: 162.3.110.96, sz_az_11: 162.3.110.98}
        endpoint_infos = config.CONF.cascading_node_plugins.endpoints_info
        for region, ip in endpoint_infos.items():
            self._create_endpoints(region, ip)

    def _create_endpoints(self, region, ip):
        reference_service = RefServices()
        reference_service.create_endpoint_for_nova(region, ip)
        reference_service.create_endpoint_for_cinder(region, ip)
        reference_service.create_endpoint_for_glance(region, ip)
        reference_service.create_endpoint_for_network(region, ip)
        reference_service.create_endpoint_for_heat(region, ip)
        reference_service.create_endpoint_for_ceilometer(region, ip)
        reference_service.create_endpoint_for_ec2(region, ip)

    def creat_ag_az_for_cascaded_node(self):
        pass

    def deploy_neutron_cascaded_big2layer_patch(self):
        pass

    def deploy_neutron_cascaded_l3_patch(self):
        pass

    def deploy_neutron_timestamp_cascaded_patch(self):
        pass

    def deploy_nova_proxy(self):
        pass

    def deploy_cinder_proxy(self):
        pass

    def deploy_neutron_l2_proxy(self):
        pass

    def deploy_neutron_l3_proxy(self):
        pass