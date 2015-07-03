__author__ = 'nash.xiejun'
import os
import logging
import traceback
import stat

import utils
from utils import CommonCMD, ELog, SSHConnection
from config import CONF
from constants import PatchFilePath, CfgFilePath
from services import RefCPSService, CPSServiceBusiness
from dispatch import DispatchPatchTool
import log
logger = log
print_logger = log

class InstallerBase(object):
    def install(self):
        return True

class PatchInstaller(InstallerBase):

    def __init__(self, patch_path, openstack_install_path, filters, host):
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
        self.host_ip = host
        # install_path is  openstack installed path'/usr/lib/python2.7/dist-packages/'
        self.openstack_install_path = openstack_install_path
        # filter is valid suffix of files, for example: ['.py']
        self.filters = filters
        self.bak_openstack_path = CONF.DEFAULT.openstack_bak_path

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
        bak_path = os.path.sep.join([self.bak_openstack_path, str(self.host_ip)])
        if not os.path.isdir(bak_path):
            CommonCMD.mkdir(bak_path)
        bak_dir = os.path.join(bak_path, os.path.dirname(relative_path))
        if not os.path.isdir(bak_dir):
            CommonCMD.mkdir(bak_dir)

        ssh = SSHConnection(self.host_ip, 'root', 'Huawei@CLOUD8!')

        if os.path.isfile(bak_file_path):
            CommonCMD.cp_to(bak_file_path, bak_dir)
        else:
            info = 'file: <%s> is a new file, no need to bak.' % bak_file_path
            logger.info(info)
        logger.info('Success to bak_patched_file, bak_file_path:%s' % bak_file_path)

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

                # cp_result = CommonCMD.cp_to(absolute_path, openstack_installed_file)
                ssh = SSHConnection(self.host_ip, 'root', 'Huawei@CLOUD8!')
                if not stat.S_ISDIR(ssh.get_sftp().stat(copy_dir).st_mode):
                    print('Need to create dir.')
                    ssh.get_sftp().mkdir(copy_dir)
                ssh.put(absolute_path, openstack_installed_file)
                ssh.close()
                result = 'SUCCESS'
        except:
            logger.error('Exception occur when install patch: %s, Exception: %s' %
                                (self.patch_path, traceback.format_exc()))
            print('Exception occur when install patch: %s, Exception: %s' %
                                (self.patch_path, traceback.format_exc()))
        return result

class PatchesTool(object):

    def __init__(self):
        self.proxy_match_region = CONF.DEFAULT.proxy_match_region

    def patch_for_cascading_and_proxy_node(self):
        host_list = RefCPSService.host_list()
        for host in host_list['hosts']:
            roles_list = host['roles']
            proxy_host_ip = host['manageip']
            region = self._get_region_by_roles_list(roles_list)
            if region is not None:
                print('Start to patch for region - <%s>' % region)
                absolute_patch_path = self._get_path_by_region(region)
                PatchInstaller(absolute_patch_path, utils.get_openstack_installed_path(), ['.py'], proxy_host_ip).install()
                print('Finish to patch for region - <%s>' % region)
            else:
                print('Region of ip <%s> is None, can not patch for this proxy' % proxy_host_ip)

    def patch_for_cascaded_nodes(self):
        cps = CPSServiceBusiness()


    def _get_path_by_region(self, region):
        absolute_cascading_patch_path = os.path.sep.join([utils.get_patches_tool_path(), PatchFilePath.PATCH_FOR_CASCADING])
        absolute_aws_proxy_patch_path = os.path.sep.join([utils.get_patches_tool_path(), PatchFilePath.PATCH_FOR_AWS_PROXY])
        absolute_vcloud_proxy_patch_path = os.path.sep.join([utils.get_patches_tool_path(), PatchFilePath.PATCH_FOR_VCLOUD_PROXY])

        if 'aws' in region:
            return absolute_aws_proxy_patch_path
        elif 'vcloud' in region:
            return absolute_vcloud_proxy_patch_path
        else:
            return absolute_cascading_patch_path

    def _get_region_by_roles_list(self, roles_list):
        for role in roles_list:
            if 'compute-proxy' in role:
                proxy_number = role.split('-')[1]
                return self.proxy_match_region[proxy_number]
        return

    def restart_service(self):
        cps_service = CPSServiceBusiness()
        for proxy in self.proxy_match_region.keys():
            cps_service.stop_all(proxy)
            cps_service.start_all(proxy)

    def verify_services_status(self):
        cps_service = CPSServiceBusiness()
        for proxy in self.proxy_match_region.keys():
            cps_service.check_all_service_template_status(proxy)

if __name__ == '__main__':
    log.init('patches_tool')
    print('Start to patch hybrid cloud patch...')
    patches_tool = PatchesTool()
    patches_tool.patch_for_cascading_and_proxy_node()
    patches_tool.restart_service()
    patches_tool.verify_services_status()
    print('Finish to patch hybrid cloud patch.')
    print('Patched backup file is in DIR - %s' % CONF.DEFAULT.openstack_bak_path)

    dispatch_patch_tool = DispatchPatchTool()
    dispatch_patch_tool.remote_patch_for_cascaded_nodes()


