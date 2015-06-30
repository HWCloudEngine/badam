__author__ = 'nash.xiejun'
import os
import logging
import traceback

import utils
from utils import CommonCMD, ELog
from config import CONF
from constants import PatchFilePath

logger = logging.getLogger(__name__)
print_logger = ELog(logger)

class InstallerBase(object):
    def install(self):
        return True

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
        self.bak_openstack_path = CONF.sysconfig.openstack_bak_path

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
            CommonCMD.mkdir(self.bak_openstack_path)
        bak_dir = os.path.join(self.bak_openstack_path, os.path.dirname(relative_path))
        if not os.path.isdir(bak_dir):
            CommonCMD.mkdir(bak_dir)

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
                if not os.path.isdir(copy_dir):
                    CommonCMD.mkdir(copy_dir)

                cp_result = CommonCMD.cp_to(absolute_path, openstack_installed_file)
                if cp_result:
                    logger.info('Success to copy source file:%s' % absolute_path)
                else:
                    logger.info('Failed to copy source file:%s' % absolute_path)
                result = 'SUCCESS'
        except:
            logger.error('Exception occur when install patch: %s, Exception: %s' %
                                (self.patch_path, traceback.format_exc()))
        return result

class PatchesTool(object):
    def patch_for_aws_cascaded(self):
        absolute_aws_cascaded_patch_path = os.path.sep.join([utils.get_patches_tool_path(), PatchFilePath.PATCH_FOR_AWS_CASCADED])
        PatchInstaller(absolute_aws_cascaded_patch_path, utils.get_openstack_installed_path(), ['.py']).install()

    def patch_for_aws_proxy(self):
        absolute_aws_proxy_patch_path = os.path.sep.join([utils.get_patches_tool_path(), PatchFilePath.PATCH_FOR_AWS_PROXY])
        PatchInstaller(absolute_aws_proxy_patch_path, utils.get_openstack_installed_path(), ['.py']).install()

