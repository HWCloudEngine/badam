__author__ = 'nash.xiejun'
import os
import traceback

import log
import utils
import sshutils
from constants import SysUserInfo, SysPath, ScriptFilePath
from services import CPSServiceBusiness



class DispatchPatchTool(object):

    def __init__(self):
        # self.filter_for_dispatch = ['.py', '.sh', '.ini', '.pem', '.txt', '.vmx', '.json']
        self.filter_for_dispatch = []
        self.cps_service_business = CPSServiceBusiness()
        self.aws_cascaded_node_hosts = self.cps_service_business.get_aws_node_hosts()
        self.vcloud_cascaded_node_hosts = self.cps_service_business.get_vcloud_node_hosts()
        self.openstack_cascaded_node_hosts = self.cps_service_business.get_openstack_hosts()

    def dispatch_patch_tool_to_host(self, host):
        path_of_patch_tool = utils.get_patches_tool_path()
        files_need_to_dispatch = utils.get_files(path_of_patch_tool, self.filter_for_dispatch)

        ssh = sshutils.SSH(host=host, user=SysUserInfo.FSP, password=SysUserInfo.FSP_PWD)
        for absolute_file, relative_path_of_file in files_need_to_dispatch:
            log.info('start to copy file <<%s>> to host <<%s>>' % (relative_path_of_file, host))
            file_copy_to = os.path.join(SysPath.HOME_FSP, SysPath.PATCHES_TOOL, relative_path_of_file)
            file_dir_copy_to = os.path.dirname(file_copy_to)
            ssh.run('mkdir -p %s' % file_dir_copy_to)
            ssh.put_file(absolute_file, file_copy_to)
            log.info('End to copy file <<%s>> to host <<%s>>' % (relative_path_of_file, host))

        ssh.close()

    def dispatch_patches_tool_to_host_with_tar(self, host, local_full_path_of_tar_file):
        log.info('Start to dispatch tar of patches_tool to host %s' % host)
        ssh = sshutils.SSH(host=host, user=SysUserInfo.ROOT, password=SysUserInfo.ROOT_PWD)
        full_path_of_file_copy_to = os.path.join(SysPath.HOME_FSP, SysPath.PATCHES_TOOL_TAR_GZ)
        dir_of_patches_tool = os.path.join(SysPath.HOME_FSP, SysPath.PATCHES_TOOL)
        try:
            # remove dir: /home/fsp/patches_tool/
            ssh.run('rm -rf %s' % dir_of_patches_tool)
        except Exception, e:
            log.error('Failed to execute <%s> in HOST <%s>' % ('rm -rf %s' % dir_of_patches_tool, host))
            log.error('Exception: %s' % traceback.format_exc())
        try:
            # remove /home/fsp/patches_tool.tar.gz
            ssh.run('rm %s' % full_path_of_file_copy_to)
        except Exception, e:
            log.error('Failed to execute <%s> in HOST <%s>' % ('rm %s' % full_path_of_file_copy_to, host))
            log.error('Exception: %s' % traceback.format_exc())
        ssh.put_file(local_full_path_of_tar_file, full_path_of_file_copy_to)
        ssh.run('tar -xzvf %s -C %s' % (full_path_of_file_copy_to, SysPath.HOME_FSP))
        ssh.close()
        log.info('Success to dispatch tar of patches_tool to host %s' % host)

    def remove_tar_patches_tool(self, full_patch_of_patches_tool):
        if os.path.isfile(full_patch_of_patches_tool):
            os.remove(full_patch_of_patches_tool)

    def tar_patches_tool(self):
        log.info('Start to tar patches_tool')
        patches_tool_path = utils.get_patches_tool_path()
        full_patch_of_patches_tool = os.path.join(patches_tool_path, SysPath.PATCHES_TOOL_TAR_GZ)
        if os.path.isfile(full_patch_of_patches_tool):
            self.remove_tar_patches_tool(full_patch_of_patches_tool)
        new_tar_of_patches_tool = os.path.join(patches_tool_path, SysPath.PATCHES_TOOL_TAR_GZ)
        utils.make_tarfile(new_tar_of_patches_tool, patches_tool_path)
        log.info('Success to tar patches_tool: <%s>' % full_patch_of_patches_tool)

        return full_patch_of_patches_tool

    def dispatch_patches_tool_to_remote_cascaded_nodes(self):
        log.info('Start to dispatch patches_tool to remote cascaded nodes')
        print('Start to dispatch_patches_tool_to_remote_cascaded_nodes')
        local_full_path_of_tar_file = self.tar_patches_tool()
        self.dispatch_patches_tool_to_aws_cascaded_nodes(local_full_path_of_tar_file)
        self.dispatch_patches_tool_to_vcloud_cascaded_nodes(local_full_path_of_tar_file)
        self.dispatch_patches_tool_to_openstack_cascaded_nodes(local_full_path_of_tar_file)
        print('Finish to dispatch_patches_tool_to_remote_cascaded_nodes')
        log.info('Finish to dispatch patches_tool to remote cascaded nodes')

    def dispatch_patches_tool_to_aws_cascaded_nodes(self, local_full_path_of_tar_file):
        log.info('Start to dispatch_patches_tool_to_aws_cascaded_nodes')
        print('Start to dispatch to aws cascaded nodes')
        for host in self.aws_cascaded_node_hosts:
            # self.dispatch_patch_tool_to_host(host)
            self.dispatch_patches_tool_to_host_with_tar(host, local_full_path_of_tar_file)
        print('Finish to dispatch to aws cascaded nodes')
        log.info('End to dispatch_patches_tool_to_aws_cascaded_nodes')

    def dispatch_patches_tool_to_vcloud_cascaded_nodes(self, local_full_path_of_tar_file):
        print('Start to dispatch to vcloud cascaded nodes')
        log.info('Start to dispatch_patches_tool_to_vcloud_cascaded_nodes')
        for host in self.vcloud_cascaded_node_hosts:
            # self.dispatch_patch_tool_to_host(host)
            self.dispatch_patches_tool_to_host_with_tar(host, local_full_path_of_tar_file)
        print('Finish to dispatch to vcloud cascaded nodes')
        log.info('End to dispatch_patches_tool_to_vcloud_cascaded_nodes')

    def dispatch_patches_tool_to_openstack_cascaded_nodes(self, local_full_path_of_tar_file):
        log.info('Start to dispatch patches_tool to openstack cascaded nodes')
        print('Start to dispatch to openstack cascaded nodes')
        for host in self.openstack_cascaded_node_hosts:
            # self.dispatch_patch_tool_to_host(host)
            self.dispatch_patches_tool_to_host_with_tar(host, local_full_path_of_tar_file)
        print('Finish to dispatch to openstack cascaded nodes')
        log.info('Finish to dispatch patches_tool to openstack cascaded nodes')

    def remote_patch_for_cascaded_nodes(self):
        print('Start to patch for vcloud cascaded nodes...')
        log.info('Start to patch for vcloud cascaded nodes...')
        self.remote_patch_vcloud_nodes()

        print('Start to patch for aws cascaded nodes...')
        log.info('Start to patch for aws cascaded nodes...')
        self.remote_patch_aws_nodes()

    def remote_patch_aws_nodes(self):
        for host in self.aws_cascaded_node_hosts:
            self.remote_patch_aws_node(host)

    def remote_patch_vcloud_nodes(self):
        for host in self.vcloud_cascaded_node_hosts:
            self.remote_patch_vcloud_node(host)

    def remote_patch_aws_node(self, host):
        try:
            ssh = sshutils.SSH(host=host, user=SysUserInfo.ROOT, password=SysUserInfo.ROOT_PWD)
            ssh.run('python %s' % ScriptFilePath.PATH_REMOTE_AWS_PATCH_FILE)
            ssh.close()
        except Exception, e:
            log.error('Exception when remote_patch_aws_node for host %s' % host)
            print('Exception when remote_patch_aws_node for host %s' % host)
            log.error('Exception: %s' % traceback.format_exc())

    def remote_patch_vcloud_node(self, host):
        try:
            ssh = sshutils.SSH(host=host, user=SysUserInfo.ROOT, password=SysUserInfo.ROOT_PWD)
            ssh.run('python %s' % ScriptFilePath.PATH_REMOTE_VCLOUD_PATCH_FILE)
            ssh.close()
        except Exception, e:
            log.error('Exception when remote_patch_vcloud_node for host %s' % host)
            print('Exception when remote_patch_vcloud_node for host %s' % host)
            log.error('Exception: %s' % traceback.format_exc())

    def remote_config_cascaded_for_all_type_node(self):
        print('Start to config cascading nodes...')

        print('Start to config aws cascaded node hosts...')
        for host in self.aws_cascaded_node_hosts:
            self.remote_config_openstack_cascaded_node(host)

        print('Start to config vcloud node hosts...')
        for host in self.vcloud_cascaded_node_hosts:
            self.remote_config_openstack_cascaded_node(host)

        print('Start to config openstack cascaded node hosts...')
        for host in self.openstack_cascaded_node_hosts:
            self.remote_config_openstack_cascaded_node(host)

        print('Finish to config cascading nodes...')

    def remote_config_openstack_cascaded_node(self, host):
        try:
            ssh = sshutils.SSH(host=host, user=SysUserInfo.ROOT, password=SysUserInfo.ROOT_PWD)
            ssh.run('python %s cascaded' % ScriptFilePath.PATCH_REMOTE_HYBRID_CONFIG_PY)
        except Exception, e:
            log.error('Exception when remote_config_openstack_cascaded_node in HOST:<%s>' % host)
            log.error('Exception: %s' % traceback.format_exc())
