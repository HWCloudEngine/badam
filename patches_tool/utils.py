__author__ = 'nash.xiejun'

import subprocess
import sys
import traceback
import os
import tarfile

import paramiko
import log

import sshutils
from constants import ScriptFilePath, SysUserInfo

class CommonCMD(object):

    @staticmethod
    def reboot():
        try:
            log.warning('Start boot system.')
            subprocess.call("reboot")
        except:
            log.error('Exception occured when reboot system, EXCEPTION: %s', sys.exc_traceback)

    @staticmethod
    def excute_cmd(cmd, *args):
        log.info('Execute CMD: %s' % cmd)
        cmd_list = []
        cmd_list.append(cmd)
        if args is not None:
            cmd_list.extend(args)
        command = ' '.join(cmd_list)
        log.info('Command is : %s' % command)
        try:
            result = subprocess.call(command.split(' '))
            if result == 0:
                log.info('SUCCESS to execute command: %s' %  command)
                return True
            else:
                log.info('FAIL to to execute command: %s' %  command)
                return False
        except:
            log.error('Exception occur when execute command: %s, Exception: %s' % (command, traceback.format_exc()))
            return False

    @staticmethod
    def cp_to(source, str_destiny):
        return CommonCMD.excute_cmd('cp', source, str_destiny)

    @staticmethod
    def mkdir(dir):
        CommonCMD.excute_cmd('mkdir', '-p', dir)

    @staticmethod
    def cp_f_to(source, str_destiny):
        try:
            cmd = 'cp -f %s %s' % (source, str_destiny)
            log.info('copy CMD: %s' % cmd)
            result = subprocess.call(cmd.split(' '))
            if result == 0:
                log.info('SUCCESS to copy %s to %s' % (source, str_destiny))
                return True
            else:
                log.info('FAIL to copy %s to %s, result is: %s' % (source, str_destiny, result))
                return False
        except:
            log.error('Exception occur when copy %s to %s, Exception: %s' %(source, str_destiny, traceback.format_exc()))
            return False

    @staticmethod
    def create_route(net, ip):
        command = ['ip', 'route', 'add', net, 'via', ip]
        try:
            result = subprocess.call(command)
            if result == 0:
                log.info('SUCCESS to execute command: %s' %  command)
                return True
            else:
                log.info('FAIL to to execute command: %s' %  command)
                return False
        except:
            log.error('Exception occur when execute command: %s, Exception: %s' % (command, traceback.format_exc()))
            return False

    @staticmethod
    def create_route_for_table(table, net, ip):
        command = ['ip', 'route', 'add', 'table', table, net, 'via', ip]
        try:
            result = subprocess.call(command)
            if result == 0:
                log.info('SUCCESS to execute command: %s' %  command)
                return True
            else:
                log.info('FAIL to to execute command: %s' %  command)
                return False
        except:
            log.error('Exception occur when execute command: %s, Exception: %s' % (command, traceback.format_exc()))
            return False


def get_patches_tool_path():
    """
    :return: <ROOT_PATH>/patches_tool/
    """
    return os.path.split(os.path.realpath(__file__))[0]


def get_files(specified_path, filters):
    """

    :param path, absolute path
    :param filters: array, specified valid file suffix.
    :return:
    for example:
    [(/root/tricircle-master/novaproxy/nova/compute/clients.py,
            nova/compute/clients.py), ..]
    """
    files_path = []
    file_sys_infos = os.walk(specified_path)

    for (path, dirs, files) in file_sys_infos:
        if not filters:
            for file in files:
                absolute_path = os.path.join(path, file)
                relative_path = absolute_path.split(specified_path)[1].split(os.path.sep, 1)[1]
                files_path.append((absolute_path, relative_path))
        else:
            for file in files:
                if os.path.splitext(file)[1] in filters:
                    absolute_path = os.path.join(path, file)
                    relative_path = absolute_path.split(specified_path)[1].split(os.path.sep, 1)[1]
                    files_path.append((absolute_path, relative_path))
                else:
                    continue
    log.info('Get files by filter %s is: %s' % (filters, files_path))
    return files_path


def get_openstack_installed_path():
    paths = [path for path in sys.path if 'site-packages' in path and 'local' not in path]
    if not paths:
        return None
    else:
        openstack_installed_path = paths[0]
        log.info('openstack_installed_path: %s' % openstack_installed_path)
        return openstack_installed_path


def remote_open_root_permit_for_host(ip):
    ssh = sshutils.SSH(host=ip, user=SysUserInfo.FSP, password=SysUserInfo.FSP_PWD)
    local_path_execute_sh = os.path.join(get_patches_tool_path(), ScriptFilePath.PATH_EXECUTE_SH)
    local_path_su_change_sh = os.path.join(get_patches_tool_path(), ScriptFilePath.PATH_SU_CHANGE_SH)
    ssh.put_file(local_path_execute_sh, ScriptFilePath.PATH_EXECUTE_SH_COPY_TO)
    ssh.put_file(local_path_su_change_sh, ScriptFilePath.PATH_SU_CHANGE_SH_COPY_TO)
    ssh.execute('sh %s' % ScriptFilePath.PATH_EXECUTE_SH_COPY_TO)
    ssh.close()


def remote_open_root_permit_for_hosts(ip_list):
    for ip in ip_list:
        remote_open_root_permit_for_host(ip)


def make_tarfile(output_filename, source_dir):
    tar = tarfile.open(output_filename, "w:gz")
    tar.add(source_dir, arcname=os.path.basename(source_dir))
    tar.close()

class SSHConnection(object):
    """"""

    def __init__(self, host, username, password, port=22):
        """Initialize and setup connection"""
        self.sftp = None
        self.sftp_open = False

        # open SSH Transport stream
        self.transport = paramiko.Transport((host, port))
        self.transport.connect(username=username, password=password)

    def get_sftp(self):
        if not self.sftp_open:
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            self.sftp_open = True
        return self.sftp

    def _openSFTPConnection(self):
        """
        Opens an SFTP connection if not already open
        """
        if not self.sftp_open:
            self.sftp = paramiko.SFTPClient.from_transport(self.transport)
            self.sftp_open = True

    def get(self, remote_path, local_path=None):
        """
        Copies a file from the remote host to the local host.
        """
        self._openSFTPConnection()
        self.sftp.get(remote_path, local_path)

    def put(self, local_path, remote_path=None):
        """
        Copies a file from the local host to the remote host
        """
        self._openSFTPConnection()
        self.sftp.put(local_path, remote_path)

    def close(self):
        """
        Close SFTP connection and ssh connection
        """
        if self.sftp_open:
            self.sftp.close()
            self.sftp_open = False
        self.transport.close()

if __name__ == '__main__':
    # patch_path = 'hybrid_tricrile/nova/nova_patch/'
    # print get_hybrid_cloud_badam_parent_path()
    # print os.path.normpath(os.path.join(get_hybrid_cloud_badam_parent_path(), patch_path))
    log.init('patches_tool_config')
    from constants import SysPath
    patches_tool_path = get_patches_tool_path()
    make_tarfile(SysPath.PATCHES_TOOL_TAR_GZ, patches_tool_path)
    print os.path.split(os.path.realpath(__file__))[0]