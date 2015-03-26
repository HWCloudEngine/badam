__author__ = 'nash.xiejun'

import subprocess
import logging
import sys
import traceback
import os

class ELog(object):

    def __init__(self, module_logger):
        self.module_logger = module_logger

    def info(self, log_contents, *args):
        self.module_logger.info(log_contents, *args)
        print(log_contents)

    def error(self, log_contents, *args):
        self.module_logger.error(log_contents, *args)
        print(log_contents)

    def warning(self, log_contents, *args):
        self.module_logger.warning(log_contents, *args)
        print(log_contents)

module_logger = logging.getLogger(__name__)
logger = ELog(module_logger)
log = logging.getLogger(__name__)


class AllInOneUsedCMD(object):

    @staticmethod
    def reboot():
        try:
            logger.warning('Start boot system.')
            subprocess.call("reboot")
        except:
            logger.error('Exception occured when reboot system, EXCEPTION: %s', sys.exc_traceback)

    @staticmethod
    def rabbitmq_changed_pwd():
        logger.info('start change rabbitmq pwd.')
        cmd = 'rabbitmqctl change_password guest openstack'

        try:
            result = subprocess.call(cmd.split(' '))

            if result == 0:
                logger.info('Change rabbitmq pwd success.')
            else:
                logger.error('Change rabbitmq pwd failed. error code is: %s' % result)
        except:
            logger.error('When change rabbitmq pwd exception occured, Exception: %s' % sys.exc_traceback)

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
        return AllInOneUsedCMD.excute_cmd('cp', source, str_destiny)

    @staticmethod
    def mkdir(dir):
        AllInOneUsedCMD.excute_cmd('mkdir', '-p', dir)

    @staticmethod
    def cp_f_to(source, str_destiny):
        try:
            cmd = 'cp -f %s %s' % (source, str_destiny)
            logger.info('copy CMD: %s' % cmd)
            result = subprocess.call(cmd.split(' '))
            if result == 0:
                logger.info('SUCCESS to copy %s to %s' % (source, str_destiny))
                return True
            else:
                logger.info('FAIL to copy %s to %s, result is: %s' % (source, str_destiny, result))
                return False
        except:
            logger.error('Exception occur when copy %s to %s, Exception: %s' %(source, str_destiny, traceback.format_exc()))
            return False

def get_engineering_s_path():
    return os.path.split(os.path.realpath(__file__))[0]

def get_hybrid_cloud_badam_parent_path():
    return os.path.sep.join(os.path.realpath(__file__).split(os.path.sep)[:-3])

def get_hybrid_cloud_badam_path():
    return os.path.sep.join(os.path.realpath(__file__).split(os.path.sep)[:-2])

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
        if files == []:
            continue
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
    paths = [path for path in sys.path if 'dist-packages' in path and 'local' not in path]
    if not paths:
        return None
    else:
        openstack_installed_path = paths[0]
        logger.info('openstack_installed_path: %s' % openstack_installed_path)
        return openstack_installed_path

def print_log(log_contents, log_level):
    if log_level == logging.WARNING:
        module_logger.warning(log_contents)
        print(log_contents)
    elif log_level == logging.ERROR:
        module_logger.error(log_contents)
        print(log_contents)
    else:
        module_logger.info(log_contents)
        print(log_contents)

if __name__ == '__main__':
    patch_path = 'hybrid_tricrile/nova/nova_patch/'
    print get_hybrid_cloud_badam_parent_path()
    print os.path.normpath(os.path.join(get_hybrid_cloud_badam_parent_path(), patch_path))