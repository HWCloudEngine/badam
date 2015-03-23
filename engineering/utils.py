__author__ = 'nash.xiejun'

import subprocess
import logging
import sys
import traceback
import os


logger = logging.getLogger(__name__)

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
    def cp_to(source, str_destiny):
        try:
            cmd = 'cp %s %s' % (source, str_destiny)
            result = subprocess.call(cmd.split(' '))
            if result == 0:
                logger.info('SUCCESS to copy %s to %s')
                return True
            else:
                logger.info('FAIL to copy %s to %s')
                return False
        except:
            logger.error('Exception occur when copy %s to %s, Exception: %s', source, destiny, traceback.format_exc())
            return False

def get_engineering_s_path():
    return os.path.split(os.path.realpath(__file__))[0]

def get_hybrid_cloud_badam_parent_path():
    return os.path.sep.join(os.path.realpath(__file__).split(os.path.sep)[:-3])

def get_files(path, filters):
    """

    :param filters: array, specified valid file suffix.
    :return:
    """
    files_path = []
    file_sys_infos = os.walk(path)

    for (path, dirs, files) in file_sys_infos:
        if files == []:
            continue
        else:
            for file in files:
                if os.path.splitext(file)[1] in filters:
                    file_path = os.path.join(path, file)
                    files_path.append(file_path)
                else:
                    continue

    return files_path

def get_openstack_installed_path():
    paths = [path for path in sys.path if 'dist-packages' in path and 'local' not in path]
    if not paths:
        return None
    else:
        return paths[0]

def print_log(log_contents, log_level):
    print(log_contents)
    if log_level == logging.WARNING:
        logger.warning(log_contents)
        print(log_contents)
    elif log_level == logging.ERROR:
        logger.error(log_contents)
        print(log_contents)
    else:
        logger.info(log_contents)
        print(log_contents)

if __name__ == '__main__':
    patch_path = 'hybrid_tricrile/nova/nova_patch/'
    print get_hybrid_cloud_badam_parent_path()
    print os.path.normpath(os.path.join(get_hybrid_cloud_badam_parent_path(), patch_path))