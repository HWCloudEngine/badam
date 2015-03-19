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
    def cp_to(self, source, destiny):
        try:
            cmd = 'cp %s %s' % (source, destiny)
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

def get_engineering_root_path():
    return os.path.split(os.path.realpath(__file__))[0]

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
                print (os.path.splitext(file))
                if os.path.splitext(file)[1] in filters:
                    file_path = os.path.join(path, file)
                    files_path.append(file_path)
                else:
                    continue

    return files_path