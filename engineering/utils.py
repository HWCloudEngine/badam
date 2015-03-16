__author__ = 'nash.xiejun'

import subprocess
import logging
import sys


logger = logging.getLogger(__name__)

class AllInOneUsedCMD(object):

    @staticmethod
    def reboot():
        try:
            logging.warning('Start boot system.')
            subprocess.call("reboot")
        except:
            logging.error('Exception occured when reboot system, EXCEPTION: %s', sys.exc_traceback)

    @staticmethod
    def rabbitmq_changed_pwd():
        logging.info('start change rabbitmq pwd.')
        cmd = 'rabbitmqctl change_password guest openstack'

        try:
            result = subprocess.call(cmd.split(' '))

            if result == 0:
                logging.info('Change rabbitmq pwd success.')
            else:
                logging.error('Change rabbitmq pwd failed. error code is: %s' % result)
        except:
            logging.error('When change rabbitmq pwd exception occured, Exception: %s' % sys.exc_traceback)
