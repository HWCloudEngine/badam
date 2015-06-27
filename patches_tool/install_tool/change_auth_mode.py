#!/usr/bin/env python
#coding:utf-8
import fs_log_util
import commands
import os
import ConfigParser
from os.path import join
import fsutils

#日志定义
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


class ChangeAuthMode():

    def __init__(self):
        pass

    def open_close_token(self, flag, token=None):
        if flag is not True and token is None:
            LOG.error("the token is none,flag:%s." % flag)
            return False

        result = self._modify_auth_mode(flag, token)
        if not result:
            LOG.error("call _modify_auth_mode failed, result:%s." % result)
            return result
        result = self.modify_cps_auth_mode(flag, token)
        if not result:
            LOG.error("call _modify_cps_auth_mode failed, result:%s." % result)
            return result
        result = self.commit(flag, token)
        if not result:
            LOG.error("call _commit failed, result:%s." % result)
            return result
        return True

    def modify_cps_server_auth_mode(self, flag, token):
        if flag is True:
            cmd = "cps template-params-update --service %s %s --parameter auth_mode=%s"
        else:
            cmd = "cps template-params-update --service %s %s --parameter auth_mode=%s --os-token " + token
        status, output = commands.getstatusoutput(cmd % ("cps", "cps-client", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("cps", "cps-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        return True

    def _modify_auth_mode(self, flag, token):
        if flag is True:
            cmd = "cps template-params-update --service %s %s --parameter auth_mode=%s"
        else:
            cmd = "cps template-params-update --service %s %s --parameter auth_mode=%s --os-token " + token

        status, output = commands.getstatusoutput(cmd % ("ceilometer", "ceilometer-agent-hardware", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        status, output = commands.getstatusoutput(cmd % ("collect", "info-collect-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("upg", "upg-client", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("upg", "upg-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("log", "log-agent", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("log", "log-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("cps", "network-client", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("cps", "network-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("backup", "backup-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("backup", "backup-client", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("ntp", "ntp-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("ntp", "ntp-client", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        result = self.modify_cps_server_auth_mode(flag, token)
        if not result:
            return False

        return True

    def modify_cps_auth_mode(self, flag, token):
        if flag is True:
            cmd = "cps template-params-update --service %s %s --parameter cps_auth_mode=%s"
        else:
            cmd = "cps template-params-update --service %s %s --parameter cps_auth_mode=%s --os-token " + token

        status, output = commands.getstatusoutput(cmd % ("cps", "network-client", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("cps", "network-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        status, output = commands.getstatusoutput(cmd % ("collect", "info-collect-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("collect", "info-collect-client", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        status, output = commands.getstatusoutput(cmd % ("ceilometer", "ceilometer-agent-central", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        status, output = commands.getstatusoutput(cmd % ("gaussdb", "gaussdb", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        status, output = commands.getstatusoutput(cmd % ("mongodb", "mongodb", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
    
        status, output = commands.getstatusoutput(cmd % ("fusionnetwork", "oam-network-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        return True

    def _modify_neutron_auth_mode(self, flag, token):
        if flag is True:
            cmd = "cps template-params-update --service %s %s --parameter neutron_auth_mode=%s"
        else:
            cmd = "cps template-params-update --service %s %s --parameter neutron_auth_mode=%s --os-token " + token

        status, output = commands.getstatusoutput(cmd % ("cps", "network-client", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False
        status, output = commands.getstatusoutput(cmd % ("cps", "network-server", flag))
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        return True

    def commit(self, flag, token):
        cmd = None
        if flag is True:
            cmd = "cps commit"
        else:
            cmd = "cps commit --os-token %s" % token

        status, output = commands.getstatusoutput(cmd)
        if status != 0:
            LOG.error("call cps template-params-update failed, detail:%s, output:%s." % (flag, fsutils.get_safe_message(output)))
            return False

        return True

    def is_auth_mode(self):
        # for test luqitao
        return False

        conf_file = "/usr/local/bin/cps-client/cps_client/cps_client.ini"
        conf = ConfigParser.RawConfigParser()
        conf.read(conf_file)
        auth_mode = conf.get("cpsclient", "auth_mode")

        if auth_mode.upper() != "TRUE":
            return "n"
        else:
            return "y"

    def is_https(self):
        # for test luqitao
        return True

        conf_file = "/usr/local/bin/cps-client/cps_client/cps_client.ini"
        conf = ConfigParser.RawConfigParser()
        conf.read(conf_file)
        auth_mode = conf.get("cpsclient", "use_ssl")

        if auth_mode.upper() != "TRUE":
            return False
        else:
            return True
