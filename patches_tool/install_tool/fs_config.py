#!/usr/bin/python
# coding:utf-8
"""
Command-line interface to deploy FusionSphere.
"""
import ConfigParser
import commands
import os
import sys
import traceback
from fs_keystone_server import PasswordException
import fs_log_util
import fs_modes
import print_msg
from print_msg import PrintMessage as PrintUtil
import fsutils as utils
from os.path import join
import fsinstall
import fs_system_server
#***************section_map******************

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'fsinstall.log')
SECTION_NAME = "name"
SECTION_INSTANCE = "instance"
SECTION_WORK_ITEMS = "work items"
SECTION_IMPORT = "import"
SECTION_CLASS = "class"
SECTION_NODES = "deploynodes"
FILE_NAME = join(CURRENT_PATH, 'deployEnv.ini')
logger = fs_log_util.localLog.get_logger(LOG_FILE)


class fsConfigParser(ConfigParser.RawConfigParser):
    def write(self, fp):
        """Write an .ini-format representation of the configuration state."""
        if self._defaults:
            fp.write("[%s]\n" % "")
            for (key, value) in self._defaults.items():
                fp.write("%s = %s\n" % (key, str(value).replace('\n', '\n\t')))
            fp.write("\n")
        sections = sorted(self._sections)
        for section in sections:
            fp.write("[%s]\n" % section)
            for (key, value) in self._sections[section].items():
                if key == "__name__":
                    continue
                if (value is not None) or (self._optcre == self.OPTCRE):
                    key = " = ".join((key, str(value).replace('\n', '\n\t')))
                fp.write("%s\n" % (key))
            fp.write("\n")


def print_line():
    print "=============================================================================================================="


def print_welcome():
    print "=============================================Welcome=========================================================="


def print_choose_notice():
    print "[y|n][n] :the input should be y or n, the default is n(just press Enter)."


def input_lanuage():
    while 1:
        print_line()
        print "0) Engligh"
        print "1) Chinese "
        inputstr = "Please choose lanuage:[0|1][1]"
        lan = raw_input(inputstr)
        if lan == "0":
            PrintUtil.set_language_mode(print_msg.LANGUAGE_EN)
        elif lan == "" or lan == "1":
            print "You should set code format to UTF-8 for Chinese"
            PrintUtil.set_language_mode(print_msg.LANGUAGE_CN)

        if lan == "0" or lan == "1" or lan == "":
            flag = 1
            while 1:
                print_line()
                PrintUtil.print_msg(["0)Continue", "0)继续"])
                PrintUtil.print_msg(["1)Cancle", "1)取消"])
                inputstr = PrintUtil.get_msg(["You choose Engligh![0|1][1]", "您选择了中文！[0|1][1]"])
                flag = raw_input(inputstr)
                if flag == "":
                    flag = "1"
                if flag == "1" or flag == "0":
                    break
                else:
                    PrintUtil.print_msg(
                        ["Please choose correct character, support \"0\" or \"1\"", "输入非法，请输入\"0\"或者\"1\""])

            if flag == "0":
                break
        else:
            print "Please choose correct character, support \"0\" or \"1\""

    if lan == "0":
        lan_mod = print_msg.LANGUAGE_EN
    else:
        lan_mod = print_msg.LANGUAGE_CN
    print_msg.PrintMessage.set_language_mode(lan_mod)


def runCommand(cmd):
    try:
        (status, output) = commands.getstatusoutput(cmd)
        logger.info("run cmd :%s,status %s output %s" % (cmd, status, output))
        return status, output
    except Exception, e:
        logger.error(e)
    return 1, output


def get_host_name():
    cmd = "hostname"
    status = 255
    (status, output) = runCommand(cmd)
    if status != 0:
        logger.error("hostname failed! curl:" + cmd + ' output=' + output)
        sys.exit(1)
    return output


def split_str_to_list(input_name):
    ret_list = []
    ret_list_tmp = input_name.split(',')
    for str_tmp in ret_list_tmp:
        ret_list.append(str_tmp.strip())
    return ret_list


def deploy_all_sections(config):
    for k, v in utils.get_section_map().iteritems():
        processer = v[SECTION_INSTANCE]
        if processer is not None:
            try:
                processer.create_def_config(config)
            except Exception, e:
                logger.error("Choose_section failed: %s, k=%s,e=%s." % (traceback.format_exc(), k, e))


def is_deployed():
    if os.path.exists(utils.DEFAULT_FILE_NAME):
        config = fsConfigParser()
        config.read(utils.DEFAULT_FILE_NAME)
        section_list = config.sections()
        for item in section_list:
            if item.find(utils.SECTION_ROLE_DEPLOY) is not -1:
                role_deploy_dict = dict(config.items(item))
                if role_deploy_dict.has_key('is_deployed'):
                    str_is_deployed = role_deploy_dict.get('is_deployed')
                    return str_is_deployed == 'YES'
    return False


def set_deployed():
    config = fsConfigParser()
    config.read(utils.DEFAULT_FILE_NAME)
    config.set(utils.SECTION_ROLE_DEPLOY, 'is_deployed', 'YES')
    with open(utils.DEFAULT_FILE_NAME, 'w') as fd:
        config.write(fd)


def check_config():
    if not utils.is_finished():
        (this_mode, ctrl_hosts) = fs_modes.check_modes()
        if this_mode is None:
            PrintUtil.print_msg(["Please deploy first,then config", "请先部署服务再配置"])
            sys.exit(1)
        else:
            init_files(this_mode, ctrl_hosts)
            return True


def init_files(this_mode, ctrl_hosts):
    print "=============================================================================================================="
    print "Detects that you have deployed."
    #print "You have selected:"
    logger.info("[1] Install mode: %s" % this_mode.get_name())
    logger.info("[2] Manager host list: %s" % str(ctrl_hosts))
    print "This is the first time you enter, so you need to check some information:"
    keystone_domain = fs_system_server.input_keystone_domain()
    glance_domain = fs_system_server.input_glance_domain()
    fsinstall.save_deploy_msg(this_mode.get_name(), ctrl_hosts, keystone_domain, glance_domain)
    utils.set_finish_flag()
    print "Successful initialization!"


def validate_proc(section):
    process = utils.get_section_map()[section][SECTION_INSTANCE]
    section_name = utils.get_section_map()[section][SECTION_NAME]
    if process is not None:
        try:
            process.validate(utils.TYPE_ONLY_CONFIG, "")
        except PasswordException, e:
            logger.error("validate_proc failed e=%s." % e)
            pass
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception, e:
            print "Save %s failed!"%section_name
            logger.error("Choose_section failed: %s, e=%s." % (traceback.format_exc(), e))


def all_section_proc(deploy_type):
    for k, v in utils.get_section_map().iteritems():
        process = v[SECTION_INSTANCE]
        if process is not None:
            process.config(deploy_type)
        else:
            logger.warning("all_section_proc k: %s." % k)


def all_section_validate(deploy_type):
    for k, v in utils.get_section_map().iteritems():
        process = v[SECTION_INSTANCE]
        if process is not None:
            process.validate(deploy_type, "")
        else:
            logger.warning("all_section_validate k: %s." % k)


def one_sec_proc(section, deploy_type):
    section_detail = utils.get_section_map()[section]
    if section_detail is None:
        return False
    process = section_detail[SECTION_INSTANCE]
    section_name = section_detail[SECTION_NAME]
    if process is not None:
        try:
            return process.config(deploy_type)
        except PasswordException:
            #对于密码错误的情况，直接将该异常抛给框架
            return False
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except Exception, e:
            print "Config %s failed!" %section_name
            logger.error("Choose_section failed: %s, e = %s." % (traceback.format_exc(), e))
            return False


def change_config_proc(deploy_type):
    # 用户进行选择配置
    section_name = ""
    while 1:
        try:
            print_line()
            #获取用户修改项
            section = choose_section()
            if 'y' == section :
                return

            logger.info("user come in section:%s" % str(section))
            try:

                section_name = utils.get_section_map()[section][SECTION_NAME]
            except KeyboardInterrupt:
                raise KeyboardInterrupt()
            except:
                logger.error("Choose_section failed: %s" % traceback.format_exc())
                print "HELP! I am in  trouble.please rerun me or connect HUAWEI FSP support staff!"
                return

            flag = one_sec_proc(section, deploy_type)
            #如果用户修改过则需要调用生效接口
            if flag is None or flag is True:
                print 'Start validate'
                validate_proc(section)
                print 'Validate end'
                #重新初始化
                section_map = utils.build_map()
                PrintUtil.print_msg(["No.%s configured.please continue" % section, "第%s项配置已经完成，请继续选择" % section])
        except PasswordException:
            continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt()
        except :
            logger.error("Choose_section failed: %s" % traceback.format_exc())
            print "Save %s failed."%section_name


def choose_section():
    try:
        PrintUtil.print_msg(["Please choose section to config:", "请选择要配置的段:"])
        while 1:
            section_list = []
            k = None
            for k in sorted(utils.get_section_map().iterkeys()):
                v = utils.get_section_map()[k]
                print '[' + k + "] " + v[SECTION_NAME]
                section_list.append(str(k))

            str_cancel = 'q'
            print '[%s] ' % str_cancel + PrintUtil.get_msg(["Quit", "取消"])
            PrintUtil.print_msg(["More advanced config, please refer to the CPS configuration commands to configure",
                                 "更多高级配置功能，请参考CPS配置命令进行配置"])
            input_str = PrintUtil.get_msg(["Please choose", "请选择"]) + " [1-" + k + "|%s][%s]" % (str_cancel, str_cancel)
            section = raw_input(input_str)
            if section == '':
                section = str_cancel
            if section == str_cancel:
                input_str = PrintUtil.get_msg(["Are you sure to quit", "确定退出"]) + "?[y|n][y]"
                tmp = raw_input(input_str)
                if tmp == 'y' or tmp == '':
                    return 'y'
                continue
            elif section in section_list:
                return section
            else:
                print PrintUtil.get_msg(["Please input correct character, only support",
                                         "请输入正确选择，只支持"]) + " [0-" + k + " |%s]!" % str_cancel
    except Exception, e:
        logger.error("Choose_section failed: %s,e=%s" % (traceback.format_exc(), e))


def main():
    try:
        logger.info("come in fs_config")
        #当前只支持配置，暂时将判断放在这里
        check_config()

        #欢迎界面打印
        print_welcome()

        #用户交互界面
        change_config_proc(utils.TYPE_ONLY_CONFIG)
    except Exception as e:
        PrintUtil.get_msg(["HELP! I am in  trouble.please rerun me or connect HUAWEI FSP support staff!",
                           "哎呀，一键部署配置脚本挂掉了，请尝试重新运行或者联系华为 FSP支持人员处理"])
        logger.debug(e, exc_info=1)


if __name__ == "__main__":
    sys.exit(main())
