#!/usr/bin/env python
#-*-coding:utf-8-*-
import logging

#初始化阶段设定的默认值，目前只支持中文和英文
import traceback
from print_msg_fs_index_constant import fsLanguageIndexConstant

LANGUAGE_CN = "CN"
LANGUAGE_EN = "EN"

#全局变量，设定的中英文模式
LANGUAGE_MODE = LANGUAGE_EN

#中英文对照表
#a section
HELLO = ["hello", "你好"]
TEST = ["test", "测试"]

INTERNAL_ERROR = ["Internal error,please Contact maintenance person!", "发生未知错误！"]
LOG = logging.getLogger(__name__)

COLOUR = "\033[1;31m%s\033[0m"

class PrintMessage():
    """
    打印信息到屏幕，支持国际化。
    """
    def __int__(self):
        pass

    @staticmethod
    def set_language_mode(mode):
        """
        设置打印的语言。初始化时设置，默认为英文。
        @param mode:CN：中文，EN:英文
        """
        global LANGUAGE_MODE
        if mode == LANGUAGE_CN:
            LANGUAGE_MODE = LANGUAGE_CN
        elif mode == LANGUAGE_EN:
            LANGUAGE_MODE = LANGUAGE_EN
        else:
            LOG.info("mode doesn't exist.mode is %s." % mode)
            print "mode doesn't exist.mode is %s." % mode

    @staticmethod
    def print_msg(msg, error=False):
        """
        打印信息。
        @param msg：例如["hello", "你好"]
        """
        if not error:
            try:
                if LANGUAGE_MODE == LANGUAGE_CN:
                    print msg[1]
                elif LANGUAGE_MODE == LANGUAGE_EN:
                    print msg[0]
                else:
                    LOG.error("mode error.mode is %s." % LANGUAGE_MODE)
                    print COLOUR % INTERNAL_ERROR
            except Exception:
                LOG.error("print_msg error.error is %s." % traceback.format_exc())
                print COLOUR % INTERNAL_ERROR
        else:
            try:
                if LANGUAGE_MODE == LANGUAGE_CN:
                    print COLOUR % msg[1]
                elif LANGUAGE_MODE == LANGUAGE_EN:
                    print COLOUR % msg[0]
                else:
                    LOG.error("mode error.mode is %s." % LANGUAGE_MODE)
                    print COLOUR % INTERNAL_ERROR
            except Exception:
                LOG.error("print_msg error.error is %s." % traceback.format_exc())
                print COLOUR % INTERNAL_ERROR


    @staticmethod
    def get_msg(msg):
        """
            打印信息。
            @param msg：例如["hello", "你好"]
            """
        try:
            if LANGUAGE_MODE == LANGUAGE_CN:
                return msg[1]
            elif LANGUAGE_MODE == LANGUAGE_EN:
                return msg[0]
            else:
                LOG.error("mode error.mode is %s." % LANGUAGE_MODE)
                return INTERNAL_ERROR
        except Exception:
            LOG.error("get_msg error.error is %s." % traceback.format_exc())
            return INTERNAL_ERROR


    @staticmethod
    def print_msg_ex(msg_const, msg_value, error=False):
        """
            打印信息。
            @param msg_const:写在常量中的信息，例如["hello：%s,%s", "你好:%s,%s"]
            @param msg_value:扩展的值，例如（"wj","yzc"）
            @return:最后打印的值，如英文状态则打印"hello:wj,yzc".
            """
        if not error:
            try:
                if LANGUAGE_MODE == LANGUAGE_CN:
                    print msg_const[1] % msg_value
                elif LANGUAGE_MODE == LANGUAGE_EN:
                    print msg_const[0] % msg_value
                else:
                    LOG.error("mode error.mode is %s." % LANGUAGE_MODE)
                    print COLOUR % INTERNAL_ERROR
            except Exception:
                LOG.error("print_msg_ex error.error is %s." % traceback.format_exc())
                print COLOUR % INTERNAL_ERROR
        else:
            try:
                if LANGUAGE_MODE == LANGUAGE_CN:
                    print COLOUR % (msg_const[1] % msg_value)
                elif LANGUAGE_MODE == LANGUAGE_EN:
                    print COLOUR % (msg_const[0] % msg_value)
                else:
                    LOG.error("mode error.mode is %s." % LANGUAGE_MODE)
                    print COLOUR % INTERNAL_ERROR
            except Exception:
                LOG.error("print_msg_ex error.error is %s." % traceback.format_exc())
                print COLOUR % INTERNAL_ERROR


    @staticmethod
    def get_msg_ex(msg_const, msg_value):
        try:
            if LANGUAGE_MODE == LANGUAGE_CN:
                return msg_const[1] % msg_value
            elif LANGUAGE_MODE == LANGUAGE_EN:
                return msg_const[0] % msg_value
            else:
                LOG.error("mode error.mode is %s." % LANGUAGE_MODE)
                return INTERNAL_ERROR
        except Exception:
            LOG.error("print_msg_ex error.error is %s." % traceback.format_exc())
            return INTERNAL_ERROR


    @staticmethod
    def print_msg_by_index_ex(index, msg_value):
        if LANGUAGE_MODE != LANGUAGE_CN and LANGUAGE_MODE != LANGUAGE_EN:
            print INTERNAL_ERROR
            return

        try:
            message = fsLanguageIndexConstant.languageMap[index][LANGUAGE_MODE]
            print message % msg_value
        except Exception:
            logging.error("print_msg_ex error.error is %s." % traceback.format_exc())
            print INTERNAL_ERROR


    @staticmethod
    def print_msg_by_index(index):
        if LANGUAGE_MODE != LANGUAGE_CN and LANGUAGE_MODE != LANGUAGE_EN:
            print INTERNAL_ERROR

        print fsLanguageIndexConstant.languageMap[index][LANGUAGE_MODE]


    @staticmethod
    def get_msg_by_index_ex(index, msg_value):
        """
            打印信息。
            @param msg：例如["hello", "你好"]
            """
        if LANGUAGE_MODE != LANGUAGE_CN and LANGUAGE_MODE != LANGUAGE_EN:
            return INTERNAL_ERROR
        try:
            return fsLanguageIndexConstant.languageMap[index][LANGUAGE_MODE] % msg_value
        except Exception:
            LOG.error("print_msg_ex error.error is %s." % traceback.format_exc())
            logging.error(traceback.format_exc())
            return INTERNAL_ERROR


    @staticmethod
    def get_msg_by_index(index):
        if LANGUAGE_MODE != LANGUAGE_CN and LANGUAGE_MODE != LANGUAGE_EN:
            return INTERNAL_ERROR

        return fsLanguageIndexConstant.languageMap[index][LANGUAGE_MODE]
