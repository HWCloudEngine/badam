#!/usr/bin/env python
# -*-coding:utf-8-*-

__author__ = 'luqitao'

import os
from os.path import join
import shlex
import signal
from eventlet.green import subprocess
from eventlet import greenthread

from install_tool import fs_log_util

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = join(CURRENT_PATH, 'hybrid_patches_tool.log')
LOG = fs_log_util.localLog.get_logger(LOG_FILE)


def _subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

def subprocess_popen(args, stdin=None, stdout=None, stderr=None, shell=False,
                     env=None):
    return subprocess.Popen(args, shell=shell, stdin=stdin, stdout=stdout,
                            stderr=stderr, preexec_fn=_subprocess_setup,
                            close_fds=True, env=env)


def create_process(cmd, root_helper=None, addl_env=None):
    """Create a process object for the given command.

    The return value will be a tuple of the process object and the
    list of command arguments used to create it.
    """
    if root_helper:
        cmd = shlex.split(root_helper) + cmd
    cmd = map(str, cmd)

    LOG.debug("Running command: %s" % cmd)
    env = os.environ.copy()
    if addl_env:
        env.update(addl_env)

    obj = subprocess_popen(cmd, shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=env)

    return obj, cmd

def execute(cmd, root_helper=None, process_input=None, addl_env=None,
            check_exit_code=True, return_stderr=False, log_fail_as_error=True,
            extra_ok_codes=None):
    try:
        obj, cmd = create_process(cmd, root_helper=root_helper,
                                  addl_env=addl_env)
        _stdout, _stderr = (process_input and
                            obj.communicate(process_input) or
                            obj.communicate())
        obj.stdin.close()
        m = "\nCommand: %s\nExit code: %s\nStdout: %r\n, Stderr: %r" % (cmd, obj.returncode, _stdout,  _stderr)

        extra_ok_codes = extra_ok_codes or []
        if obj.returncode and obj.returncode in extra_ok_codes:
            obj.returncode = None

        if obj.returncode and log_fail_as_error:
            LOG.error(m)
        else:
            LOG.debug(m)

        if obj.returncode and check_exit_code:
            raise RuntimeError(m)
    finally:
        # NOTE(termie): this appears to be necessary to let the subprocess
        #               call clean something up in between calls, without
        #               it two execute calls in a row hangs the second one
        greenthread.sleep(0)

    return return_stderr and (_stdout, _stderr) or _stdout

