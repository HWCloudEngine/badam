# Copyright 2011 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
A utils module to use vcenterapi
"""

import re
import contextlib

from oslo.config import cfg
from oslo.vmware import api
from oslo.vmware import vim
import suds

from nova import exception
from nova import utils
from nova.i18n import _, _LI, _LW
from nova.openstack.common import jsonutils
from nova.openstack.common import log as logging
from nova.openstack.common import uuidutils
from nova.virt import driver
from nova.virt.vcloudapi import network_utils

LOG = logging.getLogger(__name__)

vcenterapi_opts = [
    cfg.StrOpt('vcenter_host_ip',
               help='Hostname or IP address for connection to VMware VC '
               'host.'),
    cfg.IntOpt('vcenter_host_port',
               default=443,
               help='Port for connection to VMware VC host.'),
    cfg.StrOpt('vcenter_host_username',
               help='Username for connection to VMware VC host.'),
    cfg.StrOpt('vcenter_host_password',
               help='Password for connection to VMware VC host.',
               secret=True),
    cfg.FloatOpt('task_poll_interval',
                 default=0.5,
                 help='The interval used for polling of remote tasks.'),
    cfg.IntOpt('api_retry_count',
               default=10,
               help='The number of times we retry on failures, e.g., '
               'socket error, etc.'),
    cfg.StrOpt('wsdl_location',
               help='Optional VIM Service WSDL Location '
               'e.g http://<server>/vimService.wsdl. '
               'Optional over-ride to default location for bug '
               'work-arounds')
]

spbm_opts = [
    cfg.BoolOpt('pbm_enabled',
                default=False,
                help='The PBM status.'),
    cfg.StrOpt('pbm_wsdl_location',
               help='PBM service WSDL file location URL. '
               'e.g. file:///opt/SDK/spbm/wsdl/pbmService.wsdl '
               'Not setting this will disable storage policy based '
               'placement of instances.'),
    cfg.StrOpt('pbm_default_policy',
               help='The PBM default policy. If pbm_wsdl_location is set and '
               'there is no defined storage policy for the specific '
               'request then this policy will be used.'),
]

CONF = cfg.CONF
CONF.register_opts(vcenterapi_opts, 'vcenter')
CONF.register_opts(spbm_opts, 'vcenter')

TIME_BETWEEN_API_CALL_RETRIES = 1.0


class VCenterAPI(object):

    def __init__(self, scheme="https"):
        super(VCenterAPI, self).__init__()

        if (CONF.vcenter.vcenter_host_ip is None or
                CONF.vcenter.vcenter_host_username is None or
                CONF.vcenter.vcenter_host_password is None):
            raise Exception(_("Must specify vcenter_host_ip,"
                              "vcenter_host_username and vcenter_host_password"
                              "to use venterapi"))

        self._session = VCenterAPISession(scheme=scheme)

    def get_dvs_and_vlanid_with_pgname_alias(self, alias_name):
        return network_utils.get_pg_with_name_alias(
            self._session, alias_name)

    def get_dvs_with_dvsname(self, dvs_name):
        return network_utils.get_dvs_with_name(
            self._session, dvs_name)


class VCenterAPISession(api.VMwareAPISession):

    """Sets up a session with the VC host and handles all
    the calls made to the host.
    """

    def __init__(self, host_ip=CONF.vcenter.vcenter_host_ip,
                 host_port=CONF.vcenter.vcenter_host_port,
                 username=CONF.vcenter.vcenter_host_username,
                 password=CONF.vcenter.vcenter_host_password,
                 retry_count=CONF.vcenter.api_retry_count,
                 scheme="https"):
        super(VCenterAPISession, self).__init__(
            host=host_ip,
            port=host_port,
            server_username=username,
            server_password=password,
            api_retry_count=retry_count,
            task_poll_interval=CONF.vcenter.task_poll_interval,
            scheme=scheme,
            create_session=True,
            wsdl_loc=CONF.vcenter.wsdl_location
        )

    def _is_vim_object(self, module):
        """Check if the module is a VIM Object instance."""
        return isinstance(module, vim.Vim)

    def _call_method(self, module, method, *args, **kwargs):
        """Calls a method within the module specified with
        args provided.
        """
        if not self._is_vim_object(module):
            return self.invoke_api(module, method, self.vim, *args, **kwargs)
        else:
            return self.invoke_api(module, method, *args, **kwargs)

    def _wait_for_task(self, task_ref):
        """Return a Deferred that will give the result of the given task.
        The task is polled until it completes.
        """
        return self.wait_for_task(task_ref)
