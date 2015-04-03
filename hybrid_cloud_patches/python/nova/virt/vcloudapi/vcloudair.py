# VMware vCloud Python helper
# Copyright (c) 2014 Huawei, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at #
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from nova import exception
from oslo.config import cfg
from oslo.vmware.common import loopingcall
from oslo.utils import excutils
from nova.openstack.common import log as logging
from nova.i18n import _, _LI, _LW
import time
import base64
import requests
from StringIO import StringIO
import json
from xml.etree import ElementTree as ET
from pyvcloud.schema.vcd.v1_5.schemas.admin import vCloudEntities
from pyvcloud.schema.vcd.v1_5.schemas.vcloud import vAppType, \
    organizationListType, vdcType, catalogType, queryRecordViewType, \
    networkType, vcloudType, taskType
from pyvcloud.vcloudsession import VCS
from pyvcloud.gateway import Gateway
from pyvcloud.schema.vcim import serviceType, vchsType
from pyvcloud.helper import CommonUtils
from pyvcloud.schema.vcd.v1_5.schemas.vcloud.networkType import IpScopeType,\
    OrgVdcNetworkType, ReferenceType, NetworkConfigurationType, \
    IpScopesType, IpRangesType, IpRangeType, DhcpPoolServiceType
from pyvcloud.score import Score
from pyvcloud.vcloudair import VCA as sdk_vca
from pyvcloud.vapp import VAPP as sdk_vapp

LOG = logging.getLogger(__name__)


class VCA(sdk_vca):

    """
    Packaged Vmware vcloud python sdk vca.
    Vclouddriver just use func here.
    """

    def __init__(self, host, username, service_type='ondemand',
                 version='5.5', verify=True):

        super(VCA, self).__init__(
            host,
            username,
            service_type=service_type,
            version=version,
            verify=verify
        )

    def create_isolated_vdc_network(self, vdc_name, network_name, gateway_name,
                                    start_address, end_address, gateway_ip,
                                    netmask, dns1=None, dns2=None,
                                    dns_suffix=None):
        vdc = self.get_vdc(vdc_name)
        iprange = IpRangeType(StartAddress=start_address,
                              EndAddress=end_address)
        ipranges = IpRangesType(IpRange=[iprange])
        ipscope = IpScopeType(IsInherited=False,
                              Gateway=gateway_ip,
                              Netmask=netmask,
                              Dns1=dns1,
                              Dns2=dns2,
                              DnsSuffix=dns_suffix,
                              IpRanges=ipranges)
        ipscopes = IpScopesType(IpScope=[ipscope])

        configuration = NetworkConfigurationType(IpScopes=ipscopes,
                                                 FenceMode="isolated")
        net = OrgVdcNetworkType(name=network_name,
                                Description="Network created name is " +
                                network_name,
                                EdgeGateway=None, Configuration=configuration,
                                IsShared=False)
        namespacedef = 'xmlns="http://www.vmware.com/vcloud/v1.5"'
        content_type = "application/vnd.vmware.vcloud.orgVdcNetwork+xml"
        body = '<?xml version="1.0" encoding="UTF-8"?>{0}'.format(
            CommonUtils.convertPythonObjToStr(net, name='OrgVdcNetwork',
                                              namespacedef=namespacedef))
        postlink = filter(lambda link: link.get_type() == content_type,
                          vdc.get_Link())[0].href
        headers = self.vcloud_session.get_vcloud_headers()
        headers["Content-Type"] = content_type
        response = requests.post(
            postlink,
            data=body,
            headers=headers,
            verify=self.verify)

        if response.status_code == requests.codes.forbidden:
            raise exception.Forbidden("Create_isolated_vdc_network error, " +
                                      "network_name:" + network_name)
        if response.status_code == requests.codes.created:
            network = networkType.parseString(response.content, True)
            task = network.get_Tasks().get_Task()[0]
            return (True, task)
        else:
            return (False, response.content)

    def delete_isolated_vdc_network(self, vdc_name, network_name):
        netref = self.get_isolated_network_href(vdc_name, network_name)
        if netref is None:
            return (True, None)
        response = requests.delete(
            netref,
            headers=self.vcloud_session.get_vcloud_headers(),
            verify=self.verify)

        if response.status_code == requests.codes.forbidden:
            raise exception.Forbidden("Delete_isolated_vdc_network error, " +
                                      "network_name:" + network_name)
        if response.status_code == requests.codes.accepted:
            task = taskType.parseString(response.content, True)
            return (True, task)
        else:
            return (False, response.content)

    def get_task_result(self, task):
        """
        Wait the task finished, and return the result
        """
        headers = self.vcloud_session.get_vcloud_headers()
        headers["Content-Type"] = "application/vnd.vmware.vcloud.task+xml"
        response = requests.get(task.href, headers=headers, verify=self.verify)
        if response.status_code == requests.codes.forbidden:
            raise exception.Forbidden("Create_isolated_vdc_network error, " +
                                      "network_name:" + network_name)
        if response.status_code == requests.codes.ok:
            doc = self.parsexml_(response.content)
            return doc.attrib
        return {'status': "Error"}

    def get_isolated_network_href(self, vdc_name, network_name):
        vdc = self.get_vdc(vdc_name)
        link = filter(lambda link: link.get_rel() == "orgVdcNetworks",
                      vdc.get_Link())
        response = requests.get(
            link[0].get_href(),
            headers=self.vcloud_session.get_vcloud_headers(),
            verify=self.verify)
        queryResultRecords = queryRecordViewType.parseString(response.content,
                                                             True)
        if response.status_code == requests.codes.forbidden:
            raise exception.Forbidden("Get_isolated_network_href error, " +
                                      "network_name:" + network_name)
        if response.status_code == requests.codes.ok:
            for record in queryResultRecords.get_Record():
                if record.name == network_name:
                    return record.href
        elif response.status_code == requests.codes.forbidden:
            raise exception.Forbidden("Get_isolated_network_href forbidden, " +
                                      "network_name:" + network_name)
        else:
            raise exception.NovaException("Get_isolated_network_href error, " +
                                          " response:" + response)

    def get_vdc(self, vdc_name):
        if self.vcloud_session and self.vcloud_session.organization:
            refs = filter(lambda ref: ref.name == vdc_name and ref.type_ ==
                          'application/vnd.vmware.vcloud.vdc+xml',
                          self.vcloud_session.organization.Link)
            if len(refs) == 1:
                self.response = requests.get(
                    refs[0].href,
                    headers=self.vcloud_session.get_vcloud_headers(),
                    verify=self.verify)
                if self.response.status_code == requests.codes.ok:
                    # print self.response.content
                    return vdcType.parseString(self.response.content, True)
            elif response.status_code == requests.codes.forbidden:
                raise exception.Forbidden("Get_vdc forbidden, " +
                                          "vdc_name:" + vdc_name)
            else:
                raise exception.NovaException("Get_vdc error, " +
                                              "response:" + response)

    def session_is_active(self):
        """If session is not active, this will return false, else
        will return true"""
        return self.login(
            token=self.vcloud_session.token,
            org=self.vcloud_session.org,
            org_url=self.vcloud_session.org_url)

    def __str__(self):
        return "VCA Object"

    # def get_vapp_referenced_file_url(self, vapp):
    #     # 1.enable download.
    #     resp = vapp.enableDownload()
    #
    #     # 2.get vapp info and ovf descriptor
    #     vapp = vapp.get_updated_vapp()
    #     ovf = vapp.get_ovf_descriptor()
    #
    #     # 3.download ovf descriptor and get referenced file url
    #     referenced_file_url = vapp.get_referenced_file_url(ovf)
    #
    #     return referenced_file_url

    def get_vapp(self, vdc, vapp_name):

        vapp = super(VCA, self).get_vapp(vdc,vapp_name)
        return  VAPP(vapp.me,vapp.headers,vapp.verify)


class VAPP(sdk_vapp):

    def __init__(self, vApp, headers, verify):
        super(VAPP, self).__init__(vApp, headers, verify)


    def enableDownload(self):
        headers = self.headers
        url = '%s/action/enableDownload' % self.me.get_href()
        self.response = requests.post(url,data = {}, headers=headers, verify=self.verify)
        if self.response.status_code == requests.codes.accepted:
             return taskType.parseString(self.response.content, True)
        else:
            return False

    def get_ovf_descriptor(self):
        link = filter(lambda link: link.get_rel() == 'download:default', self.me.get_Link())
        if not link:
            print "Can Not get download url"
            return

        headers = self.headers
        url = link[0].get_href()
        self.response = requests.get(url, headers=headers, verify=self.verify)
        if self.response.status_code == requests.codes.ok:
             return vAppType.parseString(self.response.content, True)
        else:
            return False


    def get_referenced_file_url(self, ovf):

        link = filter(lambda link: link.get_rel() == 'download:default', self.me.get_Link())
        if not link:
            print "Can Not get download url"
            return

        ref_file_id = ovf.References.File[0].anyAttributes_['{http://schemas.dmtf.org/ovf/envelope/1}href']
        url = link[0].get_href()
        url = url.replace('descriptor.ovf',ref_file_id)
        return url

    # def get_updated_vapp(self):
    #     headers = self.headers
    #     url = self.me.get_href()
    #     self.response = requests.get(url, headers=headers, verify=self.verify)
    #     if self.response.status_code == requests.codes.ok:
    #         vapp = VAPP(vAppType.parseString(self.response.content, True), headers, self.verify)
    #         return vapp
    #     else:
    #         return False


class VCloudAPISession(object):

    """Sets up a session with the vcloud and handles all
    the calls made to the vcloud.
    """

    def __init__(self, host_ip, host_port, server_username, server_password,
                 org, vdc, version, service, verify, service_type,
                 retry_count, create_session=True, scheme="https",
                 task_poll_interval=1):
        self._host_ip = host_ip
        self._server_username = server_username
        self._server_password = server_password
        self._org = org
        self._vdc = vdc
        self._version = version
        self._verify = verify
        self._service_type = service_type
        self._retry_count = retry_count
        self._scheme = scheme
        self._host_port = host_port
        self._session_username = None
        self._session_id = None
        self._vca = None
        self._task_poll_interval = task_poll_interval
        if create_session:
            self._create_session()

    def _create_session(self):
        """Establish session with the server."""
        # Another thread might have created the session while the current one
        # was waiting for the lock.
        if self._session_id and self.is_current_session_active():
            LOG.debug("Current session: %s is active.",
                      self._session_id)
            return

        # Login and create new session with the server for making API calls.
        LOG.debug("Logging in with username = %s.", self._server_username)
        result = self.vca.login(password=self._server_password, org=self._org)
        if not result:
            raise exception.NovaException(
                "Logging error with username = " +
                self._server_username)
        result = self.vca.login(
            token=self.vca.token,
            org=self._org,
            org_url=self.vca.vcloud_session.org_url)
        if not result:
            raise exception.NovaException(
                "Logging error with username = " +
                self._server_username)

        self._session_id = self.vca.token

        # We need to save the username in the session since we may need it
        # later to check active session. The SessionIsActive method requires
        # the username parameter to be exactly same as that in the session
        # object. We can't use the username used for login since the Login
        # method ignores the case.
        self._session_username = self.vca.username
        LOG.info("Successfully established new session; session ID is "
                 "%s.",
                 self._session_id)

    def is_current_session_active(self):
        """Check if current session is active.

        :returns: True if the session is active; False otherwise
        """
        LOG.debug("Checking if the current session: %s is active.",
                  self._session_id)

        is_active = False
        # check is active
        try:
            is_active = self.vca.session_is_active()
        except exception.NovaException:
            LOG.error("Check session is active error %s.",
                      self._session_id)

        return is_active

    def invoke_api(self, module, method, *args, **kwargs):
        """Wrapper method for invoking APIs.

        The API call is retried in the event of exceptions due to session
        overload or connection problems.

        :param module: module corresponding to the VCA API call
        :param method: method in the module which corresponds to the
                       VCA API call
        :param args: arguments to the method
        :param kwargs: keyword arguments to the method
        :returns: response from the API call
        :raises: NovaException
        """

        def _invoke_api(module, method, *args, **kwargs):
            try:
                api_method = getattr(module, method)
                return api_method(*args, **kwargs)
            except exception.Forbidden as excep:
                # If this is due to an inactive session, we should re-create
                # the session and retry.
                LOG.debug("Returning empty response for "
                          "%(module)s.%(method)s invocation.",
                          {'module': module,
                           'method': method})
                if not self.is_current_session_active():
                    LOG.warn(_LW("Re-creating session due to connection "
                                 "problems while invoking method "
                                 "%(module)s.%(method)s."),
                             {'module': module,
                              'method': method},
                             exc_info=True)
                    self._create_session()
                raise excep

        return _invoke_api(module, method, *args, **kwargs)

    @property
    def vca(self):
        if not self._vca:
            self._vca = VCA(host=self._host_ip, username=self._server_username,
                            service_type=self._service_type,
                            version=self._version,
                            verify=self._verify)
        return self._vca

    @property
    def vdc(self):
        return self._vdc

    @property
    def username(self):
        return self._server_username

    @property
    def password(self):
        return self._server_password

    @property
    def host_ip(self):
        return  self._host_ip

    @property
    def host_port(self):
        return self._host_port

    @property
    def org(self):
        return self._org

    def wait_for_task(self, task):
        """Waits for the given task to complete and returns the result.

        The task is polled until it is done. The method returns the task
        information upon successful completion. In case of any error,
        appropriate exception is raised.

        :param task: managed object reference of the task
        :returns: task info upon successful completion of the task
        :raises: NovaException
        """
        loop = loopingcall.FixedIntervalLoopingCall(self._poll_task, task)
        evt = loop.start(self._task_poll_interval)
        LOG.debug("Waiting for the task: %s to complete.", task)
        return evt.wait()

    def _poll_task(self, task):
        """Poll the given task until completion.

        If the task completes successfully, the method returns the task info
        using the input event (param done). In case of any error, appropriate
        exception is set in the event.

        :param task: managed object reference of the task
        """
        LOG.debug("Invoking VCA API to read info of task: %s.", task)
        try:
            task_info = self.invoke_api(self.vca, "get_task_result", task)
        except exception.NovaException:
            with excutils.save_and_reraise_exception():
                LOG.exception("Error occurred while reading info of "
                              "task: %s.", task)
        else:
            if task_info['status'] in ['queued', 'running']:
                if hasattr(task_info, 'progress'):
                    LOG.debug("Task: %(task)s progress is %(progress)s%%.",
                              {'task': task,
                               'progress': task_info.progress})
            elif task_info['status'] == 'success':
                LOG.debug("Task: %s status is success.", task)
                raise loopingcall.LoopingCallDone(task_info)
            else:
                raise exception.NovaException(
                    "Task execute failed, task:%s",
                    task)

    def wait_for_lease_ready(self, lease):
        """Waits for the given lease to be ready.

        This method return when the lease is ready. In case of any error,
        appropriate exception is raised.

        :param lease: lease to be checked for
        :raises: NovaException
        """
        pass

    def _get_error_message(self, lease):
        """Get error message associated with the given lease."""
        return "Unknown"
