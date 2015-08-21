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
Utility functions for vcenter Networking.
"""
from oslo.vmware import exceptions as vexc

from nova import exception
from nova.i18n import _
from nova.openstack.common import log as logging
from nova.virt.vcloudapi import vim_util

LOG = logging.getLogger(__name__)


def get_pg_with_name_alias(session, pg_name):
    """
    find the pg with the given pg_name
    get_pg_with_name_alias
    """

    LOG.debug("Get dv Port Group with alias name %s ", pg_name)
    pg_ref = _get_dvpg_ref_from_name(session, pg_name)
    if pg_ref is not None:
        pg = session._call_method(vim_util,
                                  "get_dynamic_properties", pg_ref,
                                  "DistributedVirtualPortgroup",
                                  ["config.defaultPortConfig",
                                   "config.distributedVirtualSwitch"])
        dvs = session._call_method(vim_util,
                                   "get_dynamic_property", pg[
                                       "config.distributedVirtualSwitch"],
                                   "DistributedVirtualSwitch", "config.name")
        return pg["config.defaultPortConfig"].vlan.vlanId, dvs
    return None, None


def get_dvs_with_name(session, dvs_name):
    """get_dvs_with_name from vcenter"""
    LOG.debug("Get dvs with name %s ", dvs_name)
    return _get_dvs_ref_from_name(session, dvs_name)


def _get_dvs_ref_from_name(session, dvs_name):
    """Get reference to the dvs with the name specified."""
    dvs = session._call_method(vim_util, "get_objects",
                               "DistributedVirtualSwitch", ["name"])
    return _get_object_from_results(session, dvs, dvs_name,
                                    _get_object_for_value)


def _get_token(results):
    """Get the token from the property results."""
    return getattr(results, 'token', None)


def _get_dvpg_ref_from_name(session, pg_name):
    """Get reference to the dvpg with the name specified."""
    pgs = session._call_method(vim_util, "get_objects",
                               "DistributedVirtualPortgroup", ["name"])
    return _get_object_from_results(session, pgs, pg_name,
                                    _get_object_contains_value)


def _get_object_for_value(results, value):
    for object in results.objects:
        if object.propSet[0].val == value:
            return object.obj


def _get_object_contains_value(results, value):
    for object in results.objects:
        if value in object.propSet[0].val:
            return object.obj


def _get_object_from_results(session, results, value, func):
    while results:
        token = _get_token(results)
        object = func(results, value)
        if object:
            if token:
                session._call_method(vim_util,
                                     "cancel_retrieve",
                                     token)
            return object

        if token:
            results = session._call_method(vim_util,
                                           "continue_to_get_objects",
                                           token)
        else:
            return None
