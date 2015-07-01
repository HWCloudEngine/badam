# Copyright (c) 2015 Huawei, Inc.
# All Rights Reserved.
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
Exception definitions.
"""

import logging

import six

from cinder.i18n import _, _LE, _LW

LOG = logging.getLogger(__name__)

ALREADY_EXISTS = 'AlreadyExists'
CANNOT_DELETE_FILE = 'CannotDeleteFile'
FILE_ALREADY_EXISTS = 'FileAlreadyExists'
FILE_FAULT = 'FileFault'
FILE_LOCKED = 'FileLocked'
FILE_NOT_FOUND = 'FileNotFound'
INVALID_POWER_STATE = 'InvalidPowerState'
INVALID_PROPERTY = 'InvalidProperty'
NO_PERMISSION = 'NoPermission'
NOT_AUTHENTICATED = 'NotAuthenticated'
TASK_IN_PROGRESS = 'TaskInProgress'
DUPLICATE_NAME = 'DuplicateName'


class VCloudDriverException(Exception):

    """Base VCloud Driver Exception

    To correctly use this class, inherit from it and define
    a 'msg_fmt' property. That msg_fmt will get printf'd
    with the keyword arguments provided to the constructor.

    """
    msg_fmt = _("An unknown exception occurred.")

    def __init__(self, message=None, details=None, **kwargs):
        self.kwargs = kwargs
        self.details = details

        if not message:
            try:
                message = self.msg_fmt % kwargs

            except Exception:
                # kwargs doesn't match a variable in the message
                # log the issue and the kwargs
                LOG.exception(_LE('Exception in string format operation'))
                for name, value in six.iteritems(kwargs):
                    LOG.error(_LE("%(name)s: %(value)s"),
                              {'name': name, 'value': value})
                # at least get the core message out if something happened
                message = self.msg_fmt

        super(VCloudDriverException, self).__init__(message)


class VCloudDriverConfigurationException(VCloudDriverException):

    """Base class for all configuration exceptions.
    """
    msg_fmt = _("VCloud Driver configuration fault.")


class UseLinkedCloneConfigurationFault(VCloudDriverConfigurationException):
    msg_fmt = _("No default value for use_linked_clone found.")


class MissingParameter(VCloudDriverException):
    msg_fmt = _("Missing parameter : %(param)s")


class AlreadyExistsException(VCloudDriverException):
    msg_fmt = _("Resource already exists.")
    code = 409


class CannotDeleteFileException(VCloudDriverException):
    msg_fmt = _("Cannot delete file.")
    code = 403


class FileAlreadyExistsException(VCloudDriverException):
    msg_fmt = _("File already exists.")
    code = 409


class FileFaultException(VCloudDriverException):
    msg_fmt = _("File fault.")
    code = 409


class FileLockedException(VCloudDriverException):
    msg_fmt = _("File locked.")
    code = 403


class FileNotFoundException(VCloudDriverException):
    msg_fmt = _("File not found.")
    code = 404


class InvalidPowerStateException(VCloudDriverException):
    msg_fmt = _("Invalid power state.")
    code = 409


class InvalidPropertyException(VCloudDriverException):
    msg_fmt = _("Invalid property.")
    code = 400


class NoPermissionException(VCloudDriverException):
    msg_fmt = _("No Permission.")
    code = 403


class NotAuthenticatedException(VCloudDriverException):
    msg_fmt = _("Not Authenticated.")
    code = 403


class ForbiddenException(VCloudDriverException):
    msg_fmt = _("Forbidden.")
    code = 403

class DeleteException(VCloudDriverException):
    msg_fmt = _("Delete error.")
    code = 400

class TaskInProgress(VCloudDriverException):
    msg_fmt = _("Entity has another operation in process.")


class DuplicateName(VCloudDriverException):
    msg_fmt = _("Duplicate name.")


class SSLError(VCloudDriverException):
    msg_fmt = _("SSL connect error")


# Populate the fault registry with the exceptions that have
# special treatment.
_fault_classes_registry = {
    ALREADY_EXISTS: AlreadyExistsException,
    CANNOT_DELETE_FILE: CannotDeleteFileException,
    FILE_ALREADY_EXISTS: FileAlreadyExistsException,
    FILE_FAULT: FileFaultException,
    FILE_LOCKED: FileLockedException,
    FILE_NOT_FOUND: FileNotFoundException,
    INVALID_POWER_STATE: InvalidPowerStateException,
    INVALID_PROPERTY: InvalidPropertyException,
    NO_PERMISSION: NoPermissionException,
    NOT_AUTHENTICATED: NotAuthenticatedException,
    TASK_IN_PROGRESS: TaskInProgress,
    DUPLICATE_NAME: DuplicateName,
}


def get_fault_class(name):
    """Get a named subclass of VCloudDriverException."""
    name = str(name)
    fault_class = _fault_classes_registry.get(name)
    if not fault_class:
        LOG.debug('Fault %s not matched.', name)
        fault_class = VCloudDriverException
    return fault_class


def register_fault_class(name, exception):
    fault_class = _fault_classes_registry.get(name)
    if not issubclass(exception, VCloudDriverException):
        raise TypeError(_("exception should be a subclass of "
                          "VCloudDriverException"))
    if fault_class:
        LOG.debug('Overriding exception for %s', name)
    _fault_classes_registry[name] = exception
