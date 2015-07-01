__author__ = 'wangfeng'

from nova.exception import *
from nova.i18n import _

class MultiInstanceConfusion(NovaException):
    msg_fmt = _("More than one instance are found")


class MultiVolumeConfusion(NovaException):
    msg_fmt = _("More than one volume are found")

class MultiImageConfusion(NovaException):
    msg_fmt = _("More than one Image are found")

class UploadVolumeFailure(NovaException):
    msg_fmt = _("upload volume to provider cloud failure")

class VolumeNotFoundAtProvider(NovaException):
    msg_fmt = _("can not find this volume at provider cloud")

class ProviderRequestTimeOut(NovaException):
    msg_fmt = _("Time out when connect to provider cloud")