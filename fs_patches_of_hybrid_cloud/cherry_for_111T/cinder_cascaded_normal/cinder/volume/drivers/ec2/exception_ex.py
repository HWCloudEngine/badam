
from cinder.exception import *
from cinder.i18n import _

class ProviderMultiVolumeError(CinderException):
    msg_fmt = _("volume %(volume_id)s More than one provider_volume are found")

class ProviderMultiSnapshotError(CinderException):
    msg_fmt = _("snapshot %(snapshot_id)s More than one provider_snapshot are found")

class ProviderCreateVolumeError(CinderException):
    msg_fmt = _("volume %(volume_id)s create request failed,network or provider internal error")

class ProviderCreateSnapshotError(CinderException):
    msg_fmt = _("snapshot %(snapshot_id)s create request failed,network or provider internal error")

class ProviderLocationError(CinderException):
    msg_fmt = _("provider location error")

class ProviderExportVolumeError(CinderException):
    msg_fmt = _("provider export volume error")
    
class ProviderVolumeNotFound(NotFound):
    message = _("Volume %(volume_id)s could not be found.")

class VgwHostNotFound(NotFound):
    message = _("node of %(Vgw_id)s at provider cloud could not be found.")