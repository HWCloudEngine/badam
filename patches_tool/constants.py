__author__ = 'nash.xiejun'
import os
import utils

class FileName(object):
    PATCHES_TOOL_CONFIG_FILE = 'patches_tool_config.ini'

class CfgFilePath(object):
    HYBRID_CLOUD_CONFIG_FILES = 'hybrid_cloud_config_files'
    # 'neutron-l2-proxy.json'
    NEUTRON_L2_PROXY_JSON_FILE = 'neutron-l2-proxy.json'
    # '/etc/neutron/others/cfg_template/neutron-l2-proxy.json'
    ETC = ''.join([os.path.sep, 'etc'])
    NEUTRON_L2_PROXY_PATH = os.path.sep.join([ETC, 'neutron', 'others', 'cfg_template', NEUTRON_L2_PROXY_JSON_FILE])

    # hybrid_cloud_config_files/neutron-l2-proxy.json
    NEUTRON_L2_PROXY_PATH_TEMPLATE = os.sep.join([HYBRID_CLOUD_CONFIG_FILES, NEUTRON_L2_PROXY_JSON_FILE])

class PatchFilePath(object):
    HYBRID_CLOUD_PATCHES = 'hybrid_cloud_patches'
    AWS_CASCADED = 'aws_cascaded'
    AWS_PROXY = 'aws_proxy'
    CASCADING = 'cascading'
    VCLOUD_PROXY = 'vcloud_proxy'
    VCLOUD_CASCADED = 'VCLOUD_CASCADED'
    PATCH_FOR_AWS_CASCADED = os.path.sep.join([HYBRID_CLOUD_PATCHES, AWS_CASCADED])
    PATCH_FOR_AWS_PROXY = os.path.sep.join([HYBRID_CLOUD_PATCHES, AWS_PROXY])
    PATCH_FOR_CASCADING = os.path.sep.join([HYBRID_CLOUD_PATCHES, CASCADING])
    PATCH_FOR_VCLOUD_CASCADED = os.path.sep.join([HYBRID_CLOUD_PATCHES, VCLOUD_CASCADED])
    PATCH_FOR_VCLOUD_PROXY = os.path.sep.join([HYBRID_CLOUD_PATCHES, VCLOUD_PROXY])

class ScriptFilePath(object):
    SCRIPT = 'script'
    EXECUTE_SH = 'execute.sh'
    SU_CHANGE_SH = 'su_change.sh'
    HOME = ''.join([os.path.sep, 'home'])
    FSP = 'fsp'
    PATCHES_TOOL = 'patches_tool'
    PATCH_FILE = 'patch_file.py'
    AWS_PATCH = 'aws_patch'
    VCLOUD_PATCH = 'vcloud_patch'
    CONFIG_PY = 'config.py'
    PATH_EXECUTE_SH = os.path.join(SCRIPT, EXECUTE_SH)
    PATH_SU_CHANGE_SH = os.path.join(SCRIPT, PATH_EXECUTE_SH)
    PATH_EXECUTE_SH_COPY_TO = os.path.join(HOME, FSP, SCRIPT, EXECUTE_SH)
    PATH_SU_CHANGE_SH_COPY_TO = os.path.join(HOME, FSP, SCRIPT, SU_CHANGE_SH)

    PATH_REMOTE_AWS_PATCH_FILE = os.path.join(HOME, FSP, PATCHES_TOOL, AWS_PATCH, PATCH_FILE)
    PATH_REMOTE_VCLOUD_PATCH_FILE = os.path.join(HOME, FSP, PATCHES_TOOL, VCLOUD_PATCH, PATCH_FILE)

    PATCH_REMOTE_HYBRID_CONFIG_PY = os.path.join(HOME, FSP, PATCHES_TOOL, CONFIG_PY)

class SysPath(object):
    HOME = ''.join([os.path.sep, 'home'])
    FSP = 'fsp'
    HOME_FSP = os.path.join(HOME, FSP)
    PATCHES_TOOL = 'patches_tool'
    PATH_PATCHES_TOOL =os.path.join(HOME_FSP, PATCHES_TOOL)


class SysUserInfo(object):
    ROOT = 'root'
    ROOT_PWD = 'Huawei@CLOUD8!'
    FSP = 'fsp'
    FSP_PWD = 'Huawei@CLOUD8'