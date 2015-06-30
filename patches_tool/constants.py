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

    # <ROOT_PATH>/patches_tool/neutron-l2-proxy.json
    NEUTRON_L2_PROXY_PATH_TEMPLATE = os.path.sep.join([utils.get_patches_tool_path(), os.sep.join([HYBRID_CLOUD_CONFIG_FILES, NEUTRON_L2_PROXY_JSON_FILE])])

class PatchFilePath(object):
    HYBRID_CLOUD_PATCHES = 'hybrid_cloud_patches'
    AWS_CASCADED = 'aws_cascaded'
    AWS_PROXY = 'aws_proxy'
    PATCH_FOR_AWS_CASCADED = os.path.sep.join([HYBRID_CLOUD_PATCHES, AWS_CASCADED])
    PATCH_FOR_AWS_PROXY = os.path.sep.join([HYBRID_CLOUD_PATCHES, AWS_PROXY])
