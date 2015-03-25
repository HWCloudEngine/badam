__author__ = 'nash.xiejun'
import os

class EndpointType(object):
    COMPUTE = 'compute'
    VOLUME = 'volume'
    VOLUME2 = 'volume'
    IMAGE = 'image'
    NETWORK = 'network'
    ORCHESTRATION = 'orchestration'
    EC2 = 'ec2'
    METERING = 'metering'

class EndpointURL(object):
    COMPUTE = 'http://%s:8774/v2/$(tenant_id)s'
    VOLUME = 'http://%s:8776/v1/$(tenant_id)s'
    VOLUME2 = 'http://%s:8776/v2/$(tenant_id)s'
    IMAGE = 'http://%s:9292/'
    NETWORK = 'http://%s:9696/'
    ORCHESTRATION = 'http://%s:8004/v1/$(tenant_id)s'
    EC2 = 'http://%s:8773/services/Cloud'
    METERING = 'http://%s:8777/'

class ServiceName(object):
    NOVA = 'nova'
    CINDER = 'cinder'
    GLANCE = 'glance'
    NEUTRON = 'neutron'
    KEYSTONE = 'keystone'

class PathConfigFile(object):
    ROOT = os.path.sep

    ETC = 'etc'
    PLUGINS = 'plugins'
    ML_2 = 'ml2'
    ML2_CONF = 'ml2_conf.ini'

    NOVA_CONF = 'nova.conf'
    #etc/nova/nova.conf
    NOVA = os.path.join(ETC, ServiceName.NOVA, NOVA_CONF)

    NOVA_COMPUTE_CONF = 'nova-compute.conf'
    #etc/nova/nova-compute.conf
    NOVA_COMPUTE = os.path.join(ETC, ServiceName.NOVA, NOVA_COMPUTE_CONF)

    NEUTRON_CONF = 'neutron.conf'
    #etc/neutron/neutron.conf
    NEUTRON = os.path.join(ETC, ServiceName.NEUTRON, NEUTRON_CONF)

    # etc/neutron/plugins/ml2/ml2_conf.ini
    ML2 = os.path.join(ETC, ServiceName.NEUTRON, PLUGINS, ML_2, ML2_CONF)

    L3_PROXY_INI = 'l3_proxy.ini'

    # etc/neutron/l3_proxy.ini
    L3_PROXY = os.path.join(ETC, ServiceName.NEUTRON, L3_PROXY_INI)

    #etc/keystone/keystone.conf
    KEYSTONE_CONF = 'keystone.conf'
    KEYSTONE = os.path.join(ETC, ServiceName.KEYSTONE, KEYSTONE_CONF)

    #etc/glance/glance.conf
    GLANCE_CONF = 'glance.conf'
    GLANCE = os.path.join(ETC, ServiceName.GLANCE, GLANCE_CONF)

    #etc/cinder/cinder.conf
    CINDER_CONF = 'cinder.conf'
    CINDER = os.path.join(ETC, ServiceName.CINDER, CINDER_CONF)

class PathTriCircle(object):
    TRICIRCLE = 'tricircle-master'
    JUNO_PATCHES = 'juno-patches'
    NOVA_PROXY = 'novaproxy'
    CINDER_PROXY = 'cinderproxy'
    NEUTRON_PROXY = 'neutronproxy'
    L2_PROXY = 'l2proxy'
    L3_PROXY = 'l3proxy'
    GLANCE_SYNC = 'glancesync'
    GLANCE_STORE = 'glance_store'

    PATCH_CINDER_CASCADED_TIMESTAMP = 'timestamp-query-patch'
    PATCH_GLANCE_LOCATION = 'glance_location_patch'
    PATCH_GLANCE_STORE = 'glance_store_patch'
    PATCH_NEUTRON_CASCADED_BIG2LAYER = 'neutron_cascaded_big2layer_patch'
    PATCH_NEUTRON_CASCADED_L3 = 'neutron_cascaded_l3_patch'
    PATCH_NEUTRON_CASCADED_TIMESTAMP = 'neutron_timestamp_cascaded_patch'
    PATCH_NEUTRON_CASCADING_BIG2LAYER = 'neutron_cascading_big2layer_patch'
    PATCH_NEUTRON_CASCADING_L3 = 'neutron_cascading_l3_patch'
    PATCH_NOVA_SCHEDULING = 'nova_scheduling_patch'

    # tricircle-master/glancesync
    PATH_CASCADING_GLANCE_SYNC = os.path.join(TRICIRCLE, GLANCE_SYNC)
    # tricircle-master/cinderproxy
    PATH_PROXY_CINDER = os.path.join(TRICIRCLE, CINDER_PROXY)
    # tricircle-master/neutronproxy/l2proxy
    PATH_PROXY_NEUTRON_L2 = os.path.join(TRICIRCLE, NEUTRON_PROXY, L2_PROXY)
    # tricircle-master/neutronproxy/l3proxy
    PATH_PROXY_NEUTRON_L3 = os.path.join(TRICIRCLE, NEUTRON_PROXY, L3_PROXY)

    # tricircle-master/novaproxy
    PATH_PROXY_NOVA = os.path.join(TRICIRCLE, NOVA_PROXY)
    # tricircle-master/juno-patches/cinder/timestamp-query-patch
    PATH_PATCH_CINDER_CASCADED_TIMESTAMP = os.path.join(TRICIRCLE, JUNO_PATCHES, ServiceName.CINDER, PATCH_CINDER_CASCADED_TIMESTAMP)
    # tricircle-master/juno-patches/glance/glance_location_patch
    PATH_PATCH_GLANCE_LOCATION = os.path.join(TRICIRCLE, JUNO_PATCHES, ServiceName.GLANCE, PATCH_GLANCE_LOCATION)
    # tricircle-master/juno-patches/glance_store/glance_store_patch/
    PATH_PATCH_GLANCE_STORE = os.path.join(TRICIRCLE, JUNO_PATCHES, GLANCE_STORE, PATCH_GLANCE_STORE)

    # tricircle-master/juno-patches/neutron/neutron_cascaded_big2layer_patch
    PATH_PATCH_NEUTRON_CASCADED_BIG2LAYER = os.path.join(TRICIRCLE, JUNO_PATCHES, ServiceName.NEUTRON, PATCH_NEUTRON_CASCADED_BIG2LAYER)
    # tricircle-master/juno-patches/neutron/neutron_cascaded_l3_patch
    PATH_PATCH_NEUTRON_CASCADED_L3 = os.path.join(TRICIRCLE, JUNO_PATCHES, ServiceName.NEUTRON, PATCH_NEUTRON_CASCADED_L3)
    # tricircle-master/juno-patches/neutron/neutron_cascading_big2layer_patch
    PATH_PATCH_NEUTRON_CASCADING_BIG2LAYER = os.path.join(TRICIRCLE, JUNO_PATCHES, ServiceName.NEUTRON, PATCH_NEUTRON_CASCADING_BIG2LAYER)
    # tricircle-master/juno-patches/neutron/neutron_cascading_l3_patch
    PATH_PATCH_NEUTRON_CASCADING_L3 = os.path.join(TRICIRCLE, JUNO_PATCHES, ServiceName.NEUTRON, PATCH_NEUTRON_CASCADING_L3)
    # tricircle-master/juno-patches/neutron/neutron_timestamp_cascaded_patch
    PATH_PATCH_NEUTRON_CASCADED_TIMESTAMP = os.path.join(TRICIRCLE, JUNO_PATCHES, ServiceName.NEUTRON, PATCH_NEUTRON_CASCADED_TIMESTAMP)

    # tricircle-master/juno-patches/nova/nova_scheduling_patch
    PATH_PATCH_NOVA_SCHEDULING = os.path.join(TRICIRCLE, JUNO_PATCHES, ServiceName.NOVA, PATCH_NOVA_SCHEDULING)

    PATCH_TO_PATH = {
        PATCH_NOVA_SCHEDULING : PATH_PATCH_NOVA_SCHEDULING,
        PATCH_NEUTRON_CASCADING_BIG2LAYER : PATH_PATCH_NEUTRON_CASCADING_BIG2LAYER,
        PATCH_NEUTRON_CASCADING_L3 : PATH_PATCH_NEUTRON_CASCADING_L3,

        PATCH_NEUTRON_CASCADED_BIG2LAYER : PATH_PATCH_NEUTRON_CASCADED_BIG2LAYER,
        PATCH_NEUTRON_CASCADED_L3 : PATH_PATCH_NEUTRON_CASCADED_L3,

        PATCH_CINDER_CASCADED_TIMESTAMP : PATH_PATCH_CINDER_CASCADED_TIMESTAMP
    }

class PathTricircleConfigFile(object):
    PROXY_CINDER = os.path.join(PathTriCircle.PATH_PROXY_CINDER, PathConfigFile.CINDER)
    PROXY_NEUTRON_L2 = os.path.join(PathTriCircle.PATH_PROXY_NEUTRON_L2, PathConfigFile.ML2)
    PROXY_NEUTRON_L3 = os.path.join(PathTriCircle.PATH_PROXY_NEUTRON_L3, PathConfigFile.L3_PROXY)
    PROXY_NOVA_COMPUTE = os.path.join(PathTriCircle.PATH_PROXY_NOVA, PathConfigFile.NOVA_COMPUTE)
    PROXY_NOVA = os.path.join(PathTriCircle.PATH_PROXY_NOVA, PathConfigFile.NOVA)

class ConfigReplacement(object):
    REGION_NAME = 'region_name'
    CASCADED_NODE_IP = 'cascaded_node_ip'
    CASCADING_NODE_IP = 'cascading_node_ip'
    CINDER_TENANT_ID = 'cinder_tenant_id'
    AVAILABILITY_ZONE = 'availability_zone',
    CASCADING_OS_REGION_NAME = 'cascading_os_region_name',
    ML2_LOCAL_IP = 'ml2_local_ip'