#!/usr/bin/env python
# -*-coding:utf-8-*-

__author__ = 'luqitao'

import sys
import os
import json
import socket
from oslo.config import cfg
import traceback

import log as LOG
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))

sys.path.extend([CURRENT_PATH + "/../../", "/usr/bin/"])

import utils
from install_tool import cps_server
from patches_tool.services import RefServices, RefCPSServiceExtent, RefCPSService, RefFsSystemUtils
from patches_tool import config

PROVIDER_API_NETWORK='provider_api_network_id'
PROVIDER_TUNNEL_NETWORK='provider_tunnel_network_id'

provider_opts = [
    cfg.StrOpt('conversion_dir',
               default='/opt/HUAWEI/image',
               help='conversion_dir.'),
    cfg.StrOpt('access_key_id',
               default='',
               help='access_key_id from aws user config.'),
    cfg.StrOpt('secret_key',
           default='',
           help='secret_key from aws user config'),
    cfg.StrOpt('region',
           default='ap-southeast-1',
           help='region name from aws user config'),
    cfg.StrOpt('availability_zone',
           default='ap-southeast-1a',
           help='availability_zone'),
    cfg.StrOpt('base_linux_image',
           default='ami-68d8e93a',
           help='base_linux_image'),
    cfg.StrOpt('storage_tmp_dir',
           default='hybridbucket',
           help='storage_tmp_dir'),
    cfg.StrOpt('cascaded_node_id',
           default='i-test',
           help='cascaded_node_id'),
    cfg.StrOpt('subnet_data',
           default='subnet-bf28f8c8',
           help='subnet_data'),
    cfg.StrOpt('subnet_api',
           default='subnet-3d28f84a',
           help='subnet_api'),
    cfg.StrOpt('flavor_map',
                default='m1.tiny:t2.micro, m1.small:t2.micro, m1.medium:t2.micro3, m1.large:t2.micro, m1.xlarge:t2.micro',
                help='map nova flavor name to vcloud vm specification id'),
    cfg.StrOpt('cgw_host_ip',
           default='52.74.155.248',
           help='cgw_host_ip'),
    cfg.StrOpt('cgw_host_id',
           default='i-c124700d',
           help='cgw_host_id'),
    cfg.StrOpt('cgw_user_name',
           default='ec2-user',
           help='cgw_user_name'),
    cfg.StrOpt('cgw_certificate',
           default='/home/cgw.pem',
           help='cgw_certificate'),
    cfg.StrOpt('rabbit_password_public',
           default='',
           help='rabbit_password_public'),
    cfg.StrOpt('rabbit_host_ip_public',
           default='162.3.120.64',
           help='rabbit_host_ip_public'),
    cfg.StrOpt('vpn_route_gateway',
           default='162.3.0.0/16:172.29.0.1,172.28.48.0/20:172.29.1.1',
           help='vpn_route_gateway'),
    ]

vtepdriver = [
    cfg.StrOpt('provider_api_network_name',
               default='subnet-3d28f84a',
               help='a network name which is used for api tunnel on aws.'
               'host.'),
    cfg.StrOpt('provider_tunnel_network_name',
           default='subnet-bf28f8c8',
           help='a network name which is used for data tunnel on aws.'),
]

CONF = cfg.CONF
group_provider_opts = cfg.OptGroup(name='provider_opts', title='provider opts')
group_vtepdriver = cfg.OptGroup(name='vtepdriver', title='vtep')
CONF.register_group(group_provider_opts)
CONF.register_group(group_vtepdriver)
CONF.register_opts(provider_opts, group_provider_opts)
CONF.register_opts(vtepdriver, group_vtepdriver)

aws_config_ini = os.path.join(CURRENT_PATH, 'aws_config.ini')
CONF(['--config-file=%s' % aws_config_ini])

def restart_component(service_name, template_name):
    """Stop an component, then start it."""

    ret = RefCPSServiceExtent.host_template_instance_operate(service_name, template_name, 'stop')
    if not ret:
        LOG.error("cps template_instance_action stop for %s failed." % template_name)
        return ret
    ret = RefCPSServiceExtent.host_template_instance_operate(service_name, template_name, 'start')
    if not ret:
        LOG.error("cps template_instance_action start for %s failed." % template_name)
        return ret


def config_cascaded_az():
    """Update parameter for neutron-server and cinder-volume, then restart them."""

    params = {'mechanism_drivers': 'openvswitch,l2populationcascaded,evs,sriovnicswitch,netmapnicswitch'}
    ret = cps_server.update_template_params('neutron', 'neutron-server', params)
    if not ret:
        LOG.error("cps update_template_params for neutron-server failed.")
        return ret

    params = {'volume_driver': 'cinder.volume.drivers.ec2.driver.AwsEc2VolumeDriver'}
    ret = cps_server.update_template_params('cinder', 'cinder-volume', params)
    if not ret:
        LOG.error("cps update_template_params for cinder-volume failed.")
        return ret

    cps_server.cps_commit()

    restart_component('neutron', 'neutron-openvswitch-agent')
    restart_component('cinder', 'cinder-volume')
    restart_component('nova', 'nova-compute')


def replace_config(conf_file_path, src_key, new_value):
    """Update the config file by a given dict."""

    with open(conf_file_path, "a+") as fp:
        content = json.load(fp)

        content[src_key].update(new_value)
        fp.truncate(0)
        fp.write(json.dumps(content, indent=4))


def replace_cinder_volume_config(conf_file_path):
    """ Get config from aws_config.ini"""

    with open(conf_file_path, "a+") as fp:
        content = json.load(fp)

        content['cinder.conf']['DEFAULT']['storage_tmp_dir'] = CONF.provider_opts.storage_tmp_dir
        content['cinder.conf']['DEFAULT']['availability_zone'] = CONF.provider_opts.availability_zone
        content['cinder.conf']['DEFAULT']['cgw_host_ip'] = CONF.provider_opts.cgw_host_ip
        content['cinder.conf']['DEFAULT']['region'] = CONF.provider_opts.region
        content['cinder.conf']['DEFAULT']['provider_image_conversion_dir'] = CONF.provider_opts.conversion_dir

        content['cinder.conf']['DEFAULT']['cgw_certificate'] = CONF.provider_opts.cgw_certificate
        content['cinder.conf']['DEFAULT']['access_key_id'] = CONF.provider_opts.access_key_id
        content['cinder.conf']['DEFAULT']['secret_key'] = CONF.provider_opts.secret_key
        content['cinder.conf']['DEFAULT']['cgw_username'] = CONF.provider_opts.cgw_user_name
        content['cinder.conf']['DEFAULT']['cgw_host_id'] = CONF.provider_opts.cgw_host_id
        fp.truncate(0)
        fp.write(json.dumps(content, indent=4))


def replace_all_config():
    """Replace vcloud info for nova-compute and cinder-volume"""

    aws_conf = construct_aws_conf()
    api_netid, tunnel_netid = get_api_tunnel_netid()
    aws_conf['vtepdriver'][PROVIDER_API_NETWORK] = api_netid
    aws_conf['vtepdriver'][PROVIDER_TUNNEL_NETWORK] = tunnel_netid

    cur_path = os.path.split(os.path.realpath(__file__))[0]
    nova_compute_path = os.path.join(cur_path, "code", "etc", "nova", "others", "cfg_template", "nova-compute.json")
    replace_config(nova_compute_path, "nova.conf", aws_conf)

    # Get config from aws_config.ini
    cinder_volume_path = os.path.join(cur_path, "code", "etc", "cinder", "others", "cfg_template", "cinder-volume.json")
    replace_cinder_volume_config(cinder_volume_path)


def patch_hybridcloud_files():
    """Execute a shell script, do this things:
    1. replace python code
    2. update configuration files
    3. install some dependence packages
    4. restart component proc
    """

    utils.execute(['dos2unix', os.path.join(CURRENT_PATH, 'install.sh')])
    utils.execute(['sh', os.path.join(CURRENT_PATH, 'install.sh')])


def construct_aws_conf():
    """Build a json format config by ini file"""
    provider_opts_data = {}
    for o in CONF.provider_opts:
        provider_opts_data[o] = str(eval("CONF.provider_opts.%s" % o))

    vtepdriver_data = {}
    for o in CONF.vtepdriver:
         vtepdriver_data[o] = str(eval("CONF.vtepdriver.%s" % o))
    return {"provider_opts": provider_opts_data, "vtepdriver": vtepdriver_data}


def get_networkid_by_name(networks_data, name):
    if isinstance(networks_data, dict):
        if networks_data.has_key('networks'):
            for d in networks_data['networks']:
                if d['name'] == name:
                    return d['id']


def get_api_tunnel_netid():
    """Get api and tunnel network id from neutron api, create if it doesn't exist."""
    rs = RefServices(region_name=os.environ['OS_REGION_NAME'])
    networks_data = rs.neutron.list_networks()

    api_netid = get_networkid_by_name(networks_data, PROVIDER_API_NETWORK)
    tunnel_netid = get_networkid_by_name(networks_data, PROVIDER_TUNNEL_NETWORK)

    body = {"network": {"provider:network_type": "vlan", "provider:physical_network": "physnet1"}}
    if api_netid is None:
        body['network']['name'] = PROVIDER_API_NETWORK
        # TODO deal with create network failed.
        api_netdata = rs.neutron.create_network(body)
        api_netid = api_netdata['network']['id']
    if tunnel_netid is None:
        body['network']['name'] = PROVIDER_TUNNEL_NETWORK
        # TODO deal with create network failed.
        tunnel_netdata = rs.neutron.create_network(body)
        tunnel_netid = tunnel_netdata['network']['id']
    return api_netid, tunnel_netid

def create_aggregate_in_cascaded_node():
    """
    nova aggregate-create az31.singapore--aws az31.singapore--aws
    nova host-list
    nova aggregate-add-host az31.singapore--aws 42114FD9-D446-9248-3A05-23CF474E3C68

    :return:
    """
    host_id = socket.gethostname()
    region = RefCPSService.get_local_domain()
    os_region_name = '.'.join([RefFsSystemUtils.get_az_by_domain(region), RefFsSystemUtils.get_dc_by_domain(region)])
    ref_service = RefServices()
    if not ref_service.nova_aggregate_exist(os_region_name, os_region_name):
        create_result = ref_service.nova_aggregate_create(os_region_name, os_region_name)
        if create_result is not None:
            ref_service.nova_aggregate_add_host(os_region_name, host_id)

if __name__ == '__main__':
    LOG.init('patches_tool_config')
    LOG.info('START to patch for aws...')
    config.export_region()


    # try:
    #     replace_all_config()
    # except Exception, e:
    #     LOG.error('Excepton when replace_all_config, Exception: %s' % traceback.format_exc())

    LOG.info('Start to patch for hybrid-cloud files')
    try:
        patch_hybridcloud_files()
    except Exception, e:
        LOG.error('Excepton when patch for hybrid-cloud files, Exception: %s' % traceback.format_exc())

    try:
        LOG.info('Start to create ag in aws node.')
        create_aggregate_in_cascaded_node()

        LOG.info('Start to config cascaded az.')
        config_cascaded_az()
    except Exception, e:
        LOG.error('Excepton when create cascaded az, Exception: %s' % traceback.format_exc())

    LOG.info('SUCCESS to patch for aws.')

