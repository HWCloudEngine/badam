__author__ = 'wangfeng'

try:
    from lxml import etree as ET
except ImportError:
    from xml.etree import ElementTree as ET
import copy
import base64
from hashlib import sha1
import hmac
import sys
import ssl
import time
import uuid
import warnings
from libcloud.compute.base import KeyPair
from libcloud.utils.iso8601 import parse_date

from libcloud.compute.base import Node, NodeImage, NodeSize, NodeLocation
from libcloud.compute.base import StorageVolume, VolumeSnapshot
from libcloud.compute.drivers.ec2 import *
from libcloud.compute.providers import get_driver
from libcloud.compute.types import KeyPairDoesNotExistError 
from libcloud.compute.types import Provider
from libcloud.storage.drivers.s3 import S3StorageDriver
from libcloud.storage.drivers.s3 import S3APSEStorageDriver
from libcloud.utils.py3 import b, basestring, ensure_string
from libcloud.utils.py3 import urlencode
from libcloud.utils.py3 import PY3, PY25
from libcloud.utils.xml import fixxpath, findtext, findattr, findall
from libcloud.compute.drivers.ec2 import EC2Connection
from libcloud.compute.types import NodeState, KeyPairDoesNotExistError, \
    StorageVolumeState
from libcloud.compute.drivers.ec2 import RESOURCE_EXTRA_ATTRIBUTES_MAP
from libcloud.compute.drivers.ec2 import EC2Response
import subprocess
from libcloud.storage.base import Container, Object
from functools import wraps
import shutil
import os
import random
from libcloud.common.types import (InvalidCredsError, MalformedResponseError,
                                   LibcloudError)
from libcloud.storage.types import Provider
from libcloud.storage.providers import get_driver
from libcloud.storage.drivers.s3 import S3APSEConnection
from libcloud.storage.drivers.s3 import S3Connection
from libcloud.storage.drivers.s3 import S3EUWestConnection
from libcloud.storage.drivers.s3 import S3USWestConnection
from libcloud.storage.drivers.s3 import S3USWestOregonConnection
from libcloud.storage.drivers.s3 import S3APNEConnection
from libcloud.utils.misc import lowercase_keys

API_VERSION = '2015-03-01'
#NAMESPACE = 'http://ec2.amazonaws.com/doc/%s/' % (API_VERSION)
EXPIRATION_SECONDS=60*60
MAX_RETRY_COUNT=8
CHUNK_SIZE = 1024*4

class AwsRegion:
    US_EAST_1 = 'us-east-1'
    US_WEST_1 = 'us-west-1'
    US_WEST_2 = 'us-west-2'
    EU_WEST_1 = 'eu-west-1'
    AP_NORTHEAST_1 = 'ap-northeast-1'
    AP_SOUTHEAST_1='ap-southeast-1'
    
DRIVER_INFO={
             AwsRegion.US_EAST_1:{'connectionCls': S3Connection,'name':'Amazon S3 (standard)','ex_location_name':''},
             AwsRegion.US_WEST_1:{'connectionCls': S3USWestConnection,'name':'Amazon S3 (us-west-1)','ex_location_name':'us-west-1'},
             AwsRegion.US_WEST_2:{'connectionCls': S3USWestOregonConnection,'name':'Amazon S3 (us-west-2)','ex_location_name':'us-west-2'},
             AwsRegion.EU_WEST_1:{'connectionCls': S3EUWestConnection,'name':'Amazon S3 (eu-west-1)','ex_location_name':'EU'},
             AwsRegion.AP_NORTHEAST_1:{'connectionCls': S3APNEConnection,'name':'Amazon S3 (ap-northeast-1)','ex_location_name':'ap-northeast-1'},
             AwsRegion.AP_SOUTHEAST_1:{'connectionCls': S3APSEConnection,'name':'Amazon S3 (ap-southeast-1)','ex_location_name':'ap-southeast-1'}
             }
class HttpException(Exception):
    msg_fmt = "request failed"
    def __init__(self,status_code,status_text,message):
        super(HttpException,self).__init__(message)
        self.status_code = status_code
        self.status_text = status_text
    

class  EC2ExtResponse(EC2Response):
    def __init__(self, response, connection):
        """
        :param response: HTTP response object. (optional)
        :type response: :class:`httplib.HTTPResponse`

        :param connection: Parent connection object.
        :type connection: :class:`.Connection`
        """
        self.connection = connection

        # http.client In Python 3 doesn't automatically lowercase the header
        # names
        self.headers = lowercase_keys(dict(response.getheaders()))
        self.error = response.reason
        self.status = response.status

        # This attribute is set when using LoggingConnection.
        original_data = getattr(response, '_original_data', None)

        if original_data:
            # LoggingConnection already decompresses data so it can log it
            # which means we don't need to decompress it here.
            self.body = response._original_data
        else:
            self.body = self._decompress_response(body=response.read(),
                                                  headers=self.headers)

        if PY3:
            self.body = b(self.body).decode('utf-8')

        if not self.success():
            
            try:
                body = ET.XML(self.body)
            except:
                raise MalformedResponseError("Failed to parse XML",
                                         body=self.body, driver=EC2NodeDriver)

            for err in body.findall('Errors/Error'):
                code, message = err.getchildren() 
            raise HttpException(self.status,code.text,self.parse_error())
            #raise Exception(self.parse_error())

        self.object = self.parse_body()




class HuaweiConnection(EC2Connection):
    """
    Connection class for Ec2Adapter
    """
    version = API_VERSION
    responseCls = EC2ExtResponse
    
class EC2ExtConnection(EC2Connection):
    responseCls = EC2ExtResponse

class RetryDecorator(object):
    """Decorator for retrying a function upon suggested exceptions.

    The decorated function is retried for the given number of times, and the
    sleep time between the retries is incremented until max sleep time is
    reached. If the max retry count is set to -1, then the decorated function
    is invoked indefinitely until an exception is thrown, and the caught
    exception is not in the list of suggested exceptions.
    """

    def __init__(self, max_retry_count=-1, inc_sleep_time=5,
                 max_sleep_time=60, exceptions=()):
        """Configure the retry object using the input params.

        :param max_retry_count: maximum number of times the given function must
                                be retried when one of the input 'exceptions'
                                is caught. When set to -1, it will be retried
                                indefinitely until an exception is thrown
                                and the caught exception is not in param
                                exceptions.
        :param inc_sleep_time: incremental time in seconds for sleep time
                               between retries
        :param max_sleep_time: max sleep time in seconds beyond which the sleep
                               time will not be incremented using param
                               inc_sleep_time. On reaching this threshold,
                               max_sleep_time will be used as the sleep time.
        :param exceptions: suggested exceptions for which the function must be
                           retried
        """
        self._max_retry_count = max_retry_count
        self._inc_sleep_time = inc_sleep_time
        self._max_sleep_time = max_sleep_time
        self._exceptions = exceptions
        self._retry_count = 0
        self._sleep_time = 0
        
    def __call__(self, f):
            @wraps(f)
            def f_retry(*args, **kwargs):
                mtries, mdelay = self._max_retry_count, self._inc_sleep_time
                while mtries > 1:
                    try:
                        return f(*args, **kwargs)
                    except self._exceptions as e:
                        error_info='Second simultaneous read on fileno'
                        error_message= e.message
                        retry_error_message=['','Tunnel connection failed: 503 Service Unavailable',
                                             'Tunnel connection failed: 502 Bad Gateway',"'NoneType' object has no attribute 'makefile'"]
                        if error_message is None:
                            raise e
                        if  error_message not in retry_error_message and  not (error_info in error_message):
                            raise e
                        time.sleep(mdelay)
                        mtries -= 1
                        mdelay =random.randint(3,10)
                        if mdelay >= self._max_sleep_time:
                            mdelay=self._max_sleep_time
                return f(*args, **kwargs)
    
            return f_retry  # true decorator
        
class ErrorDecorator(object):
    """Decorator for catching  suggested exceptions.

    The decorated function is  catching the suggested exceptions
    """

    def __init__(self,exceptions=()):
        
        """Configure the decorator object using the input params.
        :param exceptions: suggested exceptions for which the function must 
                           return []
        """
        self._exceptions = exceptions  
        
    def __call__(self, f):
            @wraps(f)
            def f_retry(*args, **kwargs):
                try:
                    return f(*args, **kwargs)
                except self._exceptions as e:
                    status_text= e.status_text
                    empty_error_message=['InvalidAMIID.NotFound','InvalidInstanceID.NotFound','InvalidZone.NotFound','InvalidVpnGatewayID.NotFound',
                                         'InvalidVpnGatewayAttachment.NotFound','InvalidVpnConnectionID.NotFound','InvalidVpcPeeringConnectionID.NotFound',
                                         'InvalidVpcID.NotFound','InvalidVpcEndpointId.NotFound','InvalidVolume.NotFound','InvalidSubnetID.NotFound',
                                         'InvalidSpotInstanceRequestID.NotFound','InvalidSpotDatafeed.NotFound','InvalidSnapshot.NotFound',
                                         'InvalidSecurityGroupID.NotFound','InvalidRouteTableID.NotFound','InvalidRoute.NotFound',
                                         'InvalidReservationID.NotFound','InvalidPrefixListId.NotFound','InvalidPermission.NotFound','InvalidNetworkInterfaceID.NotFound',
                                         'InvalidNetworkAclID.NotFound','InvalidNetworkAclEntry.NotFound','InvalidKeyPair.NotFound','InvalidInternetGatewayID.NotFound',
                                         'InvalidInstanceID.NotFound','InvalidGroup.NotFound','InvalidGatewayID.NotFound','InvalidExportTaskID.NotFound',
                                         'InvalidCustomerGatewayID.NotFound','InvalidBundleID.NotFound','InvalidAttachmentID.NotFound','InvalidAttachment.NotFound',
                                         'InvalidAssociationID.NotFound','InvalidAllocationID.NotFound','InvalidAddressID.NotFound','InvalidAddress.NotFound']
                    if status_text  in empty_error_message:
                        return []
                    else:
                        raise e
                return f(*args, **kwargs)
            return f_retry  # true decorator       
  
class Ec2Adapter(EC2NodeDriver):
    connectionCls= EC2ExtConnection
    
    def __init__(self, key, secret=None, secure=False, host=None, port=None,
                 region='ap-southeast-1', **kwargs):
        self.helper = Ec2Adapter2(key, secret, secure, host, port, region, **kwargs)
        self.name_space  = 'http://ec2.amazonaws.com/doc/%s/' % (self.connectionCls.version)
        super(Ec2Adapter, self).__init__(key=key, secret=secret,
                                            secure=secure, host=host,
                                            port=port,region=region,**kwargs)
        self.region=region
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError)) 
    def create_export_instance_task(self, instance_id, des_loc,disk_image_format='VMDK', 
                                    target_environment='VMWare', **kwargs):
        """
        Exports a running or stopped instance to an S3 bucket
        :param instance_id:
        :type str
        :param des_loc:S3Bucket name
        :type str
        :param disk_image_format: The format for the exported image
        :type str
        :Valid Values: VMDK | RAW | VHD
        :param target_environment: The target virtualization environment
        :type str
        :Valid Values: citrix | vmware | microsoft
        :param kwargs:
        :return: task object
        """
        return self.helper.create_export_instance_task(instance_id, des_loc,disk_image_format, 
                                    target_environment, **kwargs)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError)) 
    def create_export_volume_task(self, volume_id,instance_id, des_loc, des_filename, **kwargs):
        return self.helper.create_export_volume_task(volume_id,instance_id, des_loc, des_filename, **kwargs)
     
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))    
    def create_import_image_task(self, src_loc, src_file, **kwargs):
        """
        import a image to provider from a file

        :param src_loc: s3 bucket name
        :type str
        :param src_file: s3 key
        :type str
        :param kwargs: other parameters
        :return: import task object
        """
        return self.helper.create_import_image_task(src_loc, src_file, **kwargs)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))     
    def create_import_volume_task(self, src_loc, src_file, src_file_format,src_file_size,
                                   volume_size, **kwargs):
        """
        :param src_loc: s3 bucket and directory of source file
        :type str
        :param src_file: souce file name in s3
        :type str
        :param src_file_format: source file format.
        :type str
         valid value: VMDK, RAW, VHD
        :param volume_size:The size of the volume, in GiB
        :type long 
        :param volume_loc: The Availability Zone for the resulting EBS volume
        :type str 
        :return: import task object
        """
        return self.helper.create_import_volume_task( src_loc, src_file, src_file_format,src_file_size,
                      volume_size, **kwargs)
        
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError)) 
    def cancel_task(self, task_obj, **kwargs):
        """
        cancels an active conversion task
        :param task_obj
        :type TaskBase or the subclass of TaskBase
        """
        return self.helper.cancel_task( task_obj,**kwargs)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))    
    def get_task_info(self, task_obj, **kwargs):
        """
        Describes one of your  task
        :param task_obj
        :type TaskBase or the subclass of TaskBase
        """
        return self.helper.get_task_info(task_obj, **kwargs)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))    
    def list_volumes(self, node=None, ex_volume_ids=None, ex_filters=None):
        """
        List all volumes
        @inherits: :class:`NodeDriver.list_volumes`
        
        ex_volume_ids parameter is used to filter the list of
        volumes that should be returned. Only the volumes
        with the corresponding volume ids will be returned.
        
        ex_tag&ex_state parameter is used to filter the list of
        volumes that should be returned. Only images matchind
        the filter will be returned.
        
        :param      ex_volume_ids: List of ``StorageVolume.id``
        :type       ex_volume_ids: ``list`` of ``str``
        
        Ex_filters parameter is used to filter the list of
        volumes that should be returned. Only volumes matchind
        the filter will be returned.
        
        :rtype: ``list`` of :class:`StorageVolume`
        """
        params = {
            'Action': 'DescribeVolumes',
        }
        if node:
            filters = {'attachment.instance-id': node.id}
            params.update(self._build_filters(filters))
            
        if ex_volume_ids:
            for index, volume_id in enumerate(ex_volume_ids):
                index += 1
                params.update({'VolumeId.%s' % (index): volume_id})
            
        if ex_filters:    
            params.update(self._build_filters(ex_filters))

        response = self.connection.request(self.path, params=params).object
        volumes = [self._to_volume(el) for el in response.findall(
            fixxpath(xpath='volumeSet/item', namespace=self.name_space))
        ]
        return volumes
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError)) 
    def attach_volume(self, node, volume, device):
        return super(Ec2Adapter, self).attach_volume(node, volume, device)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def copy_image(self, image, source_region, name=None, description=None):
        """
        Copy an Amazon Machine Image from the specified source region
        to the current region.

        @inherits: :class:`NodeDriver.copy_image`

        :param      source_region: The region where the image resides
        :type       source_region: ``str``

        :param      image: Instance of class NodeImage
        :type       image: :class:`NodeImage`

        :param      name: The name of the new image
        :type       name: ``str``

        :param      description: The description of the new image
        :type       description: ``str``

        :return:    Instance of class ``NodeImage``
        :rtype:     :class:`NodeImage`
        """
        return super(Ec2Adapter, self).copy_image(image, source_region, name=name, description=description)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def create_image(self, node, name, description=None, reboot=False,
                     block_device_mapping=None):
        """
        Create an Amazon Machine Image based off of an EBS-backed instance.

        @inherits: :class:`NodeDriver.create_image`

        :param      node: Instance of ``Node``
        :type       node: :class: `Node`

        :param      name: The name for the new image
        :type       name: ``str``

        :param      block_device_mapping: A dictionary of the disk layout
                                          An example of this dict is included
                                          below.
        :type       block_device_mapping: ``list`` of ``dict``

        :param      reboot: Whether or not to shutdown the instance before
                               creation. Amazon calls this NoReboot and
                               sets it to false by default to ensure a
                               clean image.
        :type       reboot: ``bool``

        :param      description: An optional description for the new image
        :type       description: ``str``

        An example block device mapping dictionary is included:

        mapping = [{'VirtualName': None,
                    'Ebs': {'VolumeSize': 10,
                            'VolumeType': 'standard',
                            'DeleteOnTermination': 'true'},
                            'DeviceName': '/dev/sda1'}]

        :return:    Instance of class ``NodeImage``
        :rtype:     :class:`NodeImage`
        """
        return super(Ec2Adapter, self).create_image(node, name, description=description, reboot=reboot,block_device_mapping=block_device_mapping)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def create_key_pair(self, name):
        return super(Ec2Adapter, self).create_key_pair(name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def create_node(self, **kwargs):
        """
        Create a new EC2 node.

        Reference: http://bit.ly/8ZyPSy [docs.amazonwebservices.com]

        @inherits: :class:`NodeDriver.create_node`

        :keyword    ex_keyname: The name of the key pair
        :type       ex_keyname: ``str``

        :keyword    ex_userdata: User data
        :type       ex_userdata: ``str``

        :keyword    ex_security_groups: A list of names of security groups to
                                        assign to the node.
        :type       ex_security_groups:   ``list``

        :keyword    ex_security_group_ids: A list of ids of security groups to
                                        assign to the node.[for VPC nodes only]
        :type       ex_security_group_ids:   ``list``

        :keyword    ex_metadata: Key/Value metadata to associate with a node
        :type       ex_metadata: ``dict``

        :keyword    ex_mincount: Minimum number of instances to launch
        :type       ex_mincount: ``int``

        :keyword    ex_maxcount: Maximum number of instances to launch
        :type       ex_maxcount: ``int``

        :keyword    ex_clienttoken: Unique identifier to ensure idempotency
        :type       ex_clienttoken: ``str``

        :keyword    ex_blockdevicemappings: ``list`` of ``dict`` block device
                    mappings.
        :type       ex_blockdevicemappings: ``list`` of ``dict``

        :keyword    ex_iamprofile: Name or ARN of IAM profile
        :type       ex_iamprofile: ``str``

        :keyword    ex_ebs_optimized: EBS-Optimized if True
        :type       ex_ebs_optimized: ``bool``

        :keyword    ex_subnet: The subnet to launch the instance into.
        :type       ex_subnet: :class:`.EC2Subnet`

        :keyword    ex_placement_group: The name of the placement group to
                                        launch the instance into.
        :type       ex_placement_group: ``str``
        
        :keyword    ex_network_interfaces: network interfaces. 
        :type   ex_network_interfaces `` list NetworkInterface ``
         
        """
        
        image = kwargs["image"]
        size = kwargs["size"]
        params = {
            'Action': 'RunInstances',
            'ImageId': image.id,
            'MinCount': str(kwargs.get('ex_mincount', '1')),
            'MaxCount': str(kwargs.get('ex_maxcount', '1')),
            'InstanceType': size.id
        }

        if 'ex_security_groups' in kwargs and 'ex_securitygroup' in kwargs:
            raise ValueError('You can only supply ex_security_groups or'
                             ' ex_securitygroup')

        # ex_securitygroup is here for backward compatibility
        ex_security_groups = kwargs.get('ex_security_groups', None)
        ex_securitygroup = kwargs.get('ex_securitygroup', None)
        security_groups = ex_security_groups or ex_securitygroup

        if security_groups:
            if not isinstance(security_groups, (tuple, list)):
                security_groups = [security_groups]

            for sig in range(len(security_groups)):
                params['SecurityGroup.%d' % (sig + 1,)] =\
                    security_groups[sig]

        if 'ex_security_group_ids' in kwargs and 'ex_subnet' not in kwargs:
            raise ValueError('You can only supply ex_security_group_ids'
                             ' combinated with ex_subnet')

        security_group_ids = kwargs.get('ex_security_group_ids', None)

        if security_group_ids:
            if not isinstance(security_group_ids, (tuple, list)):
                security_group_ids = [security_group_ids]

            for sig in range(len(security_group_ids)):
                params['SecurityGroupId.%d' % (sig + 1,)] =\
                    security_group_ids[sig]

        if 'location' in kwargs:
            availability_zone = getattr(kwargs['location'],
                                        'availability_zone', None)
            if availability_zone:
                if availability_zone.region_name != self.region_name:
                    raise AttributeError('Invalid availability zone: %s'
                                         % (availability_zone.name))
                params['Placement.AvailabilityZone'] = availability_zone.name

        if 'auth' in kwargs and 'ex_keyname' in kwargs:
            raise AttributeError('Cannot specify auth and ex_keyname together')

        if 'auth' in kwargs:
            auth = self._get_and_check_auth(kwargs['auth'])
            key = self.ex_find_or_import_keypair_by_key_material(auth.pubkey)
            params['KeyName'] = key['keyName']

        if 'ex_keyname' in kwargs:
            params['KeyName'] = kwargs['ex_keyname']

        if 'ex_userdata' in kwargs:
            params['UserData'] = base64.b64encode(b(kwargs['ex_userdata']))\
                .decode('utf-8')

        if 'ex_clienttoken' in kwargs:
            params['ClientToken'] = kwargs['ex_clienttoken']
            
        if image.extra is not None:   
            block_device_mappings = image.extra.get('block_device_mapping')
            ex_bdms=[]
            if block_device_mappings is not None:
                for block_device_mapping in block_device_mappings:
                    if block_device_mapping.get('ebs') is not None:    
                        bdm={'DeviceName':block_device_mapping.get('device_name'),'Ebs':{'DeleteOnTermination':block_device_mapping.get('ebs').get('delete',True),
                                                                                  'VolumeSize':block_device_mapping.get('ebs').get('volume_size'),
                                                                                  'SnapshotId':block_device_mapping.get('ebs').get('snapshot_id')}}
                        ex_bdms.append(bdm)
        if 'ex_blockdevicemappings' in kwargs and kwargs['ex_blockdevicemappings'] is not None:
            ex_blockdevicemappings = kwargs['ex_blockdevicemappings'] 
            bdms=copy.deepcopy(ex_blockdevicemappings)
            
            bdms.extend(ex_bdms)
            params.update(self._get_block_device_mapping_params(
                                                                bdms))
        else:
            params.update(self._get_block_device_mapping_params(
                                                                ex_bdms))
        if 'ex_iamprofile' in kwargs:
            if not isinstance(kwargs['ex_iamprofile'], basestring):
                raise AttributeError('ex_iamprofile not string')

            if kwargs['ex_iamprofile'].startswith('arn:aws:iam:'):
                params['IamInstanceProfile.Arn'] = kwargs['ex_iamprofile']
            else:
                params['IamInstanceProfile.Name'] = kwargs['ex_iamprofile']

        if 'ex_ebs_optimized' in kwargs:
            params['EbsOptimized'] = kwargs['ex_ebs_optimized']

        if 'ex_subnet' in kwargs:
            params['SubnetId'] = kwargs['ex_subnet'].id

        if 'ex_placement_group' in kwargs and kwargs['ex_placement_group']:
            params['Placement.GroupName'] = kwargs['ex_placement_group']
            
       
        if 'ex_network_interfaces' in kwargs and kwargs['ex_network_interfaces']:
            ex_network_interfaces = kwargs['ex_network_interfaces']
            params.update(self._get_network_interface_params(ex_network_interfaces))
           
        object = self.connection.request(self.path, params=params).object
        nodes = self._to_nodes(object, 'instancesSet/item')

        for node in nodes:
            tags = {'Name': kwargs['name']}
            if 'ex_metadata' in kwargs:
                tags.update(kwargs['ex_metadata'])

            try:
                self.ex_create_tags(resource=node, tags=tags)
            except Exception:
                continue

            node.name = kwargs['name']
            node.extra.update({'tags': tags})

        if len(nodes) == 1:
            return nodes[0]
        else:
            return nodes
   
   
    def _get_network_interface_params(self,network_interfaces):
        params = {}
        for index,network_interface in enumerate(network_interfaces):
            index += 1
            if network_interface.device_index is  None and network_interface.device_index in params.values():
                raise   AttributeError(
                    'network_interface %s device_index %sin ex_network_interfaces '
                    'not unique' % (network_interface,network_interface.device_index))
            else:
                params['NetworkInterface.%d.DeviceIndex' %(index)]=network_interface.device_index
            
            if network_interface.subnet_id is not None and network_interface.id is not None:
                raise AttributeError('network_interface %s may not specify both a network interface ID and a subnet' 
                                       %network_interface)
            elif network_interface.subnet_id is  None and network_interface.id is  None:
                raise AttributeError('network_interface %s requires either a subnet or a network interface ID' 
                                       %network_interface)
            elif network_interface.id is not None:
                params['NetworkInterface.%d.NetworkInterfaceId' %(index)]=network_interface.id
            else:
                params['NetworkInterface.%d.SubnetId' %(index)]=network_interface.subnet_id
            
            if network_interface.id is not None and network_interface.delete_on_termination is True:
                raise AttributeError('network_interface %s  may not specify a network interface ID and delete on termination as true'
                                        %network_interface)
                
            params['NetworkInterface.%d.DeleteOnTermination' %(index)]=network_interface.delete_on_termination 
            
            if network_interface.security_groups is not None:
                params['NetworkInterface.%d.Groups' %(index)]=network_interface.security_groups
      
        return params
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def create_volume(self, size, name, location=None, snapshot=None,
                      ex_volume_type='standard', ex_iops=None):
        """
        Create a new volume.

        :param size: Size of volume in gigabytes (required)
        :type size: ``int``

        :param name: Name of the volume to be created
        :type name: ``str``

        :param location: Which data center to create a volume in. If
                               empty, undefined behavior will be selected.
                               (optional)
        :type location: :class:`.NodeLocation`

        :param snapshot:  Snapshot from which to create the new
                               volume.  (optional)
        :type snapshot:  :class:`.VolumeSnapshot`

        :param location: Datacenter in which to create a volume in.
        :type location: :class:`.ExEC2AvailabilityZone`

        :param ex_volume_type: Type of volume to create.
        :type ex_volume_type: ``str``

        :param iops: The number of I/O operations per second (IOPS)
                     that the volume supports. Only used if ex_volume_type
                     is io1.
        :type iops: ``int``

        :return: The newly created volume.
        :rtype: :class:`StorageVolume`
        """
        return super(Ec2Adapter, self).create_volume(size, name, location=location, snapshot=snapshot,ex_volume_type=ex_volume_type, ex_iops=ex_iops)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def create_volume_snapshot(self, volume, name=None):
        """
        Create snapshot from volume

        :param      volume: Instance of ``StorageVolume``
        :type       volume: ``StorageVolume``

        :param      name: Name of snapshot (optional)
        :type       name: ``str``

        :rtype: :class:`VolumeSnapshot`
        """
        return super(Ec2Adapter, self).create_volume_snapshot(volume, name=name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def delete_image(self, image):
        """
        Deletes an image at Amazon given a NodeImage object

        @inherits: :class:`NodeDriver.delete_image`

        :param image: Instance of ``NodeImage``
        :type image: :class: `NodeImage`

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).delete_image( image)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def delete_key_pair(self, key_pair):
        return  super(Ec2Adapter, self).delete_key_pair(key_pair)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def destroy_node(self, node):
        return  super(Ec2Adapter, self).destroy_node(node)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def destroy_volume(self, volume):
        return  super(Ec2Adapter, self).destroy_volume(volume)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def destroy_volume_snapshot(self, snapshot):
        return  super(Ec2Adapter, self).destroy_volume_snapshot(snapshot)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def detach_volume(self, volume):
        return super(Ec2Adapter, self).detach_volume(volume)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_allocate_address(self, domain='standard'):
        """
        Allocate a new Elastic IP address for EC2 classic or VPC

        :param      domain: The domain to allocate the new address in
                            (standard/vpc)
        :type       domain: ``str``

        :return:    Instance of ElasticIP
        :rtype:     :class:`ElasticIP`
        """
        return super(Ec2Adapter, self).ex_allocate_address(domain=domain)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_associate_address_with_node(self, node, elastic_ip, domain=None):
        """
        Associate an Elastic IP address with a particular node.

        :param      node: Node instance
        :type       node: :class:`Node`

        :param      elastic_ip: Elastic IP instance
        :type       elastic_ip: :class:`ElasticIP`

        :param      domain: The domain where the IP resides (vpc only)
        :type       domain: ``str``

        :return:    A string representation of the association ID which is
                    required for VPC disassociation. EC2/standard
                    addresses return None
        :rtype:     ``None`` or ``str``
        """
        return super(Ec2Adapter, self).ex_associate_address_with_node(node, elastic_ip, domain=domain)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_associate_addresses(self, node, elastic_ip, domain=None):
        """
        Note: This method has been deprecated in favor of
        the ex_associate_address_with_node method.
        """

        return super(Ec2Adapter, self).ex_associate_addresses(node=node,
                                                   elastic_ip=elastic_ip,
                                                   domain=domain)
        
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))   
    def ex_associate_route_table(self, route_table, subnet):
        """
        Associates a route table with a subnet within a VPC.

        Note: A route table can be associated with multiple subnets.

        :param      route_table: The route table to associate.
        :type       route_table: :class:`.EC2RouteTable`

        :param      subnet: The subnet to associate with.
        :type       subnet: :class:`.EC2Subnet`

        :return:    Route table association ID.
        :rtype:     ``str``
        """

        return super(Ec2Adapter, self).ex_associate_route_table(route_table, subnet)

    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_attach_internet_gateway(self, gateway, network):
        """
        Attach an Internet gateway to a VPC

        :param      gateway: The gateway to attach
        :type       gateway: :class:`.VPCInternetGateway`

        :param      network: The VPC network to attach to
        :type       network: :class:`.EC2Network`

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_attach_internet_gateway(gateway, network)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_attach_network_interface_to_node(self, network_interface,
                                            node, device_index):
        """
        Attach a network interface to an instance.

        :param      network_interface: EC2NetworkInterface instance
        :type       network_interface: :class:`EC2NetworkInterface`

        :param      node: Node instance
        :type       node: :class:`Node`

        :param      device_index: The interface device index
        :type       device_index: ``int``

        :return:    String representation of the attachment id.
                    This is required to detach the interface.
        :rtype:     ``str``
        """
        return super(Ec2Adapter, self).ex_attach_network_interface_to_node(network_interface, node, device_index)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_authorize_security_group(self, name, from_port, to_port, cidr_ip,
                                    protocol='tcp'):
        """
        Edit a Security Group to allow specific traffic.

        @note: This is a non-standard extension API, and only works for EC2.

        :param      name: The name of the security group to edit
        :type       name: ``str``

        :param      from_port: The beginning of the port range to open
        :type       from_port: ``str``

        :param      to_port: The end of the port range to open
        :type       to_port: ``str``

        :param      cidr_ip: The ip to allow traffic for.
        :type       cidr_ip: ``str``

        :param      protocol: tcp/udp/icmp
        :type       protocol: ``str``

        :rtype: ``bool``
        """

        return  super(Ec2Adapter, self).ex_authorize_security_group(name, from_port, to_port, cidr_ip,protocol=protocol)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))       
    def ex_authorize_security_group_egress(self, id, from_port, to_port,
                                           cidr_ips, group_pairs=None,
                                           protocol='tcp'):
        """
        Edit a Security Group to allow specific egress traffic using
        CIDR blocks or either a group ID, group name or user ID (account).
        This call is not supported for EC2 classic and only works for VPC
        groups.

        :param      id: The id of the security group to edit
        :type       id: ``str``

        :param      from_port: The beginning of the port range to open
        :type       from_port: ``int``

        :param      to_port: The end of the port range to open
        :type       to_port: ``int``

        :param      cidr_ips: The list of ip ranges to allow traffic for.
        :type       cidr_ips: ``list``

        :param      group_pairs: Source user/group pairs to allow traffic for.
                    More info can be found at http://goo.gl/stBHJF

                    EC2 Classic Example: To allow access from any system
                    associated with the default group on account 1234567890

                    [{'group_name': 'default', 'user_id': '1234567890'}]

                    VPC Example: Allow access from any system associated with
                    security group sg-47ad482e on your own account

                    [{'group_id': ' sg-47ad482e'}]
        :type       group_pairs: ``list`` of ``dict``

        :param      protocol: tcp/udp/icmp
        :type       protocol: ``str``

        :rtype: ``bool``
        """

        return super(Ec2Adapter, self).ex_authorize_security_group_egress(id, from_port, to_port,cidr_ips, group_pairs=group_pairs, protocol=protocol)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))   
    def ex_authorize_security_group_ingress(self, id, from_port, to_port,
                                            cidr_ips=None, group_pairs=None,
                                            protocol='tcp'):
        """
        Edit a Security Group to allow specific ingress traffic using
        CIDR blocks or either a group ID, group name or user ID (account).

        :param      id: The id of the security group to edit
        :type       id: ``str``

        :param      from_port: The beginning of the port range to open
        :type       from_port: ``int``

        :param      to_port: The end of the port range to open
        :type       to_port: ``int``

        :param      cidr_ips: The list of ip ranges to allow traffic for.
        :type       cidr_ips: ``list``

        :param      group_pairs: Source user/group pairs to allow traffic for.
                    More info can be found at http://goo.gl/stBHJF

                    EC2 Classic Example: To allow access from any system
                    associated with the default group on account 1234567890

                    [{'group_name': 'default', 'user_id': '1234567890'}]

                    VPC Example: Allow access from any system associated with
                    security group sg-47ad482e on your own account

                    [{'group_id': ' sg-47ad482e'}]
        :type       group_pairs: ``list`` of ``dict``

        :param      protocol: tcp/udp/icmp
        :type       protocol: ``str``

        :rtype: ``bool``
        """

        return  super(Ec2Adapter, self).ex_authorize_security_group_ingress(id, from_port, to_port,
                                            cidr_ips=cidr_ips, group_pairs=group_pairs,
                                            protocol=protocol)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_authorize_security_group_permissive(self, name):
        """
        Edit a Security Group to allow all traffic.

        @note: This is a non-standard extension API, and only works for EC2.

        :param      name: The name of the security group to edit
        :type       name: ``str``

        :rtype: ``list`` of ``str``
        """

        return super(Ec2Adapter, self).ex_authorize_security_group_permissive(name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_change_node_size(self, node, new_size):
        """
        Change the node size.
        Note: Node must be turned of before changing the size.

        :param      node: Node instance
        :type       node: :class:`Node`

        :param      new_size: NodeSize intance
        :type       new_size: :class:`NodeSize`

        :return: True on success, False otherwise.
        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_change_node_size(node, new_size)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_internet_gateway(self, name=None):
        """
        Delete a VPC Internet gateway

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_create_internet_gateway(name=name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_keypair(self, name):
        """
        Creates a new keypair

        @note: This is a non-standard extension API, and only works for EC2.

        :param      name: The name of the keypair to Create. This must be
            unique, otherwise an InvalidKeyPair.Duplicate exception is raised.
        :type       name: ``str``

        :rtype: ``dict``
        """
        return super(Ec2Adapter, self).ex_create_keypair(name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_network(self, cidr_block, name=None,
                          instance_tenancy='default'):
        """
        Create a network/VPC

        :param      cidr_block: The CIDR block assigned to the network
        :type       cidr_block: ``str``

        :param      name: An optional name for the network
        :type       name: ``str``

        :param      instance_tenancy: The allowed tenancy of instances launched
                                      into the VPC.
                                      Valid values: default/dedicated
        :type       instance_tenancy: ``str``

        :return:    Dictionary of network properties
        :rtype:     ``dict``
        """
        return super(Ec2Adapter, self).ex_create_network(cidr_block, name=name,instance_tenancy=instance_tenancy)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_network_interface(self, subnet, name=None,
                                    description=None,
                                    private_ip_address=None):
        """
        Create a network interface within a VPC subnet.

        :param      subnet: EC2NetworkSubnet instance
        :type       subnet: :class:`EC2NetworkSubnet`

        :param      name:  Optional name of the interface
        :type       name:  ``str``

        :param      description:  Optional description of the network interface
        :type       description:  ``str``

        :param      private_ip_address: Optional address to assign as the
                                        primary private IP address of the
                                        interface. If one is not provided then
                                        Amazon will automatically auto-assign
                                        an available IP. EC2 allows assignment
                                        of multiple IPs, but this will be
                                        the primary.
        :type       private_ip_address: ``str``

        :return:    EC2NetworkInterface instance
        :rtype:     :class `EC2NetworkInterface`
        """
        """
        Create a network interface within a VPC subnet.

        :param      subnet: EC2NetworkSubnet instance
        :type       subnet: :class:`EC2NetworkSubnet`

        :param      name:  Optional name of the interface
        :type       name:  ``str``

        :param      description:  Optional description of the network interface
        :type       description:  ``str``

        :param      private_ip_address: Optional address to assign as the
                                        primary private IP address of the
                                        interface. If one is not provided then
                                        Amazon will automatically auto-assign
                                        an available IP. EC2 allows assignment
                                        of multiple IPs, but this will be
                                        the primary.
        :type       private_ip_address: ``str``

        :return:    EC2NetworkInterface instance
        :rtype:     :class `EC2NetworkInterface`
        """
        params = {'Action': 'CreateNetworkInterface',
                  'SubnetId': subnet.id}

        if description:
            params['Description'] = description

        if private_ip_address:
            params['PrivateIpAddress'] = private_ip_address

        response = self.connection.request(self.path, params=params).object

        elements = response.findall(fixxpath(xpath='networkInterface',
                                            namespace=self.name_space))
        if elements is None or len(elements) == 0:
            raise Exception('create networkInterface failed')
        
        element = elements[0]

        interface = self._to_interface(element, name)

        if name and self.ex_create_tags(interface, {'Name': name}):
            interface.extra['tags']['Name'] = name

        return interface
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_placement_group(self, name):
        """
        Creates new Placement Group

        :param name: Name for new placement Group
        :type name: ``str``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_create_placement_group(name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_route(self, route_table, cidr,
                        internet_gateway=None, node=None,
                        network_interface=None, vpc_peering_connection=None):
        """
        Creates a route entry in the route table.

        :param      route_table: The route table to create the route in.
        :type       route_table: :class:`.EC2RouteTable`

        :param      cidr: The CIDR block used for the destination match.
        :type       cidr: ``str``

        :param      internet_gateway: The internet gateway to route
                                      traffic through.
        :type       internet_gateway: :class:`.VPCInternetGateway`

        :param      node: The NAT instance to route traffic through.
        :type       node: :class:`Node`

        :param      network_interface: The network interface of the node
                                       to route traffic through.
        :type       network_interface: :class:`.EC2NetworkInterface`

        :param      vpc_peering_connection: The VPC peering connection.
        :type       vpc_peering_connection: :class:`.VPCPeeringConnection`

        :rtype:     ``bool``

        Note: You must specify one of the following: internet_gateway,
              node, network_interface, vpc_peering_connection.
        """

        return super(Ec2Adapter, self).ex_create_route(route_table, cidr,
                        internet_gateway=internet_gateway, node=node,
                        network_interface=network_interface, vpc_peering_connection=vpc_peering_connection)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_route_table(self, network, name=None):
        """
        Create a route table within a VPC.

        :param      vpc_id: The VPC that the subnet should be created in.
        :type       vpc_id: :class:`.EC2Network`

        :rtype:     :class: `.EC2RouteTable`
        """
        return super(Ec2Adapter, self).ex_create_route_table(network, name=name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_security_group(self, name, description, vpc_id=None):
        """
        Creates a new Security Group in EC2-Classic or a targeted VPC.

        :param      name:        The name of the security group to Create.
                                 This must be unique.
        :type       name:        ``str``

        :param      description: Human readable description of a Security
                                 Group.
        :type       description: ``str``

        :param      vpc_id:      Optional identifier for VPC networks
        :type       vpc_id:      ``str``

        :rtype: ``dict``
        """
        return super(Ec2Adapter, self).ex_create_security_group(name, description, vpc_id=vpc_id)
        
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_subnet(self, vpc_id, cidr_block,
                         availability_zone, name=None):
        """
        Create a network subnet within a VPC

        :param      vpc_id: The ID of the VPC that the subnet should be
                            associated with
        :type       vpc_id: ``str``

        :param      cidr_block: The CIDR block assigned to the subnet
        :type       cidr_block: ``str``

        :param      availability_zone: The availability zone where the subnet
                                       should reside
        :type       availability_zone: ``str``

        :param      name: An optional name for the network
        :type       name: ``str``

        :rtype:     :class: `EC2NetworkSubnet`
        """
        return  super(Ec2Adapter, self).ex_create_subnet(vpc_id, cidr_block,
                         availability_zone, name=name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_create_tags(self, resource, tags):
        """
        Create tags for a resource (Node or StorageVolume).

        :param resource: Resource to be tagged
        :type resource: :class:`Node` or :class:`StorageVolume` or
                        :class:`VolumeSnapshot`

        :param tags: A dictionary or other mapping of strings to strings,
                     associating tag names with tag values.
        :type tags: ``dict``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_create_tags(resource, tags)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_internet_gateway(self, gateway):
        """
        Delete a VPC Internet gateway

        :param      gateway: The gateway to delete
        :type       gateway: :class:`.VPCInternetGateway`

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_internet_gateway(gateway)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_keypair(self, keypair):
        """
        Delete a key pair by name.

        @note: This is a non-standard extension API, and only works with EC2.

        :param      keypair: The name of the keypair to delete.
        :type       keypair: ``str``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_keypair(keypair)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_network(self, vpc):
        """
        Deletes a network/VPC.

        :param      vpc: VPC to delete.
        :type       vpc: :class:`.EC2Network`

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_network(vpc)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_network_interface(self, network_interface):
        """
        Deletes a network interface.

        :param      network_interface: EC2NetworkInterface instance
        :type       network_interface: :class:`EC2NetworkInterface`

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_network_interface(network_interface)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_placement_group(self, name):
        """
        Deletes Placement Group

        :param name: Placement Group name
        :type name: ``str``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_placement_group(name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_route(self, route_table, cidr):
        """
        Deletes a route entry from the route table.

        :param      route_table: The route table to delete the route from.
        :type       route_table: :class:`.EC2RouteTable`

        :param      cidr: The CIDR block used for the destination match.
        :type       cidr: ``str``

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_route(route_table, cidr)
        
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_route_table(self, route_table):
        """
        Deletes a VPC route table.

        :param      route_table: The route table to delete.
        :type       route_table: :class:`.EC2RouteTable`

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_route_table( route_table)
         
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_security_group(self, name):
        """
        Wrapper method which calls ex_delete_security_group_by_name.

        :param      name: The name of the security group
        :type       name: ``str``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_security_group(name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_security_group_by_id(self, group_id):
        """
        Deletes a new Security Group using the group id.

        :param      group_id: The ID of the security group
        :type       group_id: ``str``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_security_group_by_id(group_id)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_security_group_by_name(self, group_name):
        """
        Deletes a new Security Group using the group name.

        :param      group_name: The name of the security group
        :type       group_name: ``str``

        :rtype: ``bool``
        """
        return  super(Ec2Adapter, self).ex_delete_security_group_by_name(group_name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_subnet(self, subnet):
        """
        Deletes a VPC subnet.

        :param      subnet: The subnet to delete
        :type       subnet: :class:`.EC2NetworkSubnet`

        :rtype:     ``bool``
        """
        return  super(Ec2Adapter, self).ex_delete_subnet(subnet)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_delete_tags(self, resource, tags):
        """
        Delete tags from a resource.

        :param resource: Resource to be tagged
        :type resource: :class:`Node` or :class:`StorageVolume`

        :param tags: A dictionary or other mapping of strings to strings,
                     specifying the tag names and tag values to be deleted.
        :type tags: ``dict``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_delete_tags(resource, tags)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_describe_addresses(self, nodes):
        """
        Return Elastic IP addresses for all the nodes in the provided list.

        :param      nodes: List of :class:`Node` instances
        :type       nodes: ``list`` of :class:`Node`

        :return:    Dictionary where a key is a node ID and the value is a
                    list with the Elastic IP addresses associated with
                    this node.
        :rtype:     ``dict``
        """
        return super(Ec2Adapter, self).ex_describe_addresses(nodes)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_describe_keypair(self, name):
        """
        Describes a keypair by name.

        @note: This is a non-standard extension API, and only works for EC2.

        :param      name: The name of the keypair to describe.
        :type       name: ``str``

        :rtype: ``dict``
        """

        return super(Ec2Adapter, self).ex_describe_keypair(name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))   
    def ex_describe_tags(self, resource):
        """
        Return a dictionary of tags for a resource (e.g. Node or
        StorageVolume).

        :param  resource: resource which should be used
        :type   resource: any resource class, such as :class:`Node,`
                :class:`StorageVolume,` or :class:NodeImage`

        :return: dict Node tags
        :rtype: ``dict``
        """
        return super(Ec2Adapter, self).ex_describe_tags( resource)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_detach_internet_gateway(self, gateway, network):
        """
        Detach an Internet gateway from a VPC

        :param      gateway: The gateway to detach
        :type       gateway: :class:`.VPCInternetGateway`

        :param      network: The VPC network to detach from
        :type       network: :class:`.EC2Network`

        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_detach_internet_gateway(gateway, network)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_detach_network_interface(self, attachment_id, force=False):
        """
        Detach a network interface from an instance.

        :param      attachment_id: The attachment ID associated with the
                                   interface
        :type       attachment_id: ``str``

        :param      force: Forces the detachment.
        :type       force: ``bool``

        :return:    ``True`` on successful detachment, ``False`` otherwise.
        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_detach_network_interface(attachment_id, force=force)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_disassociate_address(self, elastic_ip, domain=None):
        """
        Disassociate an Elastic IP address using the IP (EC2-Classic)
        or the association ID (VPC)

        :param      elastic_ip: ElasticIP instance
        :type       elastic_ip: :class:`ElasticIP`

        :param      domain: The domain where the IP resides (vpc only)
        :type       domain: ``str``

        :return:    True on success, False otherwise.
        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_disassociate_address(elastic_ip, domain=domain)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_dissociate_route_table(self, subnet_association):
        """
        Dissociates a subnet from a route table.

        :param      subnet_association: The subnet association object or
                                        subnet association ID.
        :type       subnet_association: :class:`.EC2SubnetAssociation` or
                                        ``str``

        :rtype:     ``bool``
        """

        return  super(Ec2Adapter, self).ex_dissociate_route_table(subnet_association)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_get_console_output(self, node):
        """
        Get console output for the node.

        :param      node: Node which should be used
        :type       node: :class:`Node`

        :return:    Dictionary with the following keys:
                    - instance_id (``str``)
                    - timestamp (``datetime.datetime``) - ts of the last output
                    - output (``str``) - console output
        :rtype:     ``dict``
        """
        return super(Ec2Adapter, self).ex_get_console_output(node)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_internet_gateways(self, gateway_ids=None, filters=None):
        """
        Describes available Internet gateways and whether or not they are
        attached to a VPC. These are required for VPC nodes to communicate
        over the Internet.

        :param      gateway_ids: Return only intenet gateways matching the
                                 provided internet gateway IDs. If not
                                 specified, a list of all the internet
                                 gateways in the corresponding region is
                                 returned.
        :type       gateway_ids: ``list``

        :param      filters: The filters so that the response includes
                             information for only certain gateways.
        :type       filters: ``dict``

        :rtype: ``list`` of :class:`.VPCInternetGateway`
        """
        return super(Ec2Adapter, self).ex_list_internet_gateways( gateway_ids=gateway_ids, filters=filters)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_describe_all_addresses(self, only_associated=False):
        """
        Return all the Elastic IP addresses for this account
        optionally, return only addresses associated with nodes

        :param    only_associated: If true, return only those addresses
                                   that are associated with an instance.
        :type     only_associated: ``bool``

        :return:  List of ElasticIP instances.
        :rtype:   ``list`` of :class:`ElasticIP`
        """
        return super(Ec2Adapter, self).ex_describe_all_addresses(only_associated=only_associated)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_get_security_groups(self, group_ids=None,
                               group_names=None, filters=None):
        """
        Return a list of :class:`EC2SecurityGroup` objects for the
        current region.

        :param      group_ids: Return only groups matching the provided
                               group IDs.
        :type       group_ids: ``list``

        :param      group_names: Return only groups matching the provided
                                 group names.
        :type       group_ids: ``list``

        :param      filters: The filters so that the response includes
                             information for only specific security groups.
        :type       filters: ``dict``

        :rtype:     ``list`` of :class:`EC2SecurityGroup`
        """

        return super(Ec2Adapter, self).ex_get_security_groups(group_ids=group_ids,
                               group_names=group_names, filters=filters)
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_availability_zones(self, only_available=True):
        """
        Return a list of :class:`ExEC2AvailabilityZone` objects for the
        current region.

        Note: This is an extension method and is only available for EC2
        driver.

        :keyword  only_available: If true, return only availability zones
                                  with state 'available'
        :type     only_available: ``str``

        :rtype: ``list`` of :class:`ExEC2AvailabilityZone`
        """
        return super(Ec2Adapter, self).ex_list_availability_zones(only_available=only_available)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_network_interfaces(self,network_interfaces=None,node=None,ex_filters=None):
         
        """
        Return all network interfaces

        :return:    List of EC2NetworkInterface instances
        :rtype:     ``list`` of :class `EC2NetworkInterface`
        """
        params = {'Action': 'DescribeNetworkInterfaces'}
        
        if node:
            filters = {'attachment.instance-id': node.id}
            params.update(self._build_filters(filters))
            
        if network_interfaces:
            params.update(self._pathlist('NetworkInterfaceId', network_interfaces))

        if ex_filters:
            params.update(self._build_filters(ex_filters))

        return self._to_interfaces(
            self.connection.request(self.path, params=params).object
        )

    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_networks(self, network_ids=None, filters=None):
        """
        Return a list of :class:`EC2Network` objects for the
        current region.

        :param      network_ids: Return only networks matching the provided
                                 network IDs. If not specified, a list of all
                                 the networks in the corresponding region
                                 is returned.
        :type       network_ids: ``list``

        :param      filters: The filters so that the response includes
                             information for only certain networks.
        :type       filters: ``dict``

        :rtype:     ``list`` of :class:`EC2Network`
        """
        return super(Ec2Adapter, self).ex_list_networks(network_ids=network_ids, filters=filters)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_placement_groups(self, names=None):
        """
        List Placement Groups

        :param names: Placement Group names
        :type names: ``list`` of ``str``

        :rtype: ``list`` of :class:`.EC2PlacementGroup`
        """
        return  super(Ec2Adapter, self).ex_list_placement_groups(names=names)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_reserved_nodes(self):
        """
        List all reserved instances/nodes which can be purchased from Amazon
        for one or three year terms. Reservations are made at a region level
        and reduce the hourly charge for instances.

        More information can be found at http://goo.gl/ulXCC7.

        :rtype: ``list`` of :class:`.EC2ReservedNode`
        """
        return  super(Ec2Adapter, self).ex_list_reserved_nodes()
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_route_tables(self, route_table_ids=None, filters=None):
        """
        Describes one or more of a VPC's route tables.
        These are used to determine where network traffic is directed.

        :param      route_table_ids: Return only route tables matching the
                                provided route table IDs. If not specified,
                                a list of all the route tables in the
                                corresponding region is returned.
        :type       route_table_ids: ``list``

        :param      filters: The filters so that the response includes
                             information for only certain route tables.
        :type       filters: ``dict``

        :rtype: ``list`` of :class:`.EC2RouteTable`
        """
        return super(Ec2Adapter, self).ex_list_route_tables(route_table_ids=route_table_ids, filters=filters)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_security_groups(self):
        """
        List existing Security Groups.

        @note: This is a non-standard extension API, and only works for EC2.

        :rtype: ``list`` of ``str``
        """
        return super(Ec2Adapter, self).ex_list_security_groups()
    
    @ErrorDecorator(exceptions=(HttpException))     
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_list_subnets(self, subnet_ids=None, filters=None):
        """
        Return a list of :class:`EC2NetworkSubnet` objects for the
        current region.

        :param      subnet_ids: Return only subnets matching the provided
                                subnet IDs. If not specified, a list of all
                                the subnets in the corresponding region
                                is returned.
        :type       subnet_ids: ``list``

        :param      filters: The filters so that the response includes
                             information for only certain subnets.
        :type       filters: ``dict``

        :rtype:     ``list`` of :class:`EC2NetworkSubnet`
        """
        return  super(Ec2Adapter, self).ex_list_subnets(subnet_ids=subnet_ids, filters=filters)
        
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_modify_image_attribute(self, image, attributes):
        """
        Modify image attributes.

        :param      image: NodeImage instance
        :type       image: :class:`NodeImage`

        :param      attributes: Dictionary with node attributes
        :type       attributes: ``dict``

        :return: True on success, False otherwise.
        :rtype: ``bool``
        """
        return  super(Ec2Adapter, self).ex_modify_image_attribute(image, attributes)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_modify_instance_attribute(self, node, attributes):
        """
        Modify node attributes.
        A list of valid attributes can be found at http://goo.gl/gxcj8

        :param      node: Node instance
        :type       node: :class:`Node`

        :param      attributes: Dictionary with node attributes
        :type       attributes: ``dict``

        :return: True on success, False otherwise.
        :rtype: ``bool``
        """
        return  super(Ec2Adapter, self).ex_modify_instance_attribute(node, attributes)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_register_image(self, name, description=None, architecture=None,
                          image_location=None, root_device_name=None,
                          block_device_mapping=None, kernel_id=None,
                          ramdisk_id=None, virtualization_type=None):
        """
        Registers an Amazon Machine Image based off of an EBS-backed instance.
        Can also be used to create images from snapshots. More information
        can be found at http://goo.gl/hqZq0a.

        :param      name:  The name for the AMI being registered
        :type       name: ``str``

        :param      description: The description of the AMI (optional)
        :type       description: ``str``

        :param      architecture: The architecture of the AMI (i386/x86_64)
                                  (optional)
        :type       architecture: ``str``

        :param      image_location: The location of the AMI within Amazon S3
                                    Required if registering an instance
                                    store-backed AMI
        :type       image_location: ``str``

        :param      root_device_name: The device name for the root device
                                      Required if registering an EBS-backed AMI
        :type       root_device_name: ``str``

        :param      block_device_mapping: A dictionary of the disk layout
                                          (optional)
        :type       block_device_mapping: ``dict``

        :param      kernel_id: Kernel id for AMI (optional)
        :type       kernel_id: ``str``

        :param      ramdisk_id: RAM disk for AMI (optional)
        :type       ramdisk_id: ``str``

        :param      virtualization_type: The type of virtualization for the
                                         AMI you are registering, paravirt
                                         or hvm (optional)
        :type       virtualization_type: ``str``

        :rtype:     :class:`NodeImage`
        """
        return super(Ec2Adapter, self).ex_register_image(name, description=description, architecture=architecture,
                          image_location=image_location, root_device_name=root_device_name,
                          block_device_mapping=block_device_mapping, kernel_id=kernel_id,
                          ramdisk_id=ramdisk_id, virtualization_type=virtualization_type)
        
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_release_address(self, elastic_ip, domain=None):
        """
        Release an Elastic IP address using the IP (EC2-Classic) or
        using the allocation ID (VPC)

        :param      elastic_ip: Elastic IP instance
        :type       elastic_ip: :class:`ElasticIP`

        :param      domain: The domain where the IP resides (vpc only)
        :type       domain: ``str``

        :return:    True on success, False otherwise.
        :rtype:     ``bool``
        """
        return super(Ec2Adapter, self).ex_release_address(elastic_ip, domain=domain)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_replace_route(self, route_table, cidr,
                         internet_gateway=None, node=None,
                         network_interface=None, vpc_peering_connection=None):
        """
        Replaces an existing route entry within a route table in a VPC.

        :param      route_table: The route table to replace the route in.
        :type       route_table: :class:`.EC2RouteTable`

        :param      cidr: The CIDR block used for the destination match.
        :type       cidr: ``str``

        :param      internet_gateway: The new internet gateway to route
                                       traffic through.
        :type       internet_gateway: :class:`.VPCInternetGateway`

        :param      node: The new NAT instance to route traffic through.
        :type       node: :class:`Node`

        :param      network_interface: The new network interface of the node
                                       to route traffic through.
        :type       network_interface: :class:`.EC2NetworkInterface`

        :param      vpc_peering_connection: The new VPC peering connection.
        :type       vpc_peering_connection: :class:`.VPCPeeringConnection`

        :rtype:     ``bool``

        Note: You must specify one of the following: internet_gateway,
              node, network_interface, vpc_peering_connection.
        """
        return super(Ec2Adapter, self).ex_replace_route(route_table, cidr,
                         internet_gateway=internet_gateway, node=node,
                         network_interface=network_interface, vpc_peering_connection=vpc_peering_connection)
         
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_replace_route_table_association(self, subnet_association,
                                           route_table):
        """
        Changes the route table associated with a given subnet in a VPC.

        Note: This method can be used to change which table is the main route
              table in the VPC (Specify the main route table's association ID
              and the route table to be the new main route table).

        :param      subnet_association: The subnet association object or
                                        subnet association ID.
        :type       subnet_association: :class:`.EC2SubnetAssociation` or
                                        ``str``

        :param      route_table: The new route table to associate.
        :type       route_table: :class:`.EC2RouteTable`

        :return:    New route table association ID.
        :rtype:     ``str``
        """
        return super(Ec2Adapter, self).ex_replace_route_table_association(subnet_association,
                                           route_table)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_revoke_security_group_egress(self, id, from_port, to_port,
                                        cidr_ips=None, group_pairs=None,
                                        protocol='tcp'):
        """
        Edit a Security Group to revoke specific egress traffic using
        CIDR blocks or either a group ID, group name or user ID (account).
        This call is not supported for EC2 classic and only works for
        VPC groups.

        :param      id: The id of the security group to edit
        :type       id: ``str``

        :param      from_port: The beginning of the port range to open
        :type       from_port: ``int``

        :param      to_port: The end of the port range to open
        :type       to_port: ``int``

        :param      cidr_ips: The list of ip ranges to allow traffic for.
        :type       cidr_ips: ``list``

        :param      group_pairs: Source user/group pairs to allow traffic for.
                    More info can be found at http://goo.gl/stBHJF

                    EC2 Classic Example: To allow access from any system
                    associated with the default group on account 1234567890

                    [{'group_name': 'default', 'user_id': '1234567890'}]

                    VPC Example: Allow access from any system associated with
                    security group sg-47ad482e on your own account

                    [{'group_id': ' sg-47ad482e'}]
        :type       group_pairs: ``list`` of ``dict``

        :param      protocol: tcp/udp/icmp
        :type       protocol: ``str``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_revoke_security_group_egress(id, from_port, to_port,
                                        cidr_ips=cidr_ips, group_pairs=group_pairs,
                                        protocol=protocol)
        
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_revoke_security_group_ingress(self, id, from_port, to_port,
                                         cidr_ips=None, group_pairs=None,
                                         protocol='tcp'):
        """
        Edit a Security Group to revoke specific ingress traffic using
        CIDR blocks or either a group ID, group name or user ID (account).

        :param      id: The id of the security group to edit
        :type       id: ``str``

        :param      from_port: The beginning of the port range to open
        :type       from_port: ``int``

        :param      to_port: The end of the port range to open
        :type       to_port: ``int``

        :param      cidr_ips: The list of ip ranges to allow traffic for.
        :type       cidr_ips: ``list``

        :param      group_pairs: Source user/group pairs to allow traffic for.
                    More info can be found at http://goo.gl/stBHJF

                    EC2 Classic Example: To allow access from any system
                    associated with the default group on account 1234567890

                    [{'group_name': 'default', 'user_id': '1234567890'}]

                    VPC Example: Allow access from any system associated with
                    security group sg-47ad482e on your own account

                    [{'group_id': ' sg-47ad482e'}]
        :type       group_pairs: ``list`` of ``dict``

        :param      protocol: tcp/udp/icmp
        :type       protocol: ``str``

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_revoke_security_group_ingress( id, from_port, to_port,
                                         cidr_ips=cidr_ips, group_pairs=group_pairs,
                                         protocol=protocol)
        
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_start_node(self, node):
        """
        Start the node by passing in the node object, does not work with
        instance store backed instances

        :param      node: Node which should be used
        :type       node: :class:`Node`

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_start_node(node)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def ex_stop_node(self, node):
        """
        Stop the node by passing in the node object, does not work with
        instance store backed instances

        :param      node: Node which should be used
        :type       node: :class:`Node`

        :rtype: ``bool``
        """
        return super(Ec2Adapter, self).ex_stop_node(node)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def get_image(self, image_id):
        """
        Get an image based on an image_id

        :param image_id: Image identifier
        :type image_id: ``str``

        :return: A NodeImage object
        :rtype: :class:`NodeImage`

        """
        image = super(Ec2Adapter, self).get_image(image_id)
        return Image(image.id,image.name,image.driver,extra = image.extra)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def get_key_pair(self, name):
        return super(Ec2Adapter, self).get_key_pair(name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def import_key_pair_from_string(self, name, key_material):
        return super(Ec2Adapter, self).import_key_pair_from_string(name, key_material)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def list_images(self, location=None, ex_image_ids=None, ex_owner=None,
                    ex_executableby=None, ex_filters=None):
        """
        List all images
        @inherits: :class:`NodeDriver.list_images`

        Ex_image_ids parameter is used to filter the list of
        images that should be returned. Only the images
        with the corresponding image ids will be returned.

        Ex_owner parameter is used to filter the list of
        images that should be returned. Only the images
        with the corresponding owner will be returned.
        Valid values: amazon|aws-marketplace|self|all|aws id

        Ex_executableby parameter describes images for which
        the specified user has explicit launch permissions.
        The user can be an AWS account ID, self to return
        images for which the sender of the request has
        explicit launch permissions, or all to return
        images with public launch permissions.
        Valid values: all|self|aws id

        Ex_filters parameter is used to filter the list of
        images that should be returned. Only images matchind
        the filter will be returned.

        :param      ex_image_ids: List of ``NodeImage.id``
        :type       ex_image_ids: ``list`` of ``str``

        :param      ex_owner: Owner name
        :type       ex_owner: ``str``

        :param      ex_executableby: Executable by
        :type       ex_executableby: ``str``

        :param      ex_filters: Filter by
        :type       ex_filters: ``dict``

        :rtype: ``list`` of :class:`NodeImage`
        """
        return super(Ec2Adapter, self).list_images(location=location, ex_image_ids=ex_image_ids, ex_owner=ex_owner,
                    ex_executableby=ex_executableby, ex_filters=ex_filters)
    
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def list_key_pairs(self):
        return super(Ec2Adapter, self).list_key_pairs()

        
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def list_locations(self):
        return  super(Ec2Adapter, self).list_locations()
     
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def list_nodes(self, ex_node_ids=None, ex_filters=None):
        """
        List all nodes

        Ex_node_ids parameter is used to filter the list of
        nodes that should be returned. Only the nodes
        with the corresponding node ids will be returned.

        :param      ex_node_ids: List of ``node.id``
        :type       ex_node_ids: ``list`` of ``str``

        :param      ex_filters: The filters so that the response includes
                             information for only certain nodes.
        :type       ex_filters: ``dict``

        :rtype: ``list`` of :class:`Node`
        """
        return super(Ec2Adapter, self).list_nodes(ex_node_ids=ex_node_ids, ex_filters=ex_filters)
         
    @ErrorDecorator(exceptions=(HttpException)) 
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=3,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def list_snapshots(self, snapshot=None, owner=None,snapshot_ids=None, ex_filters=None):
        """
        Describe all snapshots.

        :param snapshot: If provided, only return snapshot information for the
                         provided snapshot.

        :param owner: Owner for snapshot: self|amazon|ID
        :type owner: ``str``

        :rtype: ``list`` of :class:`VolumeSnapshot`
        """
        params = {
            'Action': 'DescribeSnapshots',
        }
        if snapshot:
            params.update({
                'SnapshotId.1': snapshot.id,
            })
        if owner:
            params.update({
                'Owner.1': owner,
            })
        
        if snapshot_ids:
            for index, snapshot_id in enumerate(snapshot_ids):
                index += 1
                params.update({'SnapshotId.%s' % (index): snapshot_id})
            
        if ex_filters:    
            params.update(self._build_filters(ex_filters))
            
        response = self.connection.request(self.path, params=params).object
        snapshots = self._to_snapshots(response)
        return snapshots
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def reboot_node(self, node):
        return  super(Ec2Adapter, self).reboot_node(node)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError))
    def export_volume(self,volume_id, des_loc, des_filename,cgw_host_id,cgw_host_ip=None, **kwargs):
        """
        export volume to des_location, which is a local directory or s3 directory
        :param volume_id: volume
        :param des_loc:
        :param des_filename:
        :param cgw_host_id
        :param cgw_host_ip
        :param kwargs:
        :return: file_location
        """
        if cgw_host_ip is None:
            return self._export_volume_cgw_together(volume_id, des_loc, des_filename,cgw_host_id,cgw_host_ip=cgw_host_ip, **kwargs)
        else:
            return self._export_volume_cgw_not_together(volume_id, des_loc, des_filename,cgw_host_id,cgw_host_ip=cgw_host_ip, **kwargs)
 
    def _export_volume_cgw_not_together(self,volume_id, des_loc, des_filename,cgw_host_id,cgw_host_ip, **kwargs):
        transfer_station=kwargs.get("transfer_station")
        compute_gateway_certificate = kwargs.get('cgw_certificate')
        compute_gateway_username=kwargs.get('cgw_username')
        command="ssh -i %s %s@%s bash /home/aws_img.sh %s %s %s %s %s" % \
                            (compute_gateway_certificate,compute_gateway_username,cgw_host_ip,
                             volume_id ,cgw_host_id,des_loc,des_filename,transfer_station)
        result = subprocess.call([command], shell=True)
        if result != 0:
            return
        s3Driver=S3Adapter(self.key,self.secret,region=self.region,secure=False)
        s3_object=s3Driver.get_object(container_name=transfer_station,object_name=des_filename)
        if s3_object is None:
            return
        object_size = int(s3_object.size)
        file_absolute_path = des_loc+'/'+des_filename
        container = Container(name=transfer_station, extra={},
                               driver=s3Driver)
        obj = Object(name=des_filename,size=object_size, hash=None, extra={},
                 container=container, meta_data=None,
                 driver=s3Driver)
        #with open(file_absolute_path, 'wb') as f:
        #    for chunk in s3Driver.download_object_as_stream(obj,chunk_size=CHUNK_SIZE):
        #       if chunk:
        #           f.write(chunk)
        #           f.flush()
        s3Driver.download_object(obj, file_absolute_path)
        s3Driver.delete_object(obj)
        return file_absolute_path
        
    def _export_volume_cgw_together(self,volume_id, des_loc, des_filename,cgw_host_id,cgw_host_ip, **kwargs):
        if volume_id is None or cgw_host_id is None:
            return
        ex_volume_ids=[volume_id]
        volumes=self.list_volumes(None, ex_volume_ids, None)
        if not volumes:
            return
        if len(volumes) > 1:
            return
        volume=volumes[0]
        orgin_state=volume.state
        if orgin_state==2:
            self.detach_volume(volume)
            origin_attached_instance_id=volume.extra.get('instance_id')
            origin_mount_device=volume.extra.get('device')
        ex_node_ids=[cgw_host_id]
        instances=self.list_nodes(ex_node_ids, None)
        if not instances:
            return
        if len(instances)>1:
            return
        instance=instances[0]
        vols_of_node =self.list_volumes(node=instance)
        
        used_devices_of_node =[]
        for vol in vols_of_node:
            vol_device=vol.extra.get('device')
            used_devices_of_node.append(vol_device)
        
        devices_of_node=['/dev/xvda','/dev/xvdb','/dev/xvdc','/dev/xvdd','/dev/xvde','/dev/xvdf',
                         '/dev/xvdg','/dev/xvdh','/dev/xvdi','/dev/xvdj','/dev/xvdk','/dev/xvdl',
                        '/dev/xvdm','/dev/xvdn','/dev/xvdo','/dev/xvdp','/dev/xvdq',
                       '/dev/xvdr','/dev/xvds','/dev/xvdt']
       
        for device_of_node in devices_of_node:
            device_used =False
            device_sub_str=device_of_node[7:9]
            for used_device_of_node in used_devices_of_node:
                if device_sub_str in used_device_of_node:
                    device_used =True
                    break
            if not device_used:
                device = device_of_node
                break
        if orgin_state==2:
            volumes=self.list_volumes(None, ex_volume_ids, None)
            volume=volumes[0]
            current_state=volume.state
            while current_state != 0:
                time.sleep(2)
                volumes=self.list_volumes(None, ex_volume_ids, None)
                volume=volumes[0]
                current_state=volume.state   
        self.attach_volume(instance, volume, device)
        volumes=self.list_volumes(None, ex_volume_ids, None)
        volume=volumes[0]
        attachment_status=volume.extra.get('attachment_status')
        while attachment_status!='attached':
            time.sleep(2)
            volumes=self.list_volumes(None, ex_volume_ids, None)
            volume=volumes[0]
            attachment_status=volume.extra.get('attachment_status')
        des_file = des_loc + des_filename
        convert_commond = "qemu-img convert  -O %s %s %s" % \
                    (
                     'qcow2',
                     device,
                     des_file)
        convert_result = subprocess.call([convert_commond], shell=True)
        self.detach_volume(volume)
        if origin_attached_instance_id is not None:
            ex_node_ids=[origin_attached_instance_id]
            instances=self.list_nodes(ex_node_ids, None)
            if not instances:
                return des_file
            if len(instances)>1:
                return des_file
            origin_attached_instance=instances[0]
            volumes=self.list_volumes(None, ex_volume_ids, None)
            volume=volumes[0]
            current_state=volume.state  
            while current_state != 0:
                time.sleep(2)
                volumes=self.list_volumes(None, ex_volume_ids, None)
                volume=volumes[0]
                current_state=volume.state   
            self.attach_volume(origin_attached_instance, volume, origin_mount_device)   
        return des_file
    
    @ErrorDecorator(exceptions=(HttpException)) 
    def get_location(self,availability_zone_name):
        locations=self.list_locations()
        if locations is None:
            return
        for location in locations:
            if location.availability_zone.name == availability_zone_name:
                return location
 
class Ec2Adapter2(EC2NodeDriver):
    
    connectionCls= HuaweiConnection
     
    def __init__(self, key, secret=None, secure=False, host=None, port=None,
                 region='ap-southeast-1', **kwargs):
        
        self.name_space  = 'http://ec2.amazonaws.com/doc/%s/' % (self.connectionCls.version)
        super(Ec2Adapter2, self).__init__(key=key, secret=secret,
                                            secure=secure, host=host,
                                            port=port,region=region,**kwargs)
        self.region=region
        
    
    def create_import_image_task(self, src_loc, src_file, **kwargs):
        """
        import a image to provider from a file

        :param src_loc: s3 bucket name
        :param src_file: s3 key
        :param kwargs: other parameters
        :return: import task object
        """
        description =  kwargs.get("description")
        if src_loc is None or src_file is None:
            return
        params={
                'Action': 'ImportImage',
                'Description':description,
                'DiskContainer.1.UserBucket.S3Bucket':src_loc,
                'DiskContainer.1.UserBucket.S3Key':src_file,
                }
         
        response = self.connection.request(self.path, params=params).object
        return self._to_import_image_task_info(response,self)
     
         
   
    def create_import_volume_task(self, src_loc, src_file, src_file_format,src_file_size,
                      volume_size, **kwargs):
        """

        :param src_loc: s3 bucket and directory of source file
        :param src_file: souce file name in s3
        :param src_file_format: source file format. valid value: VMDK, RAW, VHD
        :param volume_size:
        :param volume_loc: amazon availability zone
        :return: import task object
        """
        if src_loc is None or src_file is None:
            return 
        if src_file_format not in ['VMDK','RAW','VHD']:
            raise ImageFormatNotValid
        
        manifest_file_name=self._create_manifest_url(src_loc, src_file, src_file_format,src_file_size,
                                                 volume_size, **kwargs)
        #manifest_file='l2fb8e59-6727-4896-a67b-2aba0809d2e9manifest.xml'
        image_manifest_url=self._create_import_manifest_url(src_loc,manifest_file_name,'GET')
        description =  kwargs.get("description")
        availability_zone = kwargs.get("volume_loc")
        params={
                'Action': 'ImportVolume',
                'AvailabilityZone':availability_zone,
                'Description':description,
                'Image.Format':'VMDK',
                'Image.Bytes':src_file_size,
                'Image.ImportManifestUrl':image_manifest_url,
                'Volume.Size':volume_size
                }
       
        response = self.connection.request(self.path, params=params).object
        elem = response.find(
            fixxpath(xpath='conversionTask', namespace=self.name_space))
        return self._to_import_volume_task_info(elem,manifest_file_name,src_loc,src_file,self)
        
    

    def create_export_volume_task(self, volume_id,instance_id, des_loc, des_filename, **kwargs):
        """
        export volume to des_location, which is a local directory or s3 directory
        :param volume_id: volume
        :param des_loc:
        :param des_filename:
        :param kwargs:
        :return: task object
        """
        pass
        


    def create_export_instance_task(self, instance_id, des_loc,disk_image_format='VMDK', target_environment='VMWare', **kwargs):
        """

        :param instance_id:
        :param des_loc:S3Bucket name
        :param disk_image_format 
        :type str
        :Valid Values: VMDK | RAW | VHD
        :param target_environment:
        :type str
        :Valid Values: citrix | vmware | microsoft
        :param kwargs:
        :return: task object
        """
        if not instance_id:
            return
        params={
                'Action': 'CreateInstanceExportTask',
                'InstanceId': instance_id,
                'ExportToS3.DiskImageFormat': disk_image_format,
                'ExportToS3.S3Bucket':des_loc,
                'TargetEnvironment':target_environment
                }
        response = self.connection.request(self.path, params=params).object
        elem = response.find(
            fixxpath(xpath='exportTask', namespace=self.name_space))
        return self._to_export_intances_task_info(elem,self)
        

    def get_task_info(self, task_obj, **kwargs):
        """

        :param task_obj:
        :param kwargs:
        :return: updated task object
        """
        if task_obj: 
            return task_obj.update_task_info()
        

    def cancel_task(self, task_obj, **kwargs):
        """

        :param task_obj:
        :param kwargs:
        :return:
        """
        if task_obj: 
            task_obj._cancel_task()
            

    
     
    def _create_str_to_sign(self,bucket_name,object_key,expires,http_method):
        
        """stringToSign = HTTP-VERB + "\n" +
            Content-MD5 + "\n" +
            Content-Type + "\n" +
            Expires + "\n" +
            CanonicalizedAmzHeaders +
            CanonicalizedResource;
        """
        http_verb = http_method
        content_md5=''
        content_type=''
        resource='/'+bucket_name+'/'+object_key
        buf = [http_verb]
        buf.append(content_md5)
        buf.append(content_type)
        string_to_sign = '\n'.join(buf)
        values_to_sign = []
        for value in [string_to_sign,expires,resource]:
            if value:
                values_to_sign.append(value)
        string_to_sign = '\n'.join(values_to_sign)
        return string_to_sign
    
    def _get_aws_auth_param(self,string_to_sign,secret_key):
        
        b64_hmac = base64.b64encode(
            hmac.new(b(secret_key), b(string_to_sign), digestmod=sha1).digest()
        )
        return b64_hmac.decode('utf-8')
    
    def _create_import_manifest_url(self,bucket_name,object_key,http_method):
        params={}
        expires = str(int(time.time()) + EXPIRATION_SECONDS)
        string_to_sign=self._create_str_to_sign(bucket_name,object_key,expires,http_method)
        params['Signature']=self._get_aws_auth_param(string_to_sign,self.secret)
        params['Expires']=expires
        params['AWSAccessKeyId']=self.key
        params_str =  urlencode(params, doseq=True)
        url='https://'+ bucket_name + '.s3.amazonaws.com/' + object_key + '?' + params_str
        return url
        
    def _create_manifest_url(self, src_loc, src_file, src_file_format,src_file_size,
                      volume_size, **kwargs):
        
        file_name=str(uuid.uuid4())+'manifest.xml'
        #file_name='D:\l2fb8e59-6727-4896-a67b-2aba0809d2e9manifest.xml'
        #file_tmp_dir='D:\l2fb8e59-6727-4896-a67b-2aba0809d2e9manifest.xml'
        current_path=os.path.dirname(__file__)
        file_tmp_dir="/tmp/" + file_name
        shutil.copyfile(current_path+'/templatemanifest.xml', file_tmp_dir) 
        try: 
            # change the xml
            tree = ET.parse(file_tmp_dir)
            
            elem_file_format= tree.xpath('file-format') 
            elem_file_format[0].text=src_file_format
            
            elem_size=tree.xpath('.//size') 
            elem_size[0].text=src_file_size
            
            elem_volume_size=tree.xpath('.//volume-size') 
            elem_volume_size[0].text=str(volume_size)
            
            
            self_destruct_url=self._create_import_manifest_url(src_loc,file_name,'DELETE')
            elem_destruct_url=tree.xpath('self-destruct-url')
            elem_destruct_url[0].text=self_destruct_url
            
            elem_key=tree.xpath('import/parts/part/key') 
            elem_key[0].text=src_file
            
            elem_byte_range=tree.xpath('import/parts/part/byte-range')
            elem_byte_range[0].set("end", src_file_size) 
            
            head_url=self._create_import_manifest_url(src_loc,src_file,'HEAD')
            elem_head_url=tree.xpath('import/parts/part/head-url')
            elem_head_url[0].text=head_url
            
            get_url=self._create_import_manifest_url(src_loc,src_file,'GET')
            elem_get_url=tree.xpath('import/parts/part/get-url')
            elem_get_url[0].text=get_url
            tree.write(file_tmp_dir) 
        except Exception:  
           
            return 
        #upload to s3
        container = Container(name=src_loc, extra={},driver=self)
        s3Driver=S3Adapter(self.key,self.secret,region=self.region,secure=False)
        s3_object=s3Driver.upload_object(file_path=file_tmp_dir, container=container,
                                            object_name=file_name,
                                            verify_hash=True) 
        os.remove(file_tmp_dir)
        return  s3_object.name    
    
    def _to_export_intances_task_info(self,element,driver):
        """
        Parse the XML element and return a export_task_info object.
        :rtype:     :class:`export_task_info`
        """
        export_task_id = findtext(element=element, xpath='exportTaskId',
                         namespace=self.name_space)
        description = findtext(element=element, xpath='description', namespace=self.name_space)
        
        state=findtext(element=element, xpath='state', namespace=self.name_space)
        status_message=findtext(element=element, xpath='statusMessage', namespace=self.name_space)
        instance_id= findtext(element=element, xpath='instanceExport/instanceId',
                         namespace=self.name_space)
        targetEnvironment= findtext(element=element, xpath='instanceExport/targetEnvironment',
                         namespace=self.name_space)
        
        export_to_s3_info=self._to_export_to_s3(element)

        return ExportInstanceTask(export_task_id,driver,state,status_message,description,None,None,instance_id,targetEnvironment,export_to_s3_info)
        
    
    def _to_export_to_s3(self,element):
        disk_image_format=findtext(element=element, xpath='exportToS3/diskImageFormat',
                         namespace=self.name_space)
        container_format=findtext(element=element, xpath='exportToS3/containerFormat',
                         namespace=self.name_space)
        s3_bucket=findtext(element=element, xpath='exportToS3/s3Bucket',
                         namespace=self.name_space)
        s3_key=findtext(element=element, xpath='exportToS3/s3Key',
                         namespace=self.name_space)
        return ExportToS3Info(disk_image_format,container_format,s3_bucket,s3_key)  
    
    def _to_import_volume_task_info(self,element,manifest_file_name,s3_bucket_name,src_file,driver):
        """
        Parse the XML element and return a conversion_task_info object.
        :rtype:     :class:`conversion_task_info`
        """
        conversion_task_id=findtext(element=element, xpath='conversionTaskId',
                         namespace=self.name_space)
        expiration_time=findtext(element=element, xpath='expirationTime',
                         namespace=self.name_space)
        state=findtext(element=element, xpath='state', namespace=self.name_space)
        status_message=findtext(element=element, xpath='statusMessage', namespace=self.name_space)
        description = findtext(element=element, xpath='description', namespace=self.name_space)
        
        bytes_converted=findtext(element=element, xpath='importVolume/bytesConverted',
                         namespace=self.name_space)
        availability_zone =findtext(element=element, xpath='importVolume/availabilityZone',
                         namespace=self.name_space)
        
        image_format=findtext(element=element, xpath='importVolume/image/format',
                         namespace=self.name_space)
        
        image_size=findtext(element=element, xpath='importVolume/image/size',
                         namespace=self.name_space)
        
        image_import_manifest_url=findtext(element=element, xpath='importVolume/image/importManifestUrl',
                         namespace=self.name_space)
        
        volume_size=findtext(element=element, xpath='importVolume/volume/size',
                         namespace=self.name_space)
        volume_id=findtext(element=element, xpath='importVolume/volume/id',
                         namespace=self.name_space)
  
        return ImportVolumeTask(conversion_task_id,driver,state,status_message,description,None,expiration_time,bytes_converted,
                                availability_zone,image_format,image_size,image_import_manifest_url,volume_size,
                                volume_id,manifest_file_name,s3_bucket_name,src_file)
        
    
    def _to_import_image_task_info(self,element,driver):
        import_task_id = findtext(element=element, xpath='importTaskId',
                               namespace=self.name_space)
        status= findtext(element=element, xpath='status',
                               namespace=self.name_space)
        description= findtext(element=element, xpath='description',
                               namespace=self.name_space)
        status_message= findtext(element=element, xpath='statusMessage',
                               namespace=self.name_space)
        image_id=findtext(element=element, xpath='imageId',
                               namespace=self.name_space)
        snapshot_detail_set= self._to_snapshot_details(element)
       
        return ImportImageTask(import_task_id,driver,status,status_message,description,None,None,image_id,snapshot_detail_set)
    
    def _to_snapshot_detail(self,element):
        snapshot_id = findtext(element=element, xpath='snapshotId',
                               namespace=self.name_space)
        disk_image_size = findtext(element=element, xpath='diskImageSize',
                               namespace=self.name_space)
        device_name=findtext(element=element, xpath='deviceName',
                               namespace=self.name_space)
        format=findtext(element=element, xpath='format',
                               namespace=self.name_space)
        s3_bucket=findtext(element=element, xpath='userBucket/s3Bucket',
                               namespace=self.name_space)
        s3_key=findtext(element=element, xpath='userBucket/s3Key',
                               namespace=self.name_space)
        user_bucket_details=UserBucketDetails(s3_bucket,s3_key)
        return SnapshotDetail(snapshot_id,disk_image_size,device_name,format,user_bucket_details)
    
    def _to_snapshot_details(self, response):
        return [self._to_snapshot_detail(el) for el in response.findall(
            fixxpath(xpath='snapshotDetailSet/item', namespace=self.name_space))
        ]
            
        
        
    
class S3Adapter(S3StorageDriver):   
    """
    s3Adapter
    """
    def __init__(self, key, secret=None, secure=True, host=None, port=None,
                 api_version=None, region=None, token=None,connectionCls=S3Connection, **kwargs):
        self.connectionCls,self.name,self.ex_location_name=self._get_driver_info(region)
        super(S3Adapter, self).__init__(key, secret=secret, secure=secure,
                                        host=host, port=port,
                                        api_version=api_version, region=region,
                                        token=token, **kwargs)
        
        
    def _get_driver_info(self,region):
        if region is not None:
            driver_info=DRIVER_INFO.get(region,None)
            if driver_info is not None:
                return driver_info.get('connectionCls',S3Connection),driver_info.get('name','Amazon S3 (standard)'),driver_info.get('ex_location_name','')
                
                
    
    def upload_object(self, file_path, container, object_name, extra=None,
                      verify_hash=True, ex_storage_class=None):
        import boto
        s3 = boto.connect_s3(self.key, self.secret)

        bucket_name = container.name
        bucket = s3.get_bucket(bucket_name)

        from boto.s3.key import Key
        k = Key(bucket)
        k.key = object_name
        k.set_contents_from_filename(file_path)

        return self.get_object(bucket_name,object_name)

    def upload_object_via_stream(self, iterator, container, object_name,
                                 extra=None, ex_storage_class=None):
        import boto
        s3 = boto.connect_s3(self.key, self.secret)

        bucket_name = container.name
        bucket = s3.get_bucket(bucket_name)

        from boto.s3.key import Key
        k = Key(bucket)
        k.key = object_name
        k.set_contents_from_file(iterator)

        return self.get_object(bucket_name,object_name)

    def download_object(self, obj, destination_path, overwrite_existing=False,
                    delete_on_failure=True):
        import boto
        from boto.s3.key import Key

        s3 = boto.connect_s3(self.key, self.secret)

        bucket_name = obj.container.name
        object_name = obj.name

        bucket = s3.get_bucket(bucket_name)
        k = Key(bucket)
        k.key = object_name
        k.get_contents_to_filename(destination_path)
        
        
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError)) 
    def get_object(self, container_name, object_name):
        return super(S3Adapter, self).get_object(container_name, object_name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError)) 
    def delete_object(self, obj):
        return super(S3Adapter, self).delete_object(obj)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError)) 
    def create_container(self, container_name):
        return super(S3Adapter, self).create_container(container_name)
    
    @RetryDecorator(max_retry_count= MAX_RETRY_COUNT,inc_sleep_time=5,max_sleep_time=60,
                        exceptions=(Exception,ssl.SSLError)) 
    def get_container(self, container_name):
        return super(S3Adapter,self).get_container(container_name)
    
    

        
class TASK_TYPE:
    IMPORT_IAMGE = 'import_image_task'
    IMPORT_VOLUME = 'import_volume_task'

    EXPORT_VOLUME = 'export_volume_task'
    EXPORT_INSTANCE = 'export_instance_task'

class TASK_STATE:
    ACTIVE = 'active'
    CANCELLING = 'cancelling'
    CANCELLED = 'cancelled'
    COMPLETED = 'completed'

class TaskBase:
    task_id = None
    provider_task_id = None
    description = ''
    # valid state: active | cancelling | cancelled | completed
    state = TASK_STATE.ACTIVE
    statusMessage = ''
    expiration_time = None
    # valid task type: TASK_TYPE
    task_type = None
    driver=None
    
    def __init__(self,task_id,driver,state,status_message=None,description=None,provider_task_id = None,expiration_time=None,task_type = None):
        self.task_id=task_id
        self.driver=driver
        self.state=state
        self.statusMessage=status_message
        self.description=description
        self.provider_task_id=provider_task_id
        self.expiration_time =expiration_time
        self.task_type = task_type

    def is_completed(self):
        return self.state == TASK_STATE.COMPLETED

    def is_cancelled(self):
        return self.state == TASK_STATE.CANCELLED

    def wait_for_completion(self):
        raise NotImplementedError

    def clean_up(self):
        raise NotImplementedError
    
class ImportImageTask(TaskBase):
    image_id=None
    s3_bucket=None
    snapshot_detail_set=None
    
    def __init__(self,task_id,driver,state,status_message=None,description=None,provider_task_id = None,expiration_time=None,
                image_id=None,snapshot_detail_set=None):
        self.task_id=task_id
        self.driver=driver
        self.state=state
        self.statusMessage=status_message
        self.description=description
        self.provider_task_id=provider_task_id
        self.image_id=image_id
        self.snapshot_detail_set=snapshot_detail_set
        self.name_space = 'http://ec2.amazonaws.com/doc/%s/' % (API_VERSION)
        
        
    def _cancel_task(self):
        params={
                'Action': 'CancelImportTask',
                'ImportTaskId':self.task_id
                }
        #TODO
        response = self.driver.connection.request(self.driver.path, params=params).object
        return self._get_boolean(response)
        
    
    def _get_boolean(self, element):
        tag = '{%s}%s' % (self.name_space, 'return')
        return element.findtext(tag) == 'true'
    
    def update_task_info(self):
        params = {'Action': 'DescribeImportImageTasks',
                  'ImportTaskId.1':self.task_id}
        response = self.driver.connection.request(self.driver.path, params=params).object
       
        task_infos = [self._to_import_image_task_info(el,self.driver) for el in response.findall(
                       fixxpath(xpath='importImageTaskSet/item', namespace=self.name_space))]
        if not task_infos:
            raise TaskNotFound
        if len(task_infos) > 1:
            raise MultiTaskConfusion
        return task_infos[0]
    
     
    def _to_import_image_task_info(self,element,driver):
        import_task_id = findtext(element=element, xpath='importTaskId',
                               namespace=self.name_space)
        status= findtext(element=element, xpath='status',
                               namespace=self.name_space)
        description= findtext(element=element, xpath='description',
                               namespace=self.name_space)
        status_message= findtext(element=element, xpath='statusMessage',
                               namespace=self.name_space)
        image_id=findtext(element=element, xpath='imageId',
                               namespace=self.name_space)
        snapshot_detail_set= self._to_snapshot_details(element)
       
        return ImportImageTask(import_task_id,driver,status,status_message,description,None,None,image_id,snapshot_detail_set)
    
    def _to_snapshot_detail(self,element):
        snapshot_id = findtext(element=element, xpath='snapshotId',
                               namespace=self.name_space)
        disk_image_size = findtext(element=element, xpath='diskImageSize',
                               namespace=self.name_space)
        device_name=findtext(element=element, xpath='deviceName',
                               namespace=self.name_space)
        format=findtext(element=element, xpath='format',
                               namespace=self.name_space)
        s3_bucket=findtext(element=element, xpath='userBucket/s3Bucket',
                               namespace=self.name_space)
        s3_key=findtext(element=element, xpath='userBucket/s3Key',
                               namespace=self.name_space)
        user_bucket_details=UserBucketDetails(s3_bucket,s3_key)
        return SnapshotDetail(snapshot_id,disk_image_size,device_name,format,user_bucket_details)
    
    def _to_snapshot_details(self, response):
        return [self._to_snapshot_detail(el) for el in response.findall(
            fixxpath(xpath='snapshotDetailSet/item', namespace=self.name_space))
        ]
        
        
class SnapshotDetail:
    snapshotId=''
    disk_image_size=''
    deviceName=''
    format=''
    user_bucket_details=None
    def __init__(self,snapshotId,disk_image_size,deviceName,format,user_bucket_details):
        self.snapshotId=snapshotId
        self.disk_image_size=disk_image_size
        self.deviceName=deviceName
        self.format=format
        self.user_bucket_details=user_bucket_details

class UserBucketDetails:
    s3_bucket=''
    s3_key =''
    def __init__(self,s3_bucket,s3_key):
        self.s3_bucket=s3_bucket
        self.s3_key =s3_key
        
class ImportVolumeTask(TaskBase):
        bytes_converted= None 
        availability_zone = None
        image_format=None
        image_size=None
        image_import_manifest_url=None
        volume_size=None
        volume_id=None
        manifest_file_name=None
        s3_bucket_name=None
        src_file=None
        
        def __init__(self,task_id,driver,state,status_message=None,description=None,provider_task_id=None,expiration_time=None,bytes_converted=None,
                    availability_zone=None,image_format=None,image_size=None, image_import_manifest_url=None, volume_size=None,
                    volume_id=None,manifest_file_name=None,s3_bucket_name=None,src_file=None):
            self.task_id=task_id
            self.driver=driver
            self.state=state
            self.statusMessage=status_message
            self.description=description
            self.provider_task_id=provider_task_id
            self.expiration_time=expiration_time
            self.bytes_converted=bytes_converted
            self.availability_zone=availability_zone
            self.image_format=image_format
            self.image_size=image_size
            self.image_import_manifest_url=image_import_manifest_url
            self.volume_size=volume_size
            self.volume_id=volume_id
            self.name_space = 'http://ec2.amazonaws.com/doc/%s/' % (API_VERSION)
            self.manifest_file_name =manifest_file_name
            self.s3_bucket_name =s3_bucket_name
            self.src_file=src_file
        
        def _cancel_task(self):
            params={
                    'Action': 'CancelConversionTask',
                    'ConversionTaskId':self.task_id
                    }
           
            response = self.driver.connection.request(self.driver.path, params=params).object 
            return self._get_boolean(response)  
        
        def _get_boolean(self, element):
            tag = '{%s}%s' % (self.name_space, 'return')
            return element.findtext(tag) == 'true' 
        
        def update_task_info(self):
            params = {'Action': 'DescribeConversionTasks',
                      'ConversionTaskId.1':self.task_id}
            response = self.driver.connection.request(self.driver.path, params=params).object
            task_infos = [self._to_import_volume_task_info(el,self.manifest_file_name,self.s3_bucket_name,self.src_file,self.driver) for el in response.findall(
                           fixxpath(xpath='conversionTasks/item', namespace=self.name_space))]
            if not task_infos:
                raise TaskNotFound
            if len(task_infos) > 1:
                raise MultiTaskConfusion
            return task_infos[0]
        
        def _clean_tmp_file(self):
            if self.manifest_file_name is not None:
                s3Driver=S3Adapter(self.driver.key,self.driver.secret,region=self.driver.region,secure=False)
                s3_manifest_file_name=s3Driver.get_object(container_name=self.s3_bucket_name,object_name=self.manifest_file_name)
                s3Driver.delete_object(s3_manifest_file_name)
                s3_src_file=s3Driver.get_object(container_name=self.s3_bucket_name,object_name=self.src_file)
                s3Driver.delete_object(s3_src_file)
                

        def clean_up(self):
            return self._clean_tmp_file()

        def wait_for_completion(self):

            while not self.is_completed():
                time.sleep(10)
                if self.is_cancelled():
                    # LOG.error('import volume fail!')
                    raise ErrorImportVolumeFailure

                # task = self.driver.get_task_info(task)

                self.state = self.update_task_info().state


        
        def _to_import_volume_task_info(self,element,manifest_file_name,s3_bucket_name,src_file,driver):
            """
            Parse the XML element and return a conversion_task_info object.
            :rtype:     :class:`conversion_task_info`
            """
            conversion_task_id=findtext(element=element, xpath='conversionTaskId',
                             namespace=self.name_space)
            expiration_time=findtext(element=element, xpath='expirationTime',
                             namespace=self.name_space)
            state=findtext(element=element, xpath='state', namespace=self.name_space)
            status_message=findtext(element=element, xpath='statusMessage', namespace=self.name_space)
            description = findtext(element=element, xpath='description', namespace=self.name_space)
            
            bytes_converted=findtext(element=element, xpath='importVolume/bytesConverted',
                             namespace=self.name_space)
            availability_zone =findtext(element=element, xpath='importVolume/availabilityZone',
                             namespace=self.name_space)
            
            image_format=findtext(element=element, xpath='importVolume/image/format',
                             namespace=self.name_space)
            
            image_size=findtext(element=element, xpath='importVolume/image/size',
                             namespace=self.name_space)
            
            image_import_manifest_url=findtext(element=element, xpath='importVolume/image/importManifestUrl',
                             namespace=self.name_space)
            
            volume_size=findtext(element=element, xpath='importVolume/volume/size',
                             namespace=self.name_space)
            volume_id=findtext(element=element, xpath='importVolume/volume/id',
                             namespace=self.name_space)
      
            return ImportVolumeTask(conversion_task_id,driver,state,status_message,description,None,expiration_time,bytes_converted,
                                    availability_zone,image_format,image_size,image_import_manifest_url,
                                    volume_size,volume_id,manifest_file_name,s3_bucket_name,src_file)
            
class ExportInstanceTask(TaskBase):
    instance_id=None
    target_environment=None
    export_to_s3_info =None
    def __init__(self,task_id,driver,state,status_message=None,description=None,provider_task_id=None,
                expiration_time=None,instance_id=None,target_environment=None,export_to_s3_info=None):
        self.task_id=task_id
        self.driver=driver
        self.state=state
        self.statusMessage=status_message
        self.description=description
        self.provider_task_id=provider_task_id
        self.expiration_time=expiration_time
        self.instance_id=instance_id
        self.target_environment=target_environment
        self.export_to_s3_info=export_to_s3_info
        self.name_space = 'http://ec2.amazonaws.com/doc/%s/' % (API_VERSION)
        
    
    def _cancel_task(self,export_task_id):
        params={
                'Action': 'CancelExportTask',
                'ExportTaskId':export_task_id
                }
         
        response = self.driver.connection.request(self.driver.path, params=params).object
        return self._get_boolean(response)
    
    def _get_boolean(self, element):
            tag = '{%s}%s' % (self.name_space, 'return')
            return element.findtext(tag) == 'true' 
    
    def update_task_info(self):
        params = {'Action': 'DescribeExportTasks',
                  'ExportTaskId.1':self.task_id}
        
        response = self.driver.connection.request(self.driver.path, params=params).object
        task_infos = [self._to_export_intances_task_info(el,self.driver) for el in response.findall(
                       fixxpath(xpath='exportTaskSet/item', namespace=self.name_space))]
        if not task_infos:
            raise TaskNotFound
        if len(task_infos) > 1:
            raise MultiTaskConfusion
        return task_infos[0]
    
    def _to_export_intances_task_info(self,element,driver):
        """
        Parse the XML element and return a export_task_info object.
        :rtype:     :class:`export_task_info`
        """
        export_task_id = findtext(element=element, xpath='exportTaskId',
                         namespace=self.name_space)
        description = findtext(element=element, xpath='description', namespace=self.name_space)
        
        state=findtext(element=element, xpath='state', namespace=self.name_space)
        status_message=findtext(element=element, xpath='statusMessage', namespace=self.name_space)
        instance_id= findtext(element=element, xpath='instanceExport/instanceId',
                         namespace=self.name_space)
        targetEnvironment= findtext(element=element, xpath='instanceExport/targetEnvironment',
                         namespace=self.name_space)
        
        export_to_s3_info=self._to_export_to_s3(element)

        return ExportInstanceTask(export_task_id,driver,state,status_message,description,None,None,instance_id,targetEnvironment,export_to_s3_info)
     
    def _to_export_to_s3(self,element):
        disk_image_format=findtext(element=element, xpath='exportToS3/diskImageFormat',
                         namespace=self.name_space)
        container_format=findtext(element=element, xpath='exportToS3/containerFormat',
                         namespace=self.name_space)
        s3_bucket=findtext(element=element, xpath='exportToS3/s3Bucket',
                         namespace=self.name_space)
        s3_key=findtext(element=element, xpath='exportToS3/s3Key',
                         namespace=self.name_space)
        return ExportToS3Info(disk_image_format,container_format,s3_bucket,s3_key)  
 
        
class ExportToS3Info:
    def __init__(self,disk_image_format,container_format,s3_bucket,s3_key):
        self.disk_image_format=disk_image_format
        self.container_format=container_format
        self.s3_bucket=s3_bucket
        self.s3_key=s3_key
    


class ImageFormatNotValid(Exception):
    msg_fmt = "Image format not valid"
    
class  MultiTaskConfusion(Exception):
    msg_fmt = "More than one task are found"
    
class TaskNotFound(Exception):
    msg_fmt = "Task not found"

class ErrorImportVolumeFailure(Exception):
    msg_fmt = 'Upload Volume Failure'
    

class NetworkInterface(EC2NetworkInterface):
    """
       the class of NetworkInterface
    """
    delete_on_termination = True
    description = None
    device_index = None
    security_groups = None    
    private_ip_address = None
    subnet_id = None
    
    def __init__(self,id=None,name=None,state=None,delete_on_termination=True,description=None,device_index=None,security_groups=None,
                  private_ip_address=None,subnet_id=None,extra=None): 
        """
        NetworkInterface constructor.

        :param      id: networkInterface.id
        :type       id: ``str``

        :param      name: networkInterface.name
        :type       name: `str`

        :param      state: networkInterface state
        :type       size: ``str``

        :param      delete_on_termination :If set to true, the interface is deleted when the instance is terminated. 
                        You can specify true only if creating a new network interface when launching an instance.
        :type       delete_on_termination: ``boolean``

        :param      description: description for NetworkInterface
        :type       name: ``str``
        
        :param      device_index The index of the device on the instance for the network interface attachment.
                       If you are specifying a network interface in a RunInstances request, you must provide the device index.
        :type       device_index ``Integer``
        
        :param      security_groups The IDs of the security groups for the network interface
        :type       security_groups ``list str``
        
        :param      private_ip_address The private IP address of the network interface
        :type       private_ip_address ``str``
        
        :param      subnet_id The ID of the subnet associated with the network string
        :type       subnet_id ``str``
        
        :param      extra: Optional provided specific attributes associated with
                       this networkInterface.
        :type       extra: ``dict``
        
        
        """
        super(NetworkInterface, self).__init__(id=id, name=name, state=state, extra=extra)
        
        self.delete_on_termination = delete_on_termination
        self.description = description
        self.device_index = device_index
        self.security_groups = security_groups
        self.private_ip_address = private_ip_address
        self.subnet_id = subnet_id
        
        
class Image(NodeImage):
    def __init__(self, id, name, driver, extra=None):
        super(Image,self).__init__(id, name, driver, extra=extra)
        
    def set_volume_delete(self,delete_on_termination):
        if self.extra is not None:
            block_device_mappings =  self.extra.get('block_device_mapping')
            if block_device_mappings is not None:
                for bdm in block_device_mappings:
                    bdm.get('ebs')['delete']=delete_on_termination
            
    

    
 
