How to Deploy AWS Driver
==============================


Step 1: Prepare An AWS Accout
---

1. Register a AWS Account `leo.demo`
2. Add a IAM User <a name="iam-user">`userdemo`</a>, download secret key id `xxxxid` and secret key `yyyyyy`
3. Create a S3 bucket `hybridbucket`. 
	> ***NOTE: The bucket must located in the region in which you want to import volumes***
4. Create VM Import Role. 
	> VM Import uses a role in your AWS account to perform certain operations (e.g: downloading disk images from an Amazon S3 bucket).You must create a role with the name `vmimport` with the following policy and trusted entities. 

    1. Create a file named trust-policy.json with the following policy


        ```json
        {
          	"Version":"2012-10-17",
          	"Statement":[
            {
              "Sid":"",
              "Effect":"Allow",
              "Principal":{
                "Service":"vmie.amazonaws.com"
              },
              "Action":"sts:AssumeRole",
              "Condition":{
                "StringEquals":{
                  "sts:ExternalId":"vmimport"
                }
              }
            }
          ]
        }
        ```
	1. Use the aws iam create-role command to create a role named `vmimport` and give VM Import/Export access to it.
		> ***NOTE: The role name `vmimport` is unchangable!***
	
        ```shell
        aws iam create-role --role-name vmimport --assume-role-policy-document file://trust-policy.json
        ```


	
	1. Create a file named role-policy.json with the following policy. 
		> ***NOTE: Replace `hybridbucket` with the appropriate Amazon S3 bucket where the disk files are stored.*** 

        ```json
		{
		  "Version":"2012-10-17",
		  "Statement":[
		    {
		      "Effect":"Allow",
		      "Action":[
		        "s3:ListBucket",
		        "s3:GetBucketLocation"
		      ],
		      "Resource":[
		        "arn:aws:s3:::hybridbucket"
		      ]
		    },
		    {
		      "Effect":"Allow",
		      "Action":[
		        "s3:GetObject"
		      ],
		      "Resource":[
		        "arn:aws:s3:::hybridbucket/*"
		      ]
		    },
		    {
		      "Effect":"Allow",
		      "Action":[
		        "ec2:ModifySnapshotAttribute",
		        "ec2:CopySnapshot",
		        "ec2:RegisterImage",
		        "ec2:Describe*"
		      ],
		      "Resource":"*"
		    }
		  ]
		}	
        ```
            
	1. Run the following command to attach the policy to the role created above:
		
        ```shell
        aws iam put-role-policy --role-name vmimport --policy-name vmimport --policydocument file://role-policy.json 
        ```
			
5. Add IAM Permissions to user [`userdemo`](#iam-user) via aws web console. You should create following IAM policy, then attach it to `userdemo`.
	> ***NOTE: Replace `hybridbucket` with the appropriate Amazon S3 bucket where the disk files are stored.*** 

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListAllMyBuckets"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:CreateBucket",
                    "s3:DeleteBucket",
                    "s3:DeleteObject",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:PutObject"
                ],
                "Resource": [
                    "arn:aws:s3:::hybridbucket",
                    "arn:aws:s3:::hybridbucket/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:ImportInstance",
                    "ec2:ImportVolume",
                    "ec2:ImportImage",
                    "ec2:ImportSnapshot",               
                    "ec2:CancelConversionTask",                
                    "ec2:CancelImportTask",
                    "ec2:DescribeImportImageTasks",
                    "ec2:DescribeImportSnapshotTasks",
                    "ec2:DescribeConversionTasks",
                    "ec2:CreateInstanceExportTask",
                    "ec2:CancelExportTask",
                    "ec2:DescribeExportTasks",                                
                    "ec2:CreateTags",
                    "ec2:DeleteTags",
                    "ec2:DescribeTags",
                    "ec2:RunInstances",
                    "ec2:StartInstances",
                    "ec2:StopInstances",
                    "ec2:TerminateInstances",
                    "ec2:DescribeInstanceAttribute",
                    "ec2:DescribeInstanceStatus",
                    "ec2:DescribeInstances",
                    "ec2:CreateVolume",
                    "ec2:DeleteVolume",
                    "ec2:AttachVolume",
                    "ec2:DetachVolume", 
                    "ec2:DescribeVolumes",
                    "ec2:DescribeVolumeStatus",
                    "ec2:DescribeVolumeAttribute",
                    "ec2:CreateSnapshot",
                    "ec2:DeleteSnapshot",
                    "ec2:DescribeSnapshotAttribute",
                    "ec2:DescribeSnapshots",
                    "ec2:CopySnapshot",
                    "ec2:CreateImage",                  
                    "ec2:RegisterImage",
                    "ec2:DeregisterImage",
                    "ec2:DescribeImages",                
                    "ec2:DescribeImageAttribute",
                    "ec2:AssociateAddress",
                    "ec2:DisassociateAddress",
                    "ec2:DescribeAddresses",              
                    "ec2:CreateNetworkInterface",
                    "ec2:DeleteNetworkInterface",
                    "ec2:AttachNetworkInterface", 
                    "ec2:DetachNetworkInterface",
                    "ec2:DescribeNetworkInterfaceAttribute",
                    "ec2:DescribeNetworkInterfaces",
                    "ec2:DescribeRegions",
                    "ec2:DescribeAvailabilityZones"
                ],
                "Resource": "*"
            }
        ]
    }
    ```

Step 2: Install drivers at Cascaded Openstack Node(AZ31) (todo: wangjun, vtep driver) 
---


1. Install Huawei FusionSphere
2. Install hybrid cloud patch
2. Download aws nova driver folder `nova/virt/aws` from github repository, and copy it into directory `/usr/lib64/python2.6/site-packages/nova/virt` on node AZ31 
3. Download cinder driver folder `cinder/volume/drivers/ec2` from github repository, and copy it into directory  `/usr/lib64/python2.6/site-packages/cinder/volume/drivers` on node AZ31 
4. Install python dependecies:
    1). Download Dependecies from [github repository](https://github.com/Hybrid-Cloud/badam/tree/master/hybrid_cloud_deps/aws)
    2). Unzip `python-deps.zip` to `directory /usr/lib64/python2.6/site-packages/` on AZ31
5. Install ovf tools
    > ***NOTE: Because of qume-img's bug,  we use ovf tool to make ovf and stremoptimized-vmdk.***   

    1) Download `VMware-ovftool-3.5.2-1880279-lin.x86_64.bundle` from [github repository](https://github.com/Hybrid-Cloud/badam/tree/master/hybrid_cloud_deps/vcloud/1_package), 
    2) install `VMware-ovftool-3.5.2-1880279-lin.x86_64.bundle` on AZ31
    3) Download `vmx.zip` from [github repository](https://github.com/Hybrid-Cloud/badam/tree/master/hybrid_cloud_deps/aws).
    4) Unzip `vmx.zip` to directory `/tmp` on AZ31. 
    > NOTE: The directory to unzip is depending on nova driver's configuration `conversion_dir`

    

Step 3: (Optional) Deploy Compute Gateway On AWS
------------------------------------------------

> ***NOTE: This step is needed only if cascaed node AZ31 is NOT on AWS***

1. Create compute gateway instance `i-abcdef` from AMI `todo` on aws availability zone `ap-southeast-1a`, which in the some region as s3 bucket `hybridbucket`
2. Download the public key of ec2 vm `i-abcdef`, rename it as `cgw.pem`
3. Copy `cgw.pem` to directory `\home` (or somewhere non-root user can read)
4. 



Step 4: Configure Drivers on Cascading Node AZ31 *(todo: wangliuan, cinder configuration)*
------------------------------------------------

1. Configure nova driver `\etc\nova\nova-compute.conf`
> NOTE: In FusionSphere, you have to modify `\etc\nova\nova.json` and `\etc\nova\nova.conf.sample` to change configuration
    
    1) Change option `compute_driver` to `nova.virt.vtep.aws_driver.VtepAWSDriver`
    ```config 
    compute_driver = nova.virt.vtep.aws_driver.VtepAWSDriver
    ```
    2) Add option `provide_cloud_type` and assign to `aws`
    ```config 
    provide_cloud_type = aws
    ```
    3) Add section `[provider_opts]` as follow:

    ```config
    [provider_opts]
    conversion_dir = /tmp
    storage_tmp_dir = hybridbucket
    region = ap-southeast-1
    availability_zone = ap-southeast-1a
    access_key_id = ??????????
    secret_key = ************
    flavor_map = m1.tiny:t2.micro, m1.small:t2.micro, m1.medium:t2.micro3, m1.large:t2.micro, m1.xlarge:t2.micro
    cgw_host_ip = aa.bb.cc.dd
    cgw_host_id = i-xxxxxx
    cgw_user_name = ec2-user
    cgw_certificate = /home/cgw.pem
    subnet_api = subnet-11111111
    subnet_data = subnet-22222222
    vpn_route_gateway = 162.3.0.0/16:172.30.32.1,172.28.48.0/20:172.30.48.1
    rabbit_host_ip_public = 162.3.113.42
    rabbit_password_public = Fusion********
    cascaded_node_id = i-test
    base_linux_image = ami-68d8e93a
    ```
    
    4) Add section `[vtepdriver]` as follow:
    
    ```config
    [provider_opts]
    provider_api_network_id = f0278e5d-1940-459e-8a71-c0beb94594fc
    provider_api_network_name = subnet-11111111
    provider_tunnel_network_id = f0278e5d-1940-459e-8a71-c0beb94594fc
    provider_tunnel_network_name = subnet-11111111
    use_for_dr = False
    ```
    The provider_api_network_id and provider_tunnel_network_id is two prepared cascaded network id, provider_api_network_name and provider_tunnel_network_name is two prepared aws subnet id, and if your driver is used for disaster recovery or not.
    
2. Configre cinder driver 

Step 5: Some optimizing configration
------------------------------------


 - Mapping glance image `aaa-bbb-ccc-ddd` to AWS AMI `ami-eeeee`: 
 Add a tag, of which key is `hyrid_cloud_image_id` and value is `aaa-bbb-ccc-ddd`, to AWS AMI `ami-eeeee`

