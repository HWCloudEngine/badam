#!/bin/bash

src_base_path=$(cd `dirname $0`; pwd)/code
dest_base_path="/usr/lib64/python2.6/site-packages"

sed -i "/\"compute_driver\": \"nova.huawei.virt.libvirt.LibvirtDriver\"/s//\"compute_driver\": \"nova.virt.vcloudapi.VMwareVcloudDriver\"/g" /etc/nova/nova.json

cp -r $src_base_path/nova/virt/ $dest_base_path/nova/
cp -r $src_base_path/cinder/volume/drivers/ $dest_base_path/cinder/volume/

cp /etc/cinder/others/cfg_template/cinder-volume.json /etc/cinder/others/cfg_template/cinder-volume.json.bak
cp $src_base_path/etc/cinder/others/cfg_template/cinder-volume.json /etc/cinder/others/cfg_template/cinder-volume.json

cp /etc/nova/others/cfg_template/nova-compute.json /etc/nova/others/cfg_template/nova-compute.json.bak
cp $src_base_path/etc/nova/others/cfg_template/nova-compute.json /etc/nova/others/cfg_template/nova-compute.json

cp /etc/nova/nova.conf.sample /etc/nova/nova.conf.sample.bak
cp $src_base_path/etc/nova/nova.conf.sample /etc/nova/nova.conf.sample

cp $src_base_path/etc/nova/rootwrap.d/vmwareapi.filters /etc/nova/rootwrap.d/vmwareapi.filters
chown openstack:openstack /etc/nova/rootwrap.d/vmwareapi.filters

mkdir -p /opt/HUAWEI/image/vmx/
cp $src_base_path/../vcloud_deps/vmx/* /opt/HUAWEI/image/vmx/

cd $src_base_path/../vcloud_deps/vcloud/1_package
tar xvf vmware-ovftool.tar.gz -C /usr/lib/
chmod +x /usr/lib/vmware-ovftool/ovftool.bin /usr/lib/vmware-ovftool/ovftool
ln -s /usr/lib/vmware-ovftool/ovftool /usr/bin/ovftool

cd $src_base_path/../vcloud_deps/vcloud/2_package
rpm -ivh *

cd $src_base_path/../vcloud_deps/vcloud/3_package
easy_install pip-1.3.1.tar.gz

cd $src_base_path/../vcloud_deps/vcloud/4_package
pip install -r requirements.txt

cd $src_base_path/../vcloud_deps/vcloud/5_package
rpm2cpio glibc-locale-2.11.3-17.54.1.x86_64.rpm | cpio -di
cd usr/lib64/gconv/
cp ./* /usr/lib64/gconv/
iconvconfig

