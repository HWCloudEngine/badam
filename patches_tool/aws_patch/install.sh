#!/bin/bash

src_base_path=$(cd `dirname $0`; pwd)/code
dest_base_path="/usr/lib64/python2.6/site-packages"

g_dns_server_ip=''

get_dns_server_ip()
{
    g_dns_server_ip=`cat $src_base_path/../aws_config.ini | grep dns_server_ip | awk -F '=' '{print $2}'`
}

get_dns_server_ip

cp -r $src_base_path/nova/ $dest_base_path
cp -r $src_base_path/cinder/ $dest_base_path
cp -r $src_base_path/neutron/ $dest_base_path

cp -r $src_base_path/../aws_deps/backports $dest_base_path
cp -r $src_base_path/../aws_deps/libcloud $dest_base_path

mkdir -p /opt/HUAWEI/image/vmx/
cp $src_base_path/../aws_deps/vmx/* /opt/HUAWEI/image/vmx/

cd $src_base_path/../../vcloud_patch/vcloud_deps/vcloud/1_package
tar xvf vmware-ovftool.tar.gz -C /usr/lib/
chmod +x /usr/lib/vmware-ovftool/ovftool.bin /usr/lib/vmware-ovftool/ovftool
ln -f -s /usr/lib/vmware-ovftool/ovftool /usr/bin/ovftool

reconf=`cat /etc/resolv.conf | grep $g_dns_server_ip`
if [ "x${reconf}" = "x" ];then
  echo "nameserver $g_dns_server_ip">>/etc/resolv.conf
fi

cp /etc/cinder/others/cfg_template/cinder-volume.json /etc/cinder/others/cfg_template/cinder-volume.json.bak
cp $src_base_path/etc/cinder/others/cfg_template/cinder-volume.json /etc/cinder/others/cfg_template/cinder-volume.json

cp /etc/nova/others/cfg_template/nova-compute.json /etc/nova/others/cfg_template/nova-compute.json.bak
cp $src_base_path/etc/nova/others/cfg_template/nova-compute.json /etc/nova/others/cfg_template/nova-compute.json

cp /etc/nova/nova.conf.sample /etc/nova/nova.conf.sample.bak
cp $src_base_path/etc/nova/nova.conf.sample /etc/nova/nova.conf.sample

sed -i "/\"compute_driver\"/c\"compute_driver\": \"nova.virt.vtep.aws_driver.VtepAWSDriver\"," /etc/nova/nova.json
#sed -i "/\"compute_driver\": \"nova.huawei.virt.libvirt.LibvirtDriver\"/s//\"compute_driver\": \"nova.virt.vtep.aws_driver.VtepAWSDriver\"/g" /etc/nova/nova.json

dos2unix $src_base_path/../aws_config.ini
cgw_certificate_path=`cat $src_base_path/../aws_config.ini | grep cgw_certificate | awk  -F '=' '{print $2}'`
cp $src_base_path/../cgw.pem $cgw_certificate_path

dos2unix $src_base_path/../add_router.sh
sh $src_base_path/../add_router.sh
exit 0