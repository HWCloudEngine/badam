#!/bin/bash
try_times=3
usage() {
    cat <<EOF
    $0 volume-id dst-instance-id des_loc des_filename s3_bucket
EOF
exit 1
}


detach_vol() {

    local vol=$1
    local good=""
    for((i=0;i<try_times;i++)) ; do aws ec2 detach-volume --volume-id $vol >/dev/null && {  good=1; break ; } ; sleep 2 ; done

    [ -z $good ] && { echo detach volume $vol from $2 failed ; return 1 ; }
    return 0

}


[ $# -lt 5 ] && usage

vol=${1}
dst_instance_id=${2}
des_loc=${3} 
des_filename=${4}
s3_bucket=${5}
echo vol is $vol
src_instance_id=$(aws ec2 describe-volumes --volume-ids  $vol | awk -v vol=$vol '{gsub("[\",]",e)} /nstance[Ii]d/{print$2;exit}')

#[ -z $src_instance_id ] && { echo can\'t find volumes $vol ; exit 1; }
if [ $src_instance_id ];then
src_device=$(aws ec2 describe-volumes --volume-ids $vol | awk -v vol=$vol '{gsub("[\",]",e)} /Device/{print$2;exit}')
src_device=${src_device:-/dev/sdp}
echo $src_device
detach_vol $vol src || exit 1
vol_status=$(aws ec2 describe-volumes  --volume-ids $vol | awk -v vol=$vol '{gsub("[\",]",e)} /State/{print$2;exit}')
while [ $vol_status != "available" ]
do
sleep 1
vol_status=$(aws ec2 describe-volumes  --volume-ids $vol | awk -v vol=$vol '{gsub("[\",]",e)} /State/{print$2;exit}')
done
fi
mount_device=$(sudo fdisk -l| awk  'sub(".*/dev/xvd", e){dev=substr($0,1,1)dev}END{$0="abcdefghijklmnopqrst";gsub("["dev"]",FS=e);print "/dev/xvd"$1}')
echo mount_device  is  $mount_device
aws ec2 attach-volume --volume-id $vol --instance-id ${dst_instance_id} --device $mount_device  >/dev/null || {

    echo can\' attach volume to dst instance-id ${dst_instance_id}
    echo try to rollback -- attach volume to src instance-id ${src_instance_id} 
    aws ec2 attach-volume --volume-id $vol --instance-id ${src_instance_id} --device ${src_device} >/dev/null || { echo attach to src $src_instance_id failed;  }
    exit 1
}

ret=0

# $vol: volume-id
# $src_instance_id: A instance id
# $dst_instance_id: B instance id
vol_status=$(aws ec2 describe-volumes  --volume-ids $vol | awk -v vol=$vol '{gsub("[\",]",e)} /State/{print$2;exit}')
while [ $vol_status != "attached" ]
do
sleep 1
vol_status=$(aws ec2 describe-volumes  --volume-ids $vol | awk -v vol=$vol '{gsub("[\",]",e)} /State/{print$2;exit}')
done

sudo qemu-img convert -c -O qcow2 $mount_device /home/$des_filename && {
# sleep 3;
true
} || { ret=1; echo "qemu-img" failed ; }

aws s3 cp /home/$des_filename s3://$s3_bucket || { ret=1;echo "upload to s3" failed ; }
sudo rm  /home/$des_filename
detach_vol $vol dst || exit 1
if [ $src_instance_id ];then
vol_status=$(aws ec2 describe-volumes  --volume-ids $vol | awk -v vol=$vol '{gsub("[\",]",e)} /State/{print$2;exit}')
while [ $vol_status != "available" ]
do
sleep 1
vol_status=$(aws ec2 describe-volumes  --volume-ids $vol | awk -v vol=$vol '{gsub("[\",]",e)} /State/{print$2;exit}')
done

aws ec2 attach-volume --volume-id $vol --instance-id ${src_instance_id} --device ${src_device} >/dev/null || { echo attach to src $src_instance_id failed; ret=1 ; }
fi
exit $ret


