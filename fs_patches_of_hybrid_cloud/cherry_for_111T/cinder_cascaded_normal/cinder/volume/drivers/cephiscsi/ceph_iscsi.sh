#!/bin/bash
action=$1
rbdpool=$2
rbdimage=$3
file=/etc/tgt/conf.d/ceph.conf
if [ ! -f $file ]
then
touch "$file"
fi
if [ ! -s $file ]
then
echo "# iscsi target" > $file
fi

if [ $action = "create" ]
then
sed -i '$a <target\ iqn.2015-08.rbdstore.'${rbdimage}'.com:iscsi>' $file
sed -i '$a \    driver\ iscsi' $file
sed -i '$a \    bs-type\ rbd' $file
sed -i '$a \    backing-store\ '${rbdpool}/${rbdimage} $file
sed -i '$a \    initiator-address\ ALL' $file
sed -i '$a </target>' $file
elif [ $action = "delete" ] 
then 
sed -i '/'$rbdimage'/,+5d' $file
else
echo "unsupported action"
fi
service tgt reload
