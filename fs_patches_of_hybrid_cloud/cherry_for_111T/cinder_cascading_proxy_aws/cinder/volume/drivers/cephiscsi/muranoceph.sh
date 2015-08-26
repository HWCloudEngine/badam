#!/bin/bash

action=$1
target_portal=$2
target_iqn=$3
target_lun=$4
if [ $action = "attach" ]
then
    record=`iscsiadm -m node -T $target_iqn -p $target_portal`
    if [ -z $record ]
    then
        echo "New iSCSI node"
        iscsiadm -m node -T $target_iqn -p $target_portal --op new
    fi
    session=`iscsiadm -m session`
    contain=$(echo $session | grep "$target_iqn")
    if [ -z $contain]
    then
        echo "Login iSCSI node"
        iscsiadm -m node -T $target_iqn -p $target_portal --login
        echo "Update node automatic"
        iscsiadm -m node -T $target_iqn -p $target_portal --op update -n node.startup  -v automatic
    fi
elif [ $action = "detach" ]
then
   device_name=$(ls -l /dev/disk/by-path/ | grep "$target_iqn" | awk -F '/' '{print $NF}')
   device="/dev/""$device_name"
   path="/sys/block/""$device_name""/device/delete"
   blockdev --flushbufs $device
   echo "1" | tee -a $path
   iscsiadm -m node -T $target_iqn -p $target_portal --op update -n node.startup  -v manual
   iscsiadm -m node -T $target_iqn -p $target_portal --logout
   iscsiadm -m node -T $target_iqn -p $target_portal --op delete
else
   echo "unsupport action"
fi
