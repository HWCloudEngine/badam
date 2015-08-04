#!/bin/bash

let i=0
ip addr show external_api | grep secondary
result=$?
until ((result==0))
do
    sleep 1s
    let i=i+1
    if((i==600))
    then
       exit
    fi
    ip addr show external_api | grep secondary
    result=$?
done

ip route del 172.29.2.0/24
ip route del 172.29.3.0/24

ip route del 172.31.100.0/24
ip route del 172.31.101.0/24

ip route add 172.31.100.0/24 via 162.3.130.247
ip route add 172.31.101.0/24 via 172.28.48.1

ip route del table external_api 172.29.3.0/24

ip route del table external_api 172.31.100.0/24
ip route add table external_api 172.31.100.0/24 via 162.3.130.247
