#!/bin/bash

ip route del 172.29.0.0/24
ip route add 172.29.0.0/24 via 162.3.125.247
ip route add 172.29.1.0/24 via 172.28.48.1

ip route del table external_api 172.29.0.0/24
ip route add table external_api 172.29.0.0/24 via 162.3.125.247
