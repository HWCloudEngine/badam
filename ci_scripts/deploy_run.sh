#!/bin/bash
HOST_CASCADING=162.3.120.50
FILE_COPY_USER=fsp
RUN_USER=root
DES_DIR="/home/"${FILE_COPY_USER}"/"

echo "run patches_tool on HOST_CASCADING(${HOST_CASCADING}) ..."

ssh ${RUN_USER}@${HOST_CASCADING} sh ${DES_DIR}patches_tool/run.sh
