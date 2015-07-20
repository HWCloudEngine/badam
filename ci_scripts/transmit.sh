#!/bin/bash
HOST_CASCADING=162.3.120.50
FILE_COPY_USER=fsp
RUN_USER=root
DES_DIR="/home/"${FILE_COPY_USER}"/"

echo "copy patches_tool to HOST_CASCADING(${HOST_CASCADING}) ..."
ssh ${FILE_COPY_USER}@${HOST_CASCADING} rm ${DES_DIR}/patches_tool.tar
ssh ${FILE_COPY_USER}@${HOST_CASCADING} rm -rf ${DES_DIR}/patches_tool

scp ./patches_tool.tar ${FILE_COPY_USER}@${HOST_CASCADING}:${DES_DIR}
ssh ${FILE_COPY_USER}@${HOST_CASCADING} tar -xf ${DES_DIR}/patches_tool.tar -C ${DES_DIR}/

