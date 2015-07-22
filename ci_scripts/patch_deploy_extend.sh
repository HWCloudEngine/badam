#!/bin/bash
PATCH_NAME="cherry_for_B038";
PATCH_VERSION=v0.1;
PATCH_DIR=${PATCH_NAME}"_"${PATCH_VERSION}"/";

LOCAL_DIR=$(cd "$(dirname "$0")"; pwd)"/";
LOCAL_PATCH_DIR=${LOCAL_DIR}${PATCH_DIR};

GIT_ROOT_DIR="/var/lib/jenkins/jobs/badam/workspace/";
GIT_CODE_DIR=${GIT_ROOT_DIR}"fs_patches_of_hybrid_cloud/"${PATCH_NAME}"/";
GIT_PATCH_DIR=${GIT_ROOT_DIR}"patches_tool/";

CASCADING_HOST=162.3.120.50;
FILE_COPY_USER=fsp;
RUN_USER=root;
REMOTE_DIR="/home/"${FILE_COPY_USER}"/"${PATCH_DIR};

prepare() {
    if [ -d ${LOCAL_PATCH_DIR} ]; then
	    echo "delete old patch, file_dir=${LOCAL_PATCH_DIR}"
	    rm -rf ${LOCAL_PATCH_DIR}
    fi

    mkdir ${LOCAL_PATCH_DIR}
    cd ${LOCAL_PATCH_DIR}
	
    cp -rf ${GIT_PATCH_DIR} ./
    echo "clean patch tool ..."
    rm -rf ./patches_tool/aws_patch/code/cinder/*
    rm -rf ./patches_tool/aws_patch/code/neutron/*
    rm -rf ./patches_tool/aws_patch/code/nova/virt/aws/*
    rm -rf ./patches_tool/aws_patch/code/nova/virt/vtep/*


    rm -rf ./patches_tool/vcloud_patch/code/cinder/*
    rm -rf ./patches_tool/vcloud_patch/code/nova/virt/vcloudapi/*
    rm -rf ./patches_tool/vcloud_patch/code/nova/virt/vmwareapi/*
    rm -rf ./patches_tool/vcloud_patch/code/nova/virt/vtep/*


    rm -rf ./patches_tool/hybrid_cloud_patches/aws_proxy/cinder/*
    rm -rf ./patches_tool/hybrid_cloud_patches/cascading/cinder/*
    rm -rf ./patches_tool/hybrid_cloud_patches/cascading/cinder/volume/*
    rm -rf ./patches_tool/hybrid_cloud_patches/cascading/nova/api/*
    rm -rf ./patches_tool/hybrid_cloud_patches/vcloud_proxy/cinder/*


    echo "copy file ..."
    cp -rf ${GIT_CODE_DIR}"cinder_cascaded_aws/cinder"  ./patches_tool/aws_patch/code/
    cp -rf ${GIT_CODE_DIR}"neutron_cascaded_aws/neutron"  ./patches_tool/aws_patch/code/
    cp -rf ${GIT_CODE_DIR}"nova_cascaded/nova/virt/aws"  ./patches_tool/aws_patch/code/nova/virt/
    cp -rf ${GIT_CODE_DIR}"nova_cascaded/nova/virt/vtep"  ./patches_tool/aws_patch/code/nova/virt/


    cp -rf ${GIT_CODE_DIR}"cinder_cascaded_normal/cinder"  ./patches_tool/vcloud_patch/code/
    cp -rf ${GIT_CODE_DIR}"nova_cascaded/nova/virt/vcloudapi"  ./patches_tool/vcloud_patch/code/nova/virt/
    cp -rf ${GIT_CODE_DIR}"nova_cascaded/nova/virt/vmwareapi"  ./patches_tool/vcloud_patch/code/nova/virt/
    cp -rf ${GIT_CODE_DIR}"nova_cascaded/nova/virt/vtep"  ./patches_tool/vcloud_patch/code/nova/virt/


    cp -rf ${GIT_CODE_DIR}"cinder_cascading_proxy_aws/cinder"  ./patches_tool/hybrid_cloud_patches/aws_proxy/
    cp -rf ${GIT_CODE_DIR}"cinder_cascading_proxy_normal/cinder"  ./patches_tool/hybrid_cloud_patches/cascading/
    cp -rf ${GIT_CODE_DIR}"cinder_cascading/cinder/volume"  ./patches_tool/hybrid_cloud_patches/cascading/cinder/
    cp -rf ${GIT_CODE_DIR}"nova_cascading/nova/api"  ./patches_tool/hybrid_cloud_patches/cascading/nova/
    cp -rf ${GIT_CODE_DIR}"cinder_cascading_proxy_normal/cinder"  ./patches_tool/hybrid_cloud_patches/vcloud_proxy/

    echo "tar patches_tool.tar ..."
    tar -cf ./patches_tool.tar ./patches_tool >/dev/null 2>&1
	
	return 0;
}

deploy() {
    cd ${LOCAL_PATCH_DIR}

    echo "copy patches_tool to CASCADING_HOST(${CASCADING_HOST}) ..."
    ssh ${RUN_USER}@${CASCADING_HOST} rm -rf ${REMOTE_DIR}
    ssh ${FILE_COPY_USER}@${CASCADING_HOST} mkdir ${REMOTE_DIR}

    scp ./patches_tool.tar ${FILE_COPY_USER}@${CASCADING_HOST}:${REMOTE_DIR}
    ssh ${FILE_COPY_USER}@${CASCADING_HOST} tar -xf ${REMOTE_DIR}patches_tool.tar -C ${REMOTE_DIR} >/dev/null 2>&1

    echo "backup original code..."
    ssh ${RUN_USER}@${CASCADING_HOST} python ${REMOTE_DIR}patches_tool/config.py remote-backup > ./patch_deploy_log.LOG 2>&1

    echo "prepare patch..."
    ssh ${RUN_USER}@${CASCADING_HOST} python ${REMOTE_DIR}patches_tool/config.py prepare >> ./patch_deploy_log.LOG 2>&1

    echo "deploy patch..."
    ssh ${RUN_USER}@${CASCADING_HOST} python ${REMOTE_DIR}patches_tool/patches_tool.py >> ./patch_deploy_log.LOG 2>&1

    sleep 20s
    echo "check deploy result..."
    ssh ${RUN_USER}@${CASCADING_HOST} python ${REMOTE_DIR}patches_tool/config.py check > ./patch_deploy_check.LOG 2>&1
    result=$(cat patch_deploy_check.LOG | grep "fault")
    if [ "$result" = "" ]; then
        echo "deploy patch success."
		return 0;
    else
        echo "found some status of some services are fault. check patch_deploy_check.LOG for more information..."
		return 127;
    fi
}

prepare;
deploy;
if [ "$?" = 0 ]; then
    echo "ok"
else
    echo "error"
fi


