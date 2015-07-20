#!/bin/bash
if [ -d "./patches_tool" ]; then
    echo "delete file, file_dir=./patches_tool"
	rm -rf ./patches_tool
fi

if [ -f "./patches_tool.tar" ]; then
    echo "delete file, file=./patches_tool.tar"
	rm ./patches_tool.tar
fi

ROOT_DIR="/var/lib/jenkins/jobs/badam/workspace/"
SOR_ROOT_DIR=${ROOT_DIR}"fs_patches_of_hybrid_cloud/cherry_for_B038/"
PATCH_TOOL_DIR=${ROOT_DIR}"patches_tool/"

cp -rf ${PATCH_TOOL_DIR} ./

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
cp -rf ${SOR_ROOT_DIR}"cinder_cascaded_aws/cinder"/*  ./patches_tool/aws_patch/code/cinder/
cp -rf ${SOR_ROOT_DIR}"neutron_cascaded_aws/neutron"/*  ./patches_tool/aws_patch/code/neutron/
cp -rf ${SOR_ROOT_DIR}"nova_cascaded/nova/virt/aws"/*  ./patches_tool/aws_patch/code/nova/virt/aws/
cp -rf ${SOR_ROOT_DIR}"nova_cascaded/nova/virt/vtep"/*  ./patches_tool/aws_patch/code/nova/virt/vtep/


cp -rf ${SOR_ROOT_DIR}"cinder_cascaded_normal/cinder"/*  ./patches_tool/vcloud_patch/code/cinder/
cp -rf ${SOR_ROOT_DIR}"nova_cascaded/nova/virt/vcloudapi"/*  ./patches_tool/vcloud_patch/code/nova/virt/vcloudapi/
cp -rf ${SOR_ROOT_DIR}"nova_cascaded/nova/virt/vmwareapi"/*  ./patches_tool/vcloud_patch/code/nova/virt/vmwareapi/
cp -rf ${SOR_ROOT_DIR}"nova_cascaded/nova/virt/vtep"/*  ./patches_tool/vcloud_patch/code/nova/virt/vtep/


cp -rf ${SOR_ROOT_DIR}"cinder_cascading_proxy_aws/cinder"/*  ./patches_tool/hybrid_cloud_patches/aws_proxy/cinder/
cp -rf ${SOR_ROOT_DIR}"cinder_cascading_proxy_normal/cinder"/*  ./patches_tool/hybrid_cloud_patches/cascading/cinder/
cp -rf ${SOR_ROOT_DIR}"cinder_cascading/cinder/volume"/*  ./patches_tool/hybrid_cloud_patches/cascading/cinder/volume/
cp -rf ${SOR_ROOT_DIR}"nova_cascading/nova/api"/*  ./patches_tool/hybrid_cloud_patches/cascading/nova/api/
cp -rf ${SOR_ROOT_DIR}"cinder_cascading_proxy_normal/cinder"/*  ./patches_tool/hybrid_cloud_patches/vcloud_proxy/cinder/

echo "tar patches_tool.tar ..."
tar -cf ./patches_tool.tar ./patches_tool
