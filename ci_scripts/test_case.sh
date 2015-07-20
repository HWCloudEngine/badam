#!/bin/bash
ROOT_DIR="/var/lib/jenkins/scripts/"

PRE_TEST_DIR=${ROOT_DIR}"hybrid_test_case/"
TEST_CASE_DIR=${PRE_TEST_DIR}"test_case/"

TEST_CASE_DIR_NAME="test_case"
TEST_CASE_TAR="test_case.tar"
TEST_CASE_LOG_FILE="test_case_log.tar"
RUN_TEST_CASE_SH="run_test_case.sh"

if [ ! -d ${PRE_TEST_DIR} ]; then
    mkdir -p ${PRE_TEST_DIR}
fi

if [ -d ${TEST_CASE_DIR} ]; then
    echo "delete test case dir( ${TEST_CASE_DIR} )"
	rm -rf ${TEST_CASE_DIR}
fi

if [ -f ${PRE_TEST_DIR}${TEST_CASE_TAR} ]; then
    echo "delete test case file( ${PRE_TEST_DIR}${TEST_CASE_TAR} )"
	rm ${PRE_TEST_DIR}${TEST_CASE_TAR}
fi

TEST_CASE_SCRIPTS_DIR="/var/lib/jenkins/jobs/badam/workspace/high_level_test"

mkdir -p ${TEST_CASE_DIR}
cp -rf ${TEST_CASE_SCRIPTS_DIR}/* ${TEST_CASE_DIR}
cd ${PRE_TEST_DIR}
tar -cf ${TEST_CASE_TAR} ${TEST_CASE_DIR_NAME}
cd ..

HOST_CASCADING=162.3.120.50
FILE_COPY_USER=fsp
RUN_USER=root
DES_DIR="/home/"${FILE_COPY_USER}"/hybrid_test/"

echo "copy test_case.tar to HOST_CASCADING(${HOST_CASCADING}) ..."
ssh ${RUN_USER}@${HOST_CASCADING} rm -rf ${DES_DIR}
ssh ${FILE_COPY_USER}@${HOST_CASCADING} mkdir -p ${DES_DIR}

scp ${PRE_TEST_DIR}${TEST_CASE_TAR} ${FILE_COPY_USER}@${HOST_CASCADING}:${DES_DIR}
ssh ${FILE_COPY_USER}@${HOST_CASCADING} tar -xf ${DES_DIR}${TEST_CASE_TAR} -C ${DES_DIR}
scp ${ROOT_DIR}${RUN_TEST_CASE_SH} ${FILE_COPY_USER}@${HOST_CASCADING}:${DES_DIR}

ssh ${FILE_COPY_USER}@${HOST_CASCADING} /bin/sh ${DES_DIR}${RUN_TEST_CASE_SH}

if [ $?=0 ]; then
    echo "Run Test Case Finished!"
	scp ${FILE_COPY_USER}@${HOST_CASCADING}:${DES_DIR}${TEST_CASE_LOG_FILE} ${PRE_TEST_DIR}
	tar -xf ${PRE_TEST_DIR}${TEST_CASE_LOG_FILE} -C ${PRE_TEST_DIR}
fi