#!/bin/bash
HYBRID_TEST_DIR="/home/fsp/hybrid_test/"
TEST_FILE_DIR="/home/fsp/hybrid_test/test_case/"
LOG_FILE_DIR="/home/fsp/hybrid_test/test_case_log/"
RESULT_LOG=${LOG_FILE_DIR}"test_case_result.log"

success=0
failed=0

if [ ! -d ${LOG_FILE_DIR} ]; then
    mkdir -p ${LOG_FILE_DIR}
fi

if [ -f ${RESULT_LOG} ]; then
    rm ${RESULT_LOG}
fi

echo "Start Test" > ${RESULT_LOG}
for module in `ls ${TEST_FILE_DIR}`
do
    if [ -d ${TEST_FILE_DIR}${module} ]; then
	    echo "==================================================================" >> ${RESULT_LOG}
        echo "Test module: ${module}" >> ${RESULT_LOG}
	    module_dir=${TEST_FILE_DIR}${module}"/"
	    module_log_dir=${LOG_FILE_DIR}${module}"/"
	
	    for filename in `ls ${module_dir} | grep 'test_.*.py'`
        do
            echo "------------------------------------------------------------------" >> ${RESULT_LOG}
            test_case_name=${filename%%".py"}

            if [ ! -d ${module_log_dir}${test_case_name} ]; then
                echo "creat log dir (${module_log_dir}${test_case_name})"
                mkdir -p ${module_log_dir}${test_case_name}
            fi
		
            python ${module_dir}${filename} > ${module_log_dir}${test_case_name}/result.txt 2>&1

            result=`tail -1 ${module_log_dir}${test_case_name}/result.txt`
            echo -e "Test name : ${test_case_name}\t\tTest result : ${result}" >> ${RESULT_LOG}
    
            if [ "$(cat patch_deploy_check.LOG | grep "OK")" != "" ]; then
                success=`expr $success + 1`
			else
			    failed=`expr $failed + 1`
            fi
        done
	fi
done

echo ""
echo "==================================================================" >> ${RESULT_LOG}
echo "success test: ${success}" >> ${RESULT_LOG}
echo "failed test: ${failed}" >> ${RESULT_LOG}

echo "Finish Test Case"
cd ${HYBRID_TEST_DIR}
tar -cf ./test_case_log.tar ./test_case_log