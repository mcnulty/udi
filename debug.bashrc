#
# Source to set up your environment for debugging and test purposes in 
# a UNIX environment
#

UDI_SRC_ROOT=`pwd`
export UDI_SRC_ROOT

UDIRT_BUILD_DIR=${UDI_SRC_ROOT}/libudirt/build
export UDIRT_BUILD_DIR

UDI_BUILD_DIR=${UDI_SRC_ROOT}/libudi/build

UDI_LIB_DIR=${UDI_BUILD_DIR}/src
export UDI_LIB_DIR

UDI_RT_LIB_DIR=${UDIRT_BUILD_DIR}/src
export UDI_RT_LIB_DIR

UDI_LIB_TEST_DIR=${UDI_BUILD_DIR}/tests/udi_tests
export UDI_LIB_TEST_DIR

UDI_RT_LIB_TEST_DIR=${UDIRT_BUILD_DIR}/libudirt/tests/src
export UDI_RT_LIB_TEST_DIR

UDI_TEST_LIB_DIR=${UDIRT_BUILD_DIR}/tests/libuditest
export UDI_TEST_LIB_DIR

if [ ! -z ${LD_LIBRARY_PATH} ]; then
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${UDI_LIB_DIR}:${UDI_RT_LIB_DIR}:${UDI_TEST_LIB_DIR}
else
    export LD_LIBRARY_PATH=${UDI_LIB_DIR}:${UDI_RT_LIB_DIR}:${UDI_TEST_LIB_DIR}
fi
