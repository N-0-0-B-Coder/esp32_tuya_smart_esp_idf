# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
set(EXTRA_COMPONENT_DIRS 
    ${CMAKE_CURRENT_LIST_DIR}/lib
    ${CMAKE_CURRENT_LIST_DIR}/lib/gpio
    ${CMAKE_CURRENT_LIST_DIR}/services
    ${CMAKE_CURRENT_LIST_DIR}/application
)

# Debug message to verify EXTRA_COMPONENT_DIRS
message(STATUS "Extra component directories: ${EXTRA_COMPONENT_DIRS}")

project(imic_embedded_iot)
