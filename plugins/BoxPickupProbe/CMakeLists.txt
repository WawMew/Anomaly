cmake_minimum_required(VERSION 3.22)

project(AnomalyBoxPickupProbe LANGUAGES CXX)

if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "BoxPickupProbe targets Windows x64")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(AnomalySDK CONFIG REQUIRED)

set(BOX_PICKUP_PROBE_PACKAGE_DIRECTORY
    "${CMAKE_BINARY_DIR}/package/BoxPickupProbe")

anomaly_add_plugin(anomaly_box_pickup_probe
    SOURCES plugin.cpp
    MANIFEST manifest.json
    PACKAGE_NAME BoxPickupProbe
    OUTPUT_DIRECTORY "${BOX_PICKUP_PROBE_PACKAGE_DIRECTORY}")

target_include_directories(anomaly_box_pickup_probe PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../..")
target_compile_definitions(anomaly_box_pickup_probe PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

# `anomaly_add_plugin` mirrors the manifest and the `locales` directory next to it into the
# package directory, and installs the package into Anomaly/plugins/BoxPickupProbe.
