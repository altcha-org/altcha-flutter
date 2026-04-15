cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "altcha_widget")
project(${PROJECT_NAME} LANGUAGES CXX)

# Flutter toolchain provides apply_standard_settings().
set(PLUGIN_NAME "altcha_widget_plugin")

add_library(${PLUGIN_NAME} SHARED
  altcha_widget_plugin.cc
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)

target_compile_features(${PLUGIN_NAME} PRIVATE cxx_std_17)

target_compile_options(${PLUGIN_NAME} PRIVATE -O3 -ffast-math)


target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Shared portable PBKDF2 solver (header-only).
target_include_directories(${PLUGIN_NAME} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../common")

target_link_libraries(${PLUGIN_NAME} PRIVATE flutter)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::GTK)

# No bundled dynamic libraries needed.
set(altcha_widget_bundled_libraries "" PARENT_SCOPE)
