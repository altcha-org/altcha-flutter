cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "altcha_widget")
project(${PROJECT_NAME} LANGUAGES CXX)

# Flutter toolchain provides apply_standard_settings().
set(PLUGIN_NAME "altcha_widget_plugin")

add_library(${PLUGIN_NAME} SHARED
  altcha_widget_plugin.cpp
  altcha_widget_plugin.h
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)

target_compile_features(${PLUGIN_NAME} PRIVATE cxx_std_17)

target_compile_options(${PLUGIN_NAME} PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/O2 /fp:fast>
  $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O3 -ffast-math>
)

# Enable SHA-NI intrinsics on x86-64 MSVC.  /arch:AVX tells MSVC to emit AVX
# instructions and unlocks the SHA-NI intrinsic declarations in <immintrin.h>.
# Runtime CPUID detection in shani_detect() prevents use on CPUs without SHA-NI.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64" OR
   (NOT CMAKE_SYSTEM_PROCESSOR MATCHES "ARM|arm|aarch64"))
  target_compile_options(${PLUGIN_NAME} PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/arch:AVX>
  )
endif()

# Enable hardware SHA-2 on aarch64 (GCC/Clang cross-compile or ARM64 Windows).
# MSVC on ARM64 Windows enables SHA2 intrinsics via <arm_neon.h> when
# __ARM_FEATURE_SHA2 is defined; GCC/Clang need -march=armv8-a+crypto.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
  target_compile_options(${PLUGIN_NAME} PRIVATE
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-march=armv8-a+crypto>
  )
endif()

target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Shared portable PBKDF2 solver (header-only).
target_include_directories(${PLUGIN_NAME} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../common")

target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin)

# No bundled dynamic libraries needed.
set(altcha_widget_bundled_libraries "" PARENT_SCOPE)
