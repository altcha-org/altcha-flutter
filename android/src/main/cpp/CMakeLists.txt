cmake_minimum_required(VERSION 3.18.1)
project(altcha_pbkdf2)

add_library(altcha_pbkdf2 SHARED altcha_pbkdf2.cpp)

target_compile_options(altcha_pbkdf2 PRIVATE
    -O3
    -ffast-math
    $<$<STREQUAL:${ANDROID_ABI},arm64-v8a>:-march=armv8-a>
)

find_library(log-lib log)
target_link_libraries(altcha_pbkdf2 ${log-lib})

# Android 15+ requires ELF load segments to be aligned to 16 KB page
# boundaries. The linker flag is harmless on older devices.
target_link_options(altcha_pbkdf2 PRIVATE -Wl,-z,max-page-size=16384)
