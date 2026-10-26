cmake_minimum_required(VERSION 3.22.1)
project(vpngate_jni LANGUAGES C)

add_library(vpngate_jni SHARED vpngate_jni.c)
target_compile_options(vpngate_jni PRIVATE -O2 -Wall -Wextra)
target_link_libraries(vpngate_jni dl log)
