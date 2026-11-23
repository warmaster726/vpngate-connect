cmake_minimum_required(VERSION 3.24)
project(vpngate_installer_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Widgets)

add_library(vpngate_installer_core
    src/installer_core.cpp
    src/installer_core.hpp
    src/host_integration.cpp
    src/host_integration.hpp
)
target_link_libraries(vpngate_installer_core PUBLIC Qt6::Core)
target_include_directories(vpngate_installer_core PUBLIC src)

# One application: no arguments opens the GUI; any CLI arguments select headless mode.
add_executable(vpngate-installer
    src/gui_main.cpp
    src/main_window.cpp
    src/main_window.hpp
)
target_link_libraries(vpngate-installer PRIVATE vpngate_installer_core Qt6::Widgets)
target_compile_definitions(vpngate-installer PRIVATE VPNGATE_INSTALLER_VERSION="${PROJECT_VERSION}")
if(WIN32)
    set_target_properties(vpngate-installer PROPERTIES WIN32_EXECUTABLE TRUE)
    target_link_libraries(vpngate_installer_core PUBLIC ole32 shell32 advapi32 user32 rasapi32 uuid)
elseif(APPLE)
    set_target_properties(vpngate-installer PROPERTIES MACOSX_BUNDLE TRUE)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(vpngate-installer-core-tests tests/installer_core_test.cpp)
    target_link_libraries(vpngate-installer-core-tests PRIVATE vpngate_installer_core)
    add_test(NAME vpngate-installer-core-tests COMMAND vpngate-installer-core-tests)
endif()

if(MSVC)
    foreach(target vpngate_installer_core vpngate-installer vpngate-installer-core-tests)
        if(TARGET ${target})
            target_compile_options(${target} PRIVATE /W4 /permissive- /EHsc)
        endif()
    endforeach()
else()
    foreach(target vpngate_installer_core vpngate-installer vpngate-installer-core-tests)
        if(TARGET ${target})
            target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        endif()
    endforeach()
endif()
