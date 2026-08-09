if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.20)
    project(OpenConnectNativeCore LANGUAGES CXX)

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENCONNECT REQUIRED openconnect)
    pkg_check_modules(GNUTLS REQUIRED gnutls)

    set(existing_openconnect_includes)
    foreach(include_dir IN LISTS OPENCONNECT_INCLUDE_DIRS)
        if(EXISTS "${include_dir}")
            list(APPEND existing_openconnect_includes "${include_dir}")
        endif()
    endforeach()
    set(OPENCONNECT_INCLUDE_DIRS ${existing_openconnect_includes})
    set(GNUTLS_INCLUDE_DIR ${GNUTLS_INCLUDE_DIRS})
    link_directories(${OPENCONNECT_LIBRARY_DIRS} ${GNUTLS_LIBRARY_DIRS})
    set(OPENCONNECT_LIBRARIES ${OPENCONNECT_LIBRARIES})
    set(GNUTLS_LIBRARY ${GNUTLS_LIBRARIES})
endif()

add_library(openconnect-core STATIC
    vpn_types.cpp
    vpn_types.h
    openconnect_session.cpp
    openconnect_session.h
    openconnect_core_c.cpp
    openconnect_core_c.h
)

add_executable(openconnect-core-helper
    openconnect_core_helper.cpp
)

add_executable(openvpn-core-helper
    openvpn_core_helper.cpp
)

target_compile_features(openvpn-core-helper PRIVATE cxx_std_17)

target_link_libraries(openconnect-core-helper PRIVATE
    openconnect-core
    ${OPENCONNECT_LIBRARIES}
    ${GNUTLS_LIBRARY}
)

target_include_directories(openconnect-core-helper PRIVATE
    ${OPENCONNECT_INCLUDE_DIRS}
    ${GNUTLS_INCLUDE_DIR}
)

target_compile_features(openconnect-core-helper PRIVATE cxx_std_17)

set_target_properties(openconnect-core-helper PROPERTIES
    AUTOMOC OFF
    AUTOUIC OFF
    AUTORCC OFF
)

set_target_properties(openvpn-core-helper PROPERTIES
    AUTOMOC OFF
    AUTOUIC OFF
    AUTORCC OFF
)

target_include_directories(openconnect-core
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(openconnect-core PUBLIC cxx_std_17)

target_include_directories(openconnect-core PRIVATE
    ${OPENCONNECT_INCLUDE_DIRS}
    ${GNUTLS_INCLUDE_DIR}
)

target_link_libraries(openconnect-core PRIVATE
    ${OPENCONNECT_LIBRARIES}
    ${GNUTLS_LIBRARY}
)

# Keep this target independent from the user interface layer.
set_target_properties(openconnect-core PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    AUTOMOC OFF
    AUTOUIC OFF
    AUTORCC OFF
)
