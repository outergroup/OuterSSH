function(add_flow_test name)
    set(sources "test_${name}.c")
    foreach(source IN LISTS ARGN)
        list(APPEND sources "${PROJECT_SOURCE_DIR}/${source}")
    endforeach()
    add_executable(${name} ${sources})
    target_include_directories(${name} PRIVATE
        "${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/include/OuterSSH"
        "${PROJECT_SOURCE_DIR}/olibssh/libssh2")
    target_compile_definitions(${name} PRIVATE LIBSSH2_STATIC)
    if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
        # Test doubles can make included flow branches unreachable or shadow globals.
        target_compile_options(${name} PRIVATE /UNDEBUG /W4 /WX
            /wd4505 /wd4100 /wd4459 /wd4702 /Gy /Gw)
    else()
        target_compile_options(${name} PRIVATE "$<$<COMPILE_LANGUAGE:C>:-UNDEBUG;-Wall;-Wextra;-Werror;\
-Wno-unused-function;-Wno-unused-parameter;-ffunction-sections;-fdata-sections>")
    endif()
    if(WIN32 OR name STREQUAL "ssh_socket_preparation_flows")
        target_sources(${name} PRIVATE "UnusedFlowDependencies.c")
    endif()
    if(WIN32)
        if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
            target_link_options(${name} PRIVATE /OPT:REF /INCREMENTAL:NO)
        else()
            target_link_options(${name} PRIVATE -Wl,/OPT:REF -Wl,/INCREMENTAL:NO)
        endif()
    elseif(APPLE)
        target_link_options(${name} PRIVATE LINKER:-dead_strip)
    else()
        target_link_options(${name} PRIVATE -Wl,--gc-sections)
    endif()
    target_link_libraries(${name} PRIVATE OuterSSHRuntime Threads::Threads)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 60)
endfunction()

add_flow_test(socket_bridge_commands SocketBridgeCommands.c)
add_flow_test(ssh_bridge_flows SocketBridgeCommands.c SSHProxyError.c)
add_flow_test(proxy_connect ProxyReactor.c ProxyPendingConnections.c ProxySOCKSHandshake.c SSHProxyError.c)
add_flow_test(ssh_controller_flows SSHProxyError.c SocketBridgeCommands.c SSHEndpointNames.c SSHEvents.c SSHBridgeBinary.c)
add_flow_test(ssh_listener_flows SSHProxyError.c)
add_flow_test(ssh_reactor)
add_flow_test(ssh_reactor_lifecycle HelperProtocol.c SSHProxyError.c)
add_flow_test(ssh_recovery_flows SSHProxyError.c)
add_flow_test(ssh_relay_flows SSHProxyError.c)
add_flow_test(ssh_socket_service SSHProxyError.c SocketBridgeCommands.c SSHEndpointNames.c SSHEvents.c SSHBridgeBinary.c)
add_flow_test(ssh_socket_preparation_flows SSHProxyError.c SocketBridgeCommands.c)
add_flow_test(ssh_session_flows SSHProxyError.c)
add_flow_test(ssh_proxy_error)
add_flow_test(socket_bridge_protocol HelperProtocol.c)
add_flow_test(proxy_socks_handshake ProxyReactor.c SSHProxyError.c)

add_flow_test(otqueue_contract)

add_flow_test(ssh_session_start SSHProxyError.c)
target_link_libraries(ssh_session_start PRIVATE OuterSSH ${OUTERSSH_CRYPTO_LIBRARIES})

if(NOT OUTERSSH_WINDOWS_CRYPTO AND NOT OUTERSSH_APPLE_CRYPTO)
add_test(NAME ssh_session_start_software COMMAND ssh_session_start chacha20-poly1305@openssh.com)
set_tests_properties(ssh_session_start_software PROPERTIES
    ENVIRONMENT "OPENSSL_armcap=0;OPENSSL_ia32cap=0:0")
endif()

add_flow_test(ssh_handshake)
target_link_libraries(ssh_handshake PRIVATE OuterSSH)

add_flow_test(ssh_authentication olibssh/key_exchange.c)
target_include_directories(ssh_authentication PRIVATE
    "${PROJECT_SOURCE_DIR}/olibssh/libssh2")
target_link_libraries(ssh_authentication PRIVATE OuterSSH ${OUTERSSH_CRYPTO_LIBRARIES})

add_flow_test(endpoint_names SSHEndpointNames.c)
target_include_directories(endpoint_names PRIVATE "${PROJECT_SOURCE_DIR}/include")
