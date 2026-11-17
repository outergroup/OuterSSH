set(OUTERSSH_HELPER_WINDOWS_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}")

# Adds a Windows helper executable built from the OuterSSH helper sources and
# the given sources, one of which defines wmain.
function(outerssh_add_windows_helper target)
    set(directory "${OUTERSSH_HELPER_WINDOWS_DIRECTORY}")
    add_executable(${target} ${ARGN} "${directory}/Helper.c" "${directory}/NamedPipes.c"
        "${directory}/EndpointNames.c" "${directory}/EndpointIcons.c"
        "${directory}/../../OuterSSH/HelperProtocol.c" "${directory}/../../OuterSSH/SSHEndpointNames.c")
    target_include_directories(${target} PRIVATE "${directory}/../../OuterSSH/include")
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(${target} PRIVATE advapi32 shell32 ole32 oleaut32 taskschd uuid)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX $<$<NOT:$<CONFIG:Debug>>:/O1>)
        target_compile_definitions(${target} PRIVATE $<$<NOT:$<CONFIG:Debug>>:OUTERSSH_HELPER_ENTRY>)
        target_link_options(${target} PRIVATE
            $<$<NOT:$<CONFIG:Debug>>:/ENTRY:outerssh_helper_entry /NODEFAULTLIB:libucrt.lib /DEFAULTLIB:ucrt.lib /DEFAULTLIB:libvcruntime.lib>)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
    endif()
    if(MINGW)
        target_link_options(${target} PRIVATE -municode)
    endif()
endfunction()
