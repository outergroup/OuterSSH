#ifndef OUTERSSH_REMOTE_PLATFORM_H
#define OUTERSSH_REMOTE_PLATFORM_H

#include "WindowsBridgeCommands.h"

#define OUTERSSH_WINDOWS_BRIDGE_EXECUTABLE "outerssh:windows-installed"

#define OUTERSSH_REMOTE_PLATFORM_COMMAND \
    "machine_arch=\"$(uname -m)\"\n" \
    "case \"$(uname -s)\" in\n" \
    "    Darwin) platform=darwin ;;\n" \
    "    Linux)\n" \
    "        if [ \"$(od -An -j4 -N1 -tu1 /bin/sh 2>/dev/null | tr -d ' ')\" = 1 ]; then\n" \
    "            case \"$machine_arch\" in\n" \
    "                aarch64|arm64) machine_arch=armv8l ;;\n" \
    "                x86_64|amd64) machine_arch=i686 ;;\n" \
    "            esac\n" \
    "        fi\n" \
    "        if ls /lib/ld-musl-*.so.1 >/dev/null 2>&1 || { command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; }; then\n" \
    "            platform=musl\n" \
    "        else\n" \
    "            platform=glibc\n" \
    "        fi ;;\n" \
    "    *) echo \"Unsupported remote operating system\" >&2; exit 1 ;;\n" \
    "esac\n" \
    "printf '%s %s\\n' \"$machine_arch\" \"$platform\"\n"

#define OUTERSSH_WINDOWS_PLATFORM_COMMAND OUTERSSH_WINDOWS_BRIDGE_PLATFORM_COMMAND

#endif
