# Builds outerssh.exe with a static runtime and static zlib, using Windows CNG for
# cryptography. Run it from the repository root in a Visual Studio developer
# environment for the target architecture, with CMake, Ninja, Clang, and vcpkg.
# It leaves an unsigned outerssh.exe in the output directory.
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][ValidateSet('arm64', 'x64')][string]$Architecture,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$VcpkgRoot = $env:VCPKG_INSTALLATION_ROOT
)

$ErrorActionPreference = 'Stop'
if (!$VcpkgRoot) { throw 'Pass -VcpkgRoot or set VCPKG_INSTALLATION_ROOT' }
$triplet = "$Architecture-windows-static"
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$build = "build/release-windows-$Architecture"

& "$VcpkgRoot/vcpkg" install "zlib:$triplet"
if ($LASTEXITCODE -ne 0) { throw 'Installing zlib failed' }

if (Test-Path $build) { Remove-Item -Recurse -Force $build }
& cmake -S OuterSSH -B $build -G Ninja '-DCMAKE_BUILD_TYPE=Release' `
    '-DCMAKE_C_COMPILER=clang' "-DCMAKE_C_COMPILER_TARGET=$target" `
    '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded' `
    "-DCMAKE_TOOLCHAIN_FILE=$VcpkgRoot/scripts/buildsystems/vcpkg.cmake" `
    "-DVCPKG_TARGET_TRIPLET=$triplet" `
    '-DOUTERSSH_BUILD_CLI=ON' '-DOUTERSSH_BUILD_TESTS=OFF' "-DOUTERSSH_CLI_VERSION=$Version"
if ($LASTEXITCODE -ne 0) { throw 'Configuring outerssh failed' }
& cmake --build $build --target outerssh
if ($LASTEXITCODE -ne 0) { throw 'Building outerssh failed' }

$binary = "$build/bin/outerssh.exe"
& $binary --version
if ($LASTEXITCODE -ne 0) { throw 'outerssh --version failed' }
New-Item -ItemType Directory -Force $Output | Out-Null
Copy-Item $binary, LICENSE $Output
Write-Host "Built $Output/outerssh.exe"
