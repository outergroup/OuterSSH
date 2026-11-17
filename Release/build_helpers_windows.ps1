# Builds outerssh-helper.exe with a static runtime. Run it from the repository root
# in a Visual Studio developer environment for the target architecture, with CMake,
# Ninja, and LLVM's clang-cl. It leaves an unsigned outerssh-helper.exe in the output directory.
# Release/package_helper_windows.sh turns it into the archive OuterSSH uploads.
param(
    [Parameter(Mandatory = $true)][ValidateSet('arm64', 'x64', 'x86')][string]$Architecture,
    [Parameter(Mandatory = $true)][string]$Output
)

$ErrorActionPreference = 'Stop'
$targets = @{ arm64 = 'aarch64-pc-windows-msvc'; x64 = 'x86_64-pc-windows-msvc'; x86 = 'i686-pc-windows-msvc' }
$build = "build/release-windows-helper-$Architecture"

if (Test-Path $build) { Remove-Item -Recurse -Force $build }
& cmake -S OuterSSHHelper/Windows -B $build -G Ninja '-DCMAKE_BUILD_TYPE=Release' `
    '-DCMAKE_C_COMPILER=clang-cl' "-DCMAKE_C_COMPILER_TARGET=$($targets[$Architecture])" '-DBUILD_TESTING=OFF'
if ($LASTEXITCODE -ne 0) { throw 'Configuring outerssh-helper failed' }
& cmake --build $build --target outerssh-helper
if ($LASTEXITCODE -ne 0) { throw 'Building outerssh-helper failed' }

$binary = "$build/outerssh-helper.exe"
& $binary --version
if ($LASTEXITCODE -ne 0) { throw 'outerssh-helper --version failed' }
New-Item -ItemType Directory -Force $Output | Out-Null
Copy-Item $binary $Output
Write-Host "Built $Output/outerssh-helper.exe"
