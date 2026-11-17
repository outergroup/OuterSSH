param(
    [Parameter(Mandatory = $true)][string]$VcpkgRoot,
    [string]$BuildDirectory,
    [ValidateSet('clang', 'msvc')][string]$Compiler = 'clang',
    [ValidateSet('arm64', 'x64')][string]$Architecture = 'arm64',
    [string]$FixtureDirectory,
    [string]$SSHHost,
    [int]$SSHPort = 22222
)

$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '../OuterSSH'
$triplet = "$Architecture-windows-static"
$target = if ($Architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
if (!$BuildDirectory) { $BuildDirectory = "$PSScriptRoot/../../build/outerssh-windows-$Compiler" }
[string[]]$compilerOptions = if ($Compiler -eq 'msvc') {
    @('-DCMAKE_C_COMPILER=cl')
} else {
    @('-DCMAKE_C_COMPILER=clang', "-DCMAKE_C_COMPILER_TARGET=$target")
}

& cmake -S $source -B $BuildDirectory -G Ninja `
    @compilerOptions '-DCMAKE_BUILD_TYPE=Debug' `
    '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDebug' `
    "-DCMAKE_TOOLCHAIN_FILE=$VcpkgRoot/scripts/buildsystems/vcpkg.cmake" `
    "-DVCPKG_TARGET_TRIPLET=$triplet" '-DOUTERSSH_BUILD_TESTS=ON'
if ($LASTEXITCODE -ne 0) { throw 'OuterSSH configuration failed' }
& cmake --build $BuildDirectory --parallel 4
if ($LASTEXITCODE -ne 0) { throw 'OuterSSH build failed' }
& ctest --test-dir $BuildDirectory --output-on-failure
if ($LASTEXITCODE -ne 0) { throw 'OuterSSH tests failed' }

if ($FixtureDirectory) {
    if (!$SSHHost) { throw 'Supply SSHHost when using an external SSH fixture' }
    $authenticationTest = Join-Path $BuildDirectory 'outerssh-authentication-test.exe'
    foreach ($expected in @('success', 'reject', 'cancel', 'timeout')) {
        & $authenticationTest $SSHPort 'outerssh-test' 'password' 'outerssh-test-password' `
            'unused' 'C:\OuterLoopDev\no-agent' $expected $SSHHost
        if ($LASTEXITCODE -ne 0) { throw "OuterSSH authentication test failed: $expected" }
    }
    & $authenticationTest $SSHPort 'outerssh-test' 'password' 'incorrect' `
        'unused' 'C:\OuterLoopDev\no-agent' 'failure' $SSHHost
    if ($LASTEXITCODE -ne 0) { throw 'OuterSSH authentication rejection test failed' }
    $fixture = Get-Content (Join-Path $FixtureDirectory 'ready.json') -Raw | ConvertFrom-Json
    & (Join-Path $BuildDirectory 'outerssh-integration-test.exe') `
        $SSHPort (Join-Path $FixtureDirectory 'client') `
        (Join-Path $FixtureDirectory 'host.blob') $fixture.echo_port $fixture.unix_socket `
        (Join-Path $FixtureDirectory 'outerssh-test-bridge') $SSHHost
    if ($LASTEXITCODE -ne 0) { throw 'OuterSSH SSH integration test failed' }
}
