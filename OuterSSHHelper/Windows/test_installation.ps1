param([Parameter(Mandatory=$true)][string]$SourcePath, [switch]$RequireNonAdministrative)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($RequireNonAdministrative -and $admin){throw 'Expected a non-administrative token'}
$installer=Join-Path $PSScriptRoot 'install.ps1'
$base=if($admin){Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "OuterSSH\Users\$($identity.User.Value)"}else{Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'OuterSSH'}
& $installer -SourcePath $SourcePath
$original=[IO.File]::ReadAllText((Join-Path $base 'current.txt'))
$installed=Join-Path $base "versions\$original\outerssh-helper.exe"
if((Get-FileHash $installed).Hash.ToLowerInvariant() -ne $original){throw 'Incorrect installed contents'}
$copy=Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N')+'.exe')
try {
    $bytes=[IO.File]::ReadAllBytes($SourcePath)
    [IO.File]::WriteAllBytes($copy,($bytes+[byte]0))
    & $installer -SourcePath $copy
    $updated=[IO.File]::ReadAllText((Join-Path $base 'current.txt'))
    if($original -eq $updated){throw 'Upgrade did not select a new version'}
    if((Get-FileHash $installed).Hash.ToLowerInvariant() -ne $original){throw 'Upgrade modified the previous version'}
    & $installer -SourcePath $SourcePath
} finally {Remove-Item $copy -Force}
if(!$admin){
    $rejected=$false
    try {& $installer -SourcePath $SourcePath -UserSid 'S-1-5-18'} catch {if($_.Exception.Message -notmatch 'only target the current user'){throw};$rejected=$true}
    if(!$rejected){throw 'Non-administrator installed for another account'}
}
$arguments='$outerBridgeArguments=''--version''' + "`n" + [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ResolveBridge.ps1'))
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($arguments))
$result=& C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded
if($LASTEXITCODE -ne 0 -or $result -ne 'outerssh-helper 1 windows'){throw 'Launcher did not run the selected version'}
Write-Output "PASS: installation, immutable upgrade, rollback, and launch for $($identity.User.Value); administrative=$admin"
if($admin){
    function Assert-LaunchRejected {
        $ErrorActionPreference='Continue'
        & C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand $encoded *> $null
        if($LASTEXITCODE -eq 0){throw 'Elevated launcher accepted an unsafe or missing installation'}
    }
    $pointer=Join-Path $base 'current.txt'
    $savedAcl=Get-Acl $pointer
    try {
        $unsafe=Get-Acl $pointer
        $unsafe.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'Write','Allow'))
        Set-Acl $pointer $unsafe
        Assert-LaunchRejected
    } finally {Set-Acl $pointer $savedAcl}
    try {
        [IO.File]::WriteAllText($pointer,'..\other-user\bridge.exe')
        Assert-LaunchRejected
    } finally {[IO.File]::WriteAllText($pointer,$original)}
    $saved=Join-Path $base ([Guid]::NewGuid().ToString('N')+'.saved')
    Move-Item $pointer $saved
    try {Assert-LaunchRejected} finally {Move-Item $saved $pointer}
    Write-Output 'PASS: elevated launcher rejects writable pointers, traversal, and missing protected installation'
}
