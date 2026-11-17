param(
    [Parameter(Mandatory=$true)][string]$SourcePath,
    [string]$UserSid
)
$ErrorActionPreference = 'Stop'
if ([Environment]::SystemDirectory -ine 'C:\Windows\System32') {
    throw 'The Windows SSH client currently requires Windows installed at C:\Windows.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$UserSid) { $UserSid = $identity.User.Value }
$UserSid = ([Security.Principal.SecurityIdentifier]::new($UserSid)).Value
if (!$elevated -and $UserSid -ne $identity.User.Value) {
    throw 'A non-administrative installation can only target the current user.'
}
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
if (!$elevated) { $trusted += $UserSid }
function Assert-SafePath([string]$Path, [bool]$Directory, [bool]$AllowCreation=$false) {
    $item = Get-Item -Force -LiteralPath $Path
    if ($item.PSIsContainer -ne $Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unsafe SSH bridge path: $Path"
    }
    $existing = Get-Acl -LiteralPath $Path
    if ($existing.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) {
        throw "Untrusted SSH bridge owner: $Path"
    }
    $mask = [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete
    if (!$AllowCreation) { $mask = $mask -bor [Security.AccessControl.FileSystemRights]::Write }
    foreach ($rule in $existing.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band $mask) -and $rule.IdentityReference.Value -notin $trusted) {
            throw "SSH bridge path permits untrusted modification: $Path"
        }
    }
}
$sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
$owner = if ($elevated) { 'BA' } else { $UserSid }
$directoryAcl = New-Object Security.AccessControl.DirectorySecurity
$directoryAcl.SetSecurityDescriptorSddlForm("O:${owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$owner)", $sections)
$fileAcl = New-Object Security.AccessControl.FileSecurity
$fileAcl.SetSecurityDescriptorSddlForm("O:${owner}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$owner)", $sections)
function Prepare-Directory([string]$Path) {
    if (!(Test-Path -LiteralPath $Path)) { [void][IO.Directory]::CreateDirectory($Path, $directoryAcl) }
    Assert-SafePath $Path $true
}
function Publish-File([string]$Target, [byte[]]$Bytes) {
    if (Test-Path -LiteralPath $Target) { Assert-SafePath $Target $false }
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($Target)) ([Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($temporary, $Bytes)
        [IO.File]::SetAccessControl($temporary, $fileAcl)
        if (Test-Path -LiteralPath $Target) { [IO.File]::Replace($temporary, $Target, [NullString]::Value) }
        else { [IO.File]::Move($temporary, $Target) }
        Assert-SafePath $Target $false
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
$source = Get-Item -Force -LiteralPath $SourcePath
if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The bridge source must be a regular executable file.'
}
$bytes = [IO.File]::ReadAllBytes($source.FullName)
$sha = [Security.Cryptography.SHA256]::Create()
try { $version = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
finally { $sha.Dispose() }
if ($elevated) {
    $destination = [Environment]::GetFolderPath('CommonApplicationData')
    Assert-SafePath ([IO.Path]::GetPathRoot($destination)) $true $true
    Assert-SafePath $destination $true $true
    foreach ($part in @('OuterSSH','Users',$UserSid)) {
        $destination = Join-Path $destination $part
        Prepare-Directory $destination
    }
} else {
    $destination = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'OuterSSH'
    Prepare-Directory $destination
}
$versions = Join-Path $destination 'versions'
Prepare-Directory $versions
$versionDirectory = Join-Path $versions $version
Prepare-Directory $versionDirectory
$target = Join-Path $versionDirectory 'outerssh-helper.exe'
if (Test-Path -LiteralPath $target) {
    Assert-SafePath $target $false
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -ne $version) {
        throw 'An installed bridge version has unexpected contents.'
    }
} else { Publish-File $target $bytes }
Publish-File (Join-Path $destination 'current.txt') ([Text.Encoding]::ASCII.GetBytes($version))
$mode = if ($elevated) { 'administrator-protected' } else { 'non-administrative' }
Write-Output "Installed $mode SSH bridge for $UserSid at $target"
