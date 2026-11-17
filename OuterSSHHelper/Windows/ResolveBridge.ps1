$ErrorActionPreference='Stop'
$i=[Security.Principal.WindowsIdentity]::GetCurrent()
$a=([Security.Principal.WindowsPrincipal]::new($i)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$t=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
function Check($p,$directory,$creation){
$x=[IO.File]::GetAttributes($p)
if((($x -band 16) -ne 0) -ne $directory -or ($x -band 1024)){throw 'Unsafe bridge path'}
if(!$a){return}
$d=if($directory){[IO.Directory]::GetAccessControl($p)}else{[IO.File]::GetAccessControl($p)}
if($d.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $t){throw 'Untrusted bridge owner'}
$m=0xD0040
if(!$creation){$m=$m -bor 0x116}
foreach($r in $d.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
if(($r.PropagationFlags -band 2) -eq 0 -and $r.AccessControlType -eq 0 -and ($r.FileSystemRights -band $m) -and $r.IdentityReference.Value -notin $t){throw 'Writable elevated bridge path'}
}
}
if($a){
$p=[Environment]::GetFolderPath('CommonApplicationData')
Check ([IO.Path]::GetPathRoot($p)) $true $true
Check $p $true $true
foreach($s in @('OuterSSH','Users',$i.User.Value)){$p=[IO.Path]::Combine($p,$s);Check $p $true $false}
}else{
$p=[IO.Path]::Combine([Environment]::GetFolderPath('LocalApplicationData'),'OuterSSH')
Check $p $true $false
}
$c=[IO.Path]::Combine($p,'current.txt')
Check $c $false $false
$v=[IO.File]::ReadAllText($c).Trim()
if($v -cnotmatch '\A[0-9a-f]{64}\z'){throw 'Invalid bridge version'}
foreach($s in @('versions',$v)){$p=[IO.Path]::Combine($p,$s);Check $p $true $false}
$p=[IO.Path]::Combine($p,'outerssh-helper.exe')
Check $p $false $false
$s=[Diagnostics.ProcessStartInfo]::new()
$s.FileName=$p
$s.Arguments=$outerBridgeArguments
$s.UseShellExecute=$false
$q=[Diagnostics.Process]::Start($s)
$q.WaitForExit()
exit $q.ExitCode
