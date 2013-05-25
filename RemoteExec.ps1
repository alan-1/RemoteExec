# RemoteExec.ps1 [args]
# /V NNN = Limited execution (first connection to remote computer)
# /X NNN = Unlimited execution (each connection to remote computer)
#
# Scans clients from the textfile provided, testing reverse lookup,
# admin$ share errors & remote registry.  Launches script provided & 
# downloads client logs

#===========================================
# Loop through the data for each computer name
#
# $data = PCs to run script
# $logs = Result file
# $root = Host domain

function Main($args0, $args1) {
  $data = ".\RemoteExec.txt"
  $logs = ".\logs\RemoteExec-{0}.csv" -f (Get-Date -f MMddyyyy-HHmm).ToString()
  $root = "thcg.net"

  echo "Please wait..."
  if (Test-Path $logs) {
    echo "Logfile is in use."
    exit 1}
  
  if (!(Test-Path .\logs\.)) {md .\logs}
  New-Item -force -type file "$logs" | Out-Null
  Add-Content $logs ("`"Report: {0}`"" -f (Get-Date -f MM/dd/yyyy).ToString()) | Out-Null
  if ($args0 -eq $null) {Loop}
  if ($args1 -eq $null) {NoFile}
  if (!(Test-Path $args1)) {NoFile}
  Loop $args0 $args1
}

function Loop($args0, $args1) {
  if (!($args1 -eq $null)) {
    Add-Content $logs ("`"Command: $args0 $args1`"") | Out-Null}

  if (!(Test-Path $path\logs\.)) {md $path\logs}
  $cols = "`"NAME,OU,OS,VERSION,SP,LOGON,STATE,ADDRESS,WINS,WMI,ACL,FILE,UPLOAD,RESULT`""
  Add-Content $logs ($cols.split(",") -join "`",`"") | Out-Null
  type $data | ForEach-Object {
    Start-Job -filepath RemoteExec.ps1 -argumentlist $_.trim(), $args0, $args1 | Out-Null
    Limit 30 3} -end {Limit 0 60}

  if (!($hist -eq $null)) {
    xcopy $path\logs\$hist .\logs\ /s /y | Out-Null
    del $path\logs\$hist -recurse | Out-Null}
    
  dir $path\logs\*.csv -name | ForEach-Object {
    Add-Content $logs (type $path\logs\$_) | Out-Null
    del $path\logs\$_}

  exit
}

#===========================================
# Limit the number of script jobs running
#
# $max = Total concurrent scripts allowed
# $wait = Delay time when limit is reached

Function Limit($max, $wait) {
  $jobs = (Get-Job -state running)
  if ($max -eq 0) {
    if (!($jobs -eq $null)) {
      $jobs | Wait-Job -timeout $wait | Out-Null
      $jobs | Stop-Job -erroraction silentlycontinue}

    echo "`nDone"
    return}

  $jobs = (Get-Job -state running)
  $jobs = ($jobs | Measure-Object).count
  While ($jobs -ge $max) {
    Write-Host -nonewline "`r`t`t`r"
    $jobs = (Get-Job -state running)
    $jobs = ($jobs | Measure-Object).count
    Write-Host -nonewline "Current jobs: $jobs"
    Start-Sleep $wait}

  Write-Host -nonewline "`r`t`t`r"
  return
}

#===========================================
# Ping host, if online lookup IP and domain,
# test WINS (if it fails reporting is finished)

function Test($args0, $args1, $args2) {
  $spec="{|}~[\]^':;<=>?&@!`"#`$%^``()+/,* "
  if ($args0.split($spec).length -ge 2 ) {
    echo "`"$args0`": INVALID NAME"
    echo "`"$args0`",`"INVALID NAME`"" >> $logs
    exit 1}

  $na = "N/A"
  $repo = "$path\logs\{0}.csv" -f $args0
  $stat = @(ping -4 $args0 -i 255 -n 1)
  if ($lastexitcode -gt 0) {
    OffLine $args0
    exit 1} 

  $acc = $true
  $addr = "UNKNOWN"
  $fqdn = "$args0.$root".toupper()
  $stat | ForEach-Object {
    $ip=$_.toupper()
    if ($ip.split(" []:=")[9] -eq "DATA") {
      $addr = $ip.split(" []:=")[3]
      $fqdn = $ip.split(" []:=")[1]}

    if ($ip.split(" []:=")[4] -eq "BYTES") {
      $addr = $ip.split(" []:=")[2]}

    if ($ip.split(" []:=")[4] -eq "TTL") {
      $acc = $false}}

  if (!($acc)) {
    Expired $args0
    exit}

  Wins $args0 $args1 $args2
  exit
}

function Wins($args0, $args1, $args2) {
  $acc = $true
  $dns = $false
  
  For ($pass = 0; $pass -lt 3; ++$pass) {
    $stat = @(ping -4 -a $addr -i 255 -n 1)
    if ($lastexitcode -eq 0) {break}}
    
  if ($lastexitcode -gt 0) {
    TimeOut $args0
    return} 

  $testres = "ONLINE,$addr,PASS"
  $stat | ForEach-Object {
    $ip=$_.toupper()
    if ($ip.split(" []:=.")[1] -eq $args0) {
      $dns = $true} else {

      if ($ip.split(" []:=")[4] -eq "TTL") {
        $acc = $false}}}

  if ($dns) {
    Wmi $args0 $args1 $args2
    return} else {

    if (!($acc)) {
      Expired $args0
      return}}

  BadWins $args0
  return
}

#===========================================
# Run external script provided, test ICS,
# test WMI response and remote registry

function Wmi($args0, $args1, $args2) {
  if ($args1 -eq "/v") {& $args2 $args0}
  if ($args1 -eq "/x") {& $args2 $args0}
  cmd /c sc \\$fqdn interrogate sharedaccess
  if ($lastexitcode -eq 0) {
    FireWall $args0 $args1
    return}

  echo "" | net use \\$fqdn\admin$
  if ($lastexitcode -gt 0) {
    BadWmi $args0 $args1
    return}

  $testres = "$testres,$lastexitcode"
  Acl $args0 $args1
  return
}

function Acl($args0, $args1) {
  reg query "\\$fqdn\HKLM"
  $testres = "$testres,$lastexitcode"
  Prep $args0 $args1
  return
}

#===========================================
# If no $code value reporting is finished, 
# check for script on client (/V only), if
# this exists collect log files, otherwise
# copy script to client and launch
#
# $code = script to launch on client
# $hist = log file to copy from client
# $local = folder where $hist is stored
# $serv = folder where $code is stored
# $work = folder to copy $code on client

function Prep($args0, $args1) {
  $work = "\\$fqdn\admin$\Temp"
  net use \\$fqdn\admin$ /d

  if ($code -eq $null) {
    NoCode $args0
    return}

  $prog = $code.split(" ")[0]
  $vars = $code.substring($prog.length).trim()
  if ($args1 -eq "/x") {
    NoPrep $args0
    return}

  if (Test-Path "$work\$prog") {
    LogFile $args0
    return}
   
  $testres = "$testres,$lastexitcode"
  File $args0
  return
}

function File($args0) {
  xcopy "$serv\$prog" $work\ /y
  if ($lastexitcode -gt 0) {
    BadFile $args0
    return}

  $testres = "$testres,$lastexitcode"
  Exec $args0
  return
}

function Exec($args0) {
  $work = "C:\Windows\Temp"
  psexec \\$fqdn -accepteula -d -h -s cscript.exe $work\$prog "$vars"
  $testres = "$testres,$lastexitcode"
  EndTest $args0
  return
}

function NoPrep($args0) {
  $testres = "$testres,$lastexitcode"
  File $args0
  return
}

#========================
# Log files

function LogFile($args0) {
  $dirs = "$local"
  $testres = "$testres,1,$na,0"
  $user = $env:username
  if (Test-Path "$dirs\$hist") {
    LogHist $args0
    return} else {

    $dirs = "\\$args0\c$\$local"
    if (Test-Path "$dirs\$hist") {
      LogHist $args0
      return}}

  $dirs = "\\$args0\admin$\SysWOW64\CCM\Logs"
  if (Test-Path "$dirs\$hist") {
    LogHist $args0
    return} else {

    $dirs = "\\$args0\admin$\CCMSetup"
    if (Test-Path "$dirs\$hist") {
      LogHist $args0
      return}}

  $dirs = "\\$args0\admin$\System32\Config\SystemProfile\Local Settings\Temp"
  if (Test-Path "$dirs\$hist") {
    LogHist $args0
    return} else {

    $dirs = "\\$args0\admin$\SysWOW64\Config\SystemProfile\AppData\Local\Temp"
    if (Test-Path "$dirs\$hist") {
      LogHist $args0
      return}}

  $dirs = "\\$args0\c$\Documents and Settings\$user\Local Settings\Temp"
  if (Test-Path "$dirs\$hist") {
    LogHist $args0
    return} else {

    $dirs = "\\$args0\c$\Users\$user\AppData\Local\Temp"
    if (Test-Path "$dirs\$hist") {
      LogHist $args0
      return}}

  EndTest $args0
  return
}

function LogHist($args0) {
  xcopy "$dirs\$hist" $path\logs\$args0\ /y | Out-Null
  EndTest $args0
  return
}

#========================
# Reporting errors

function NoFile {
  echo "File not found." 
  echo "File not found." >> $logs
  exit 1
}

function OffLine($args0) {
  $addr = "UNKNOWN"
  $testres = "OFFLINE"
  $stat | ForEach-Object {
    $ip=$_.toupper()
    if ($ip.split(" []:")[9] -eq "DATA") {
      $addr = $ip.split(" []:")[3]}}

  NoEcho $args0
  return
}

function NoEcho($args0) {
  $testres = "$testres,$addr,$na,$na,$na,$na,$na,$na"
  EndTest $args0
  return
}

function Expired($args0) {
  $testres = "EXPIRED"
  NoEcho $args0
  return
}

function TimeOut($args0) {
  $testres = "TIMEOUT"
  NoEcho $args0
  return
}

function BadWins($args0) {
  $testres = "ONLINE,$addr,FAIL,$na,$na,$na,$na,$na"
  EndTest $args0
  return
}

function FireWall($args0) {
  $testres = "FIREWALL"
  NoEcho $args0
  return
}

function BadWmi($args0, $args1) {
  $testres = "$testres,$lastexitcode"
  Acl $args0 $args1
  return
}

function NoCode($args0) {
  $testres = "$testres,$na,$na,$na"
  EndTest $args0
  return
}

function BadFile($args0) {
  $testres = "$testres,$lastexitcode,$na"
  EndTest $args0
  return
}

#========================
# Lookup acct, log results

function EndTest($args0) {
  New-Item -force -type file "$repo" | Out-Null
  $odir = New-Object DirectoryServices.DirectorySearcher
  $odir.Filter = "(&(objectClass=Computer)(samAccountName=$args0$))"
  $odir.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry
  $srch = $odir.FindOne()
  if ($srch -eq $null) {
    $vals = "`"$args0,$na,$na,$na,$na,$na,$testres`""
    Add-Content $repo ($vals.split(",") -join "`",`"") | Out-Null
    return}

  $adcn=$srch.path
  $adou=$adcn.split(",")
  $ado=$adou[$adou.count-3]
  $log=$srch.properties.item('lastlogontimestamp')
  $logd=[DateTime]::FromFileTime([Int64]::Parse($log))
  $os=$srch.properties.item('operatingsystem')
  $osver=$srch.properties.item('operatingsystemversion')
  $sp=$srch.properties.item('operatingsystemservicepack')
  $vals = "`"$args0,$ado,$os,$osver,$sp,$logd,$testres`""
  Add-Content $repo ($vals.split(",") -join "`",`"") | Out-Null
  return
}

$path = "C:\Windows\Temp"
if ($args.count -eq 1) {test $args[0]}
if ($args.count -eq 3) {test $args[0] $args[1] $args[2]}
Set-Variable -name code -scope global
Set-Variable -name hist -scope global
Set-Variable -name local -scope global
Set-Variable -name serv -scope global
Main $args[0] $args[1]
