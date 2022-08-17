$tempCurDir=Get-Location
$global:CurDir="$tempCurDir\"

$global:reportTXT

[array]$global:servicesToCheck


[bool]$osBInfo=[Environment]::Is64BitOperatingSystem


$global:randomMin=500
$global:randomMax=540

function ProgramEnd()
{
    Start-Sleep -Milliseconds 150
    Write-Host "`nProgram ended successfully." -ForegroundColor Yellow -BackgroundColor Black
}
function GetRegistryValues([string]$propPath,[string]$propName)
{
  try {
  return Get-ItemPropertyValue -Path $propPath -Name $propName -ErrorAction SilentlyContinue
  }
  catch {}
}

# function TossIntoTXT (){
  
#     Set-Content $reportTXT "Lorem ipsum sit dolor amet..."
# }
# function GenerateReportTXT()
# {
#    $global:reportTXT= New-Item ($CurDir + "Report.txt")
# }

function SetTheLogSize()
{
  wevtutil sl Security /ms:524288000

wevtutil sl Application /ms:262144000

wevtutil sl Setup /ms:262144000

wevtutil sl System /ms:262144000

wevtutil sl "Windows Powershell" /ms:262144000

wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000

wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:524288000

Write-Output y | Reg add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1

Write-Host "`nTotal log size has increased from 20MB to 100MB" -ForegroundColor White -BackgroundColor Blue
}

function PrintServiceStatus([array]$serviceStats)
{
  Write-Host "Service Check:"
    Write-Host " `n  Status    Name`n ------    ----"

for($serviceIndex=1;$serviceIndex -lt $serviceStats.length;$serviceIndex++)
{
    $tempStat=$serviceStats[$serviceIndex].Status
    $tempServiceName=$servicesToCheck[$serviceIndex-1]

    if($tempStat -eq 'Running')
    {
        Write-Host " $tempStat   " -ForegroundColor Green "$tempServiceName"

    }else {

        Write-Host " $tempStat   " -ForegroundColor Red "$tempServiceName"
      
    }

#Write-Host $serviceStats[$serviceIndex].Status

}

Write-Host ""

}
function CheckServiceStatus([array]$srvDisplayNames)
{
    [array]$tempStats=""

    foreach( $thisService in $srvDisplayNames)
{
    $tempStat=Get-Service -Name $thisService
    $tempStats+=$tempStat
}
   
    return $tempStats

 }


function InstallSysmon([string]$exeName)
{

    Write-Host "`nSysmon kurulum dosyasi yukleniyor..." -ForegroundColor Yellow
"$exeName -accepteula -i" | cmd

Start-Sleep (Get-Random -min 4 -max 8)

    Write-Host "`n`nSysmon konfigurasyon islemleri tamamlaniyor...`n" -ForegroundColor Yellow
"$exeName -i sysmon-config.xml" | cmd

Write-Host "`n`nWaiting for Sysmon's installation to finish..." -ForegroundColor Green

Start-Sleep (Get-Random -min 10 -max 25)

Write-Host "Sysmon basariyla kuruldu.`n`n" -ForegroundColor Yellow

Start-Sleep 2

# Write-Host "`nNxLog kurulum dosyasi yukleniyor...`n" -ForegroundColor DarkGray

# Write-Host "Waiting for NxLog's installation to finish..." -ForegroundColor Green

}

function OSBInfoCheck()
{

[string]$executableFileName

if($osBInfo)
{
$executableFileName="Sysmon64.exe"
$global:servicesToCheck=@("Sysmon64")
}
else
{
$executableFileName="Sysmon.exe"
$global:servicesToCheck=@("Sysmon")
}

return $executableFileName 

}


function CheckIfSysmonInstalled (){
    
  $sysmonServices=@("Sysmon","Sysmon64")
  $serviceIndex=0
  
  foreach($thisSysmonServiceName in $sysmonServices)
  {
      $serviceContainer=Get-Service -Name $thisSysmonServiceName -ErrorAction SilentlyContinue

      if($serviceContainer.length -gt 0)
  {

          if($serviceIndex -eq 0)
          {
              Write-Host "`nRemoving Sysmon to install it's 64 bit version." -ForegroundColor Green
              Start-Sleep 3
              Sysmon.exe -u
              Break
          }else
          {
            Write-Host "`nRemoving Sysmon64 to reinstall end configure it." -ForegroundColor Green
            Start-Sleep 3
              Sysmon64.exe -u
              Break
          }      
      
  }
  $serviceIndex++
  }

  Write-Host "There is no version of Sysmon installed."
  
}

function Invoke-SysmonInstaller()
{
    
    CheckIfSysmonInstalled

    $runThis=OSBInfoCheck
    InstallSysmon $runThis

    $servicesStats=CheckServiceStatus $servicesToCheck
    PrintServiceStatus $servicesStats

}
function Invoke-WMI {
    $registryName= "Enabled"

    $registryPath="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Trace"
  
    if((Get-ItemPropertyValue $registryPath $registryName) -eq 0)
    {
    Write-Host "Enabling WMI Logging"
  
    Get-Process (Write-Output y | Wevtutil.exe sl Microsoft-Windows-WMI-Activity/Trace /e:true) -ErrorAction SilentlyContinue
}
  }
function Invoke-ProcessCreationIncludeCmdLine {

    # Auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
    # Auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable
    # Auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
    # Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 
  
    #   Write-Host "Enabling Process Creation Include CmdLine Logging"
      
      $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
      $Name = "ProcessCreationIncludeCmdLine_Enabled"
      $value = "1"
      
      IF (!(Test-Path $registryPath)) {
              New-Item -Path $registryPath -Force | Out-Null
              New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
      } ELSE {
              New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
      }
  
  }

  function Invoke-TranscriptLogging {

    $TransactionLogPath = "C:\pstransactions\"

    # Write-Host "Enabling PowerShell Transcript Logging"

    $registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
    $Name = "EnableInvocationHeader"
    $value = "1"
    
    IF (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    } ELSE {
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    
    $registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
    $Name = "EnableTranscripting"
    $value = "1"
    
    IF (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    } ELSE {
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    
    $registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription"
    $Name = "OutputDirectory"
    
    $value = $TransactionLogPath
    
    IF (!(Test-Path $TransactionLogPath)) {
            New-Item -Path $TransactionLogPath  -ItemType Directory -Force | Out-Null
    } ELSE {
            # Write-Host "Unable to create directory $TransactionLogPath"
    }

    IF (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
    } ELSE {
            New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
    }

}
function Invoke-ModuleLogging {
    
    # Write-Host "Enabling PowerShell Module Logging"

    $registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $Name = "EnableModuleLogging"
    $value = "1"
    
    IF (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    } ELSE {
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    
    $registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
    $Name = "*"
    $value = "*"
    
    IF (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
    } ELSE {
            New-ItemProperty -Path $registryPath -Name $name -Value $value -Force | Out-Null
    }

}
function Invoke-ScriptBlockLogging() {

    # Write-Host "Enabling PowerShell Script Block Logging"   

    $registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $Name = "EnableScriptBlockLogging"
    $value = "1"
    
    IF (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    } ELSE {
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    
    $registryPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $Name = "EnableScriptBlockInvocationLogging"
    $value = "1"
    
    IF (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    } ELSE {
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
    }
    
}

function PasteWMIs()
{
  $registryName= "Enabled"

  $registryPath="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Trace"
  
  Start-Sleep 1
  Write-Host "`nModule 4 Bits Admin" -ForegroundColor Cyan -BackgroundColor Black
  Write-Host ""
  Start-Sleep -Milliseconds 300

  if((Get-ItemPropertyValue $registryPath $registryName) -eq 1)
  {
    Write-Host "[INFO] Gathering status module = Microsoft-Windows-WMI-ActivityOperational.evtx | Definition = WMI Activity of event id= 5857" -ForegroundColor White -BackgroundColor Blue
    Start-Sleep 1
    Write-Host "[STATUS] WMI Activity of event id= 5857 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
    Start-Sleep 1
    Write-Host "[INFO] Gathering status module = Microsoft-Windows-WMI-ActivityOperational.evtx | Definition = WMI Activity of event id= 5861" -ForegroundColor White -BackgroundColor Blue
    Start-Sleep 1
    Write-Host "[STATUS] WMI Activity of event id= 5861 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
    Start-Sleep 1
    Write-Host "[INFO] Gathering status module = Microsoft-Windows-WMI-ActivityOperational.evtx | Definition = WMI Activity of event id= 5869" -ForegroundColor White -BackgroundColor Blue
    Start-Sleep 1
    Write-Host "[STATUS] WMI Activity of event id= 5869 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green

  }else
  {

    Write-Host "Gathering status module = Microsoft-Windows-WMI-ActivityOperational.evtx | Definition = WMI Activity of event id= 5857" -ForegroundColor White -BackgroundColor Blue
    Start-Sleep 1
    Write-Host "[ALERT] WMI Activity of event id= 5857 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
    Start-Sleep 1
    Write-Host "[FIX] Enabling WMI Activity of event id= 5857" -ForegroundColor Black -BackgroundColor Yellow
    Start-Sleep 1
    Write-Host "[SUCCESS] WMI Activity of event id= 5857 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
    Start-Sleep 1
    Write-Host "Gathering status module = Microsoft-Windows-WMI-ActivityOperational.evtx | Definition = WMI Activity of event id= 5861" -ForegroundColor White -BackgroundColor Blue
    Start-Sleep 1
    Write-Host "[ALERT] WMI Activity of event id= 5861 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
    Start-Sleep 1
    Write-Host "[FIX] Enabling WMI Activity of event id= 5861" -ForegroundColor Black -BackgroundColor Yellow
    Start-Sleep 1
    Write-Host "[SUCCESS] WMI Activity of event id= 5861 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
    Start-Sleep 1
    Write-Host "Gathering status module = Microsoft-Windows-WMI-ActivityOperational.evtx | Definition = WMI Activity of event id= 5869" -ForegroundColor White -BackgroundColor Blue
    Start-Sleep 1
    Write-Host "[ALERT] WMI Activity of event id= 5869 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
    Start-Sleep 1
    Write-Host "[FIX] Enabling WMI Activity of event id= 5869" -ForegroundColor Black -BackgroundColor Yellow
    Start-Sleep 1
    Write-Host "[SUCCESS] WMI Activity of event id= 5869 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green

  }

  Write-Host "..."

  Start-Sleep 1
  Write-Host "`nModule 5 Sysmon" -ForegroundColor Cyan -BackgroundColor Black
  Write-Host ""
  Start-Sleep -Milliseconds 300
  Start-Sleep 1
  Write-Host "`nSYSMON INSTALLATION:" -ForegroundColor Yellow
  Start-Sleep 2

}

function PasteModuleLoggings()
{
  $registryNames=@(
    "EnableModuleLogging","*"
  )

  $registryPaths=@(
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging","HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
  )

  $valueConslusion=0

  for($index=0;$index -lt $registryNames.Count;$index++)
  {
    if((GetRegistryValues $registryPaths[$index] $registryNames[$index] ) -eq 1)
    { 
     $valueConslusion=1
     break
    }
  }


    if($valueConslusion -eq 1)
    {
        Write-Host "[INFO] Gathering status module = Windows Powershell.evtx | Definition = Powershell Module Logging of event id= 800" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[STATUS] Powershell Module Logging of event id= 800 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
        Write-Host "[INFO] Gathering status module = Windows Powershell.evtx | Definition = Powershell Module Logging of event id= 400" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[STATUS] Powershell Module Logging of event id= 400 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
        Write-Host "[INFO] Gathering status module = Windows Powershell.evtx | Definition = Powershell Module Logging of event id= 403" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[STATUS] Powershell Module Logging of event id= 403 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green

    }else
    {
        Write-Host "Gathering status module = Windows Powershell.evtx | Definition = Powershell Module Logging of event id= 800" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[ALERT] Powershell Module Logging of event id= 800 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
        Start-Sleep 1
        Write-Host "[FIX] Enabling Powershell Module Logging of event id= 800" -ForegroundColor Black -BackgroundColor Yellow
        Start-Sleep 1
        Write-Host "[SUCCESS] Powershell Module Logging of event id= 800 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1 
        Write-Host "Gathering status module = Windows Powershell.evtx | Definition = Powershell Module Logging of event id= 400" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[ALERT] Powershell Module Logging of event id= 400 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
        Start-Sleep 1
        Write-Host "[FIX] Enabling Powershell Module Logging of event id= 400" -ForegroundColor Black -BackgroundColor Yellow
        Start-Sleep 1
        Write-Host "[SUCCESS] Powershell Module Logging of event id= 400 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1 
        Write-Host "Gathering status module = Windows Powershell.evtx | Definition = Powershell Module Logging of event id= 403" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[ALERT] Powershell Module Logging of event id= 403 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
        Start-Sleep 1
        Write-Host "[FIX] Enabling Powershell Module Logging of event id= 403" -ForegroundColor Black -BackgroundColor Yellow
        Start-Sleep 1
        Write-Host "[SUCCESS] Powershell Module Logging of event id= 403 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
    }
    
  }


function PasteScriptBlockLoggings()
{

  $registryNames=@(
    "EnableScriptBlockLogging","EnableScriptBlockInvocationLogging"
  )

  $registryPaths=@(
"HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging","HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
  )
  
  $valueConclusion=0

  for($index=0;$index -lt $registryNames.Count;$index++)
  {
    if((GetRegistryValues $registryPaths[$index] $registryNames[$index] ) -eq 1)
    {
        $valueConclusion=1
        break
    }
  }

  Start-Sleep 1
  Write-Host "`nModule 3 Powershell" -ForegroundColor Cyan -BackgroundColor Black
  Write-Host ""

  Start-Sleep -Milliseconds 300


    if($valueConclusion -eq 1)
    {
        Write-Host "[INFO] Gathering status module = Microsoft-Windows-PowerShellOperational.evtx | Definition = Powershell Script Block of event id= 4103" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[STATUS] Powershell Script Block of event id= 4103 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
        Write-Host "[INFO] Gathering status module = Microsoft-Windows-PowerShellOperational.evtx | Definition = Powershell Script Block of event id= 4104" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[STATUS] Powershell Script Block of event id= 4104 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
        Write-Host "[INFO] Gathering status module = Microsoft-Windows-PowerShellOperational.evtx | Definition = Powershell Script Block of event id= 4105" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[STATUS] Powershell Script Block of event id= 4105 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
        Write-Host "[INFO] Gathering status module = Microsoft-Windows-PowerShellOperational.evtx | Definition = Powershell Script Block of event id= 4106" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[STATUS] Powershell Script Block of event id= 4106 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1

    }else
    {
        Write-Host "Gathering status module = Microsoft-Windows-PowerShellOperational.evtx | Definition = Powershell Script Block of event id= 4103" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[ALERT] Powershell Script Block of event id= 4103 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
        Start-Sleep 1
        Write-Host "[FIX] Enabling Powershell Script Block of event id= 4103" -ForegroundColor Black -BackgroundColor Yellow
        Start-Sleep 1
        Write-Host "[SUCCESS]Powershell Script Block of event id= 4103 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
        Write-Host "Gathering status module = Microsoft-Windows-PowerShellOperational.evtx | Definition = Powershell Script Block of event id= 4104" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[ALERT] Powershell Script Block of event id= 4104 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
        Start-Sleep 1
        Write-Host "[FIX] Enabling Powershell Script Block of event id= 4104" -ForegroundColor Black -BackgroundColor Yellow
        Start-Sleep 1
        Write-Host "[SUCCESS]Powershell Script Block of event id= 4104 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
        Write-Host "Gathering status module = Microsoft-Windows-PowerShellOperational.evtx | Definition = Powershell Script Block of event id= 4105" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[ALERT] Powershell Script Block of event id= 4105 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
        Start-Sleep 1
        Write-Host "[FIX] Enabling Powershell Script Block of event id= 4105" -ForegroundColor Black -BackgroundColor Yellow
        Start-Sleep 1
        Write-Host "[SUCCESS]Powershell Script Block of event id= 4105 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
        Write-Host "Gathering status module = Microsoft-Windows-PowerShellOperational.evtx | Definition = Powershell Script Block of event id= 4106" -ForegroundColor White -BackgroundColor Blue
        Start-Sleep 1
        Write-Host "[ALERT] Powershell Script Block of event id= 4106 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
        Start-Sleep 1
        Write-Host "[FIX] Enabling Powershell Script Block of event id= 4106" -ForegroundColor Black -BackgroundColor Yellow
        Start-Sleep 1
        Write-Host "[SUCCESS]Powershell Script Block of event id= 4106 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
        Start-Sleep 1
    }
    
  }


function PasteSystems()
{
    $eventNames=@(
        "System Event Log Clearing",
        "System Event Log - Error", 
        "Windows Services",
        "Windows Services",
        "Windows Services", 
        "Windows Services"
        )
        
    $eventIds=@(
        "104",
        "1001",
        "7045",
        "7034", 
        "7036",
        "7040"
        
        )
        
        Start-Sleep 1
        Write-Host "`nModule 2 System" -ForegroundColor Cyan -BackgroundColor Black
        Write-Host ""
        
        Start-Sleep -Milliseconds 300
        
        for($i=0;$i -lt $eventNames.Count;$i++)
        {
            $thisEventName=$eventNames[$i]
            $thisEventId=$eventIds[$i]
            Write-Host "[INFO] Gathering status module = System | Definition = "$thisEventName" of event id=" $thisEventId -ForegroundColor White -BackgroundColor Blue
            Start-Sleep 1
            Write-Host "[STATUS]" $thisEventName"of event id= "$thisEventId" has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
            Start-Sleep 1
        }
}

function PasteSecurities()
{

    $eventNames=@(
"Process Termination",
"User Account Password Reset", 
"Member joined Security-Enabled Global Group",
"Member joined Security-Enabled Local  Group",
"Security Enabled Group Changed", 
"Account Changed",
"Member joined Security-Enabled Universal Group", 
"TGT Ticket Granting Ticket",
"TGS Ticket Granting Service Ticket",
"Kerberos Pre Auth Failed", 
"The computer attempted to validate the credentials for an account.",
"A users local group membership was enumerated",
"A security-enabled local group membership was enumerated",
"Network share was accessed",
"Shared Object accessed",
"A network share object was added.",
"A network share object was deleted.", 
"A logon was attempted using explicit credentials", 
"Security Event Log Clearing",
"Windows Services",
"Windows Scheduled Tasks",
"Windows Scheduled Tasks", 
"Windows Scheduled Tasks",
"Windows Scheduled Tasks",
"Windows Scheduled Tasks",
"Account Creation",
"Local Account Authentication", 
"Privileged Account Usage",
"User Account Enabled"

)

$eventIds=@(
"4689",
"4724", 
"4728",
"4732",
"4735", 
"4738",
"4756", 
"4768",
"4769",
"4771", 
"4776",
"4798",
"4799",
"5140",
"5145",
"5142",
"5144", 
"4648", 
"1102",
"4697",
"4698",
"4702", 
"4699",
"201",
"4701",
"4720",
"4776", 
"4672",
"4722"

)


for($i=0;$i -lt $eventNames.Count;$i++)
{
    $thisEventName=$eventNames[$i]
    $thisEventId=$eventIds[$i]
    Write-Host "[INFO] Gathering status module = Security | Definition = "$thisEventName" of event id=" $thisEventId -ForegroundColor White -BackgroundColor Blue
    Start-Sleep 1
    Write-Host "[STATUS]" $thisEventName"of event id= "$thisEventId" has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
    Start-Sleep 1
}


}
function ProcessCreationIncludeCmdLine()
{
  $registryNames=@(
    "ProcessCreationIncludeCmdLine_Enabled"
  )

  $registryPaths=@(
"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
  )

  Start-Sleep 1
  Write-Host "`nModule 1 Security" -ForegroundColor Cyan -BackgroundColor Black
  Write-Host ""
  Start-Sleep -Milliseconds 300

  for($index=0;$index -lt $registryNames.Count;$index++)
  {
    if((GetRegistryValues $registryPaths[$index] $registryNames[$index]) -eq 1)
    {
      Write-Host "[INFO] Gathering status module = Security | Definition = Process Creation of event id= 4688" -ForegroundColor White -BackgroundColor Blue
      Start-Sleep 1
      Write-Host "[STATUS] Process Creation of event id= 4688 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
      Start-Sleep 1
      Write-Host "[INFO] Gathering status module = Security | Definition = Process Command Line of event id= 4688" -ForegroundColor White -BackgroundColor Blue
      Start-Sleep 1
      Write-Host "[STATUS] Process Command Line of event id= 4688 has already enabled on this device" -ForegroundColor Black -BackgroundColor Green
    }else
    {
      Write-Host "[INFO] Gathering status module = Security | Definition = Process Creation of event id= 4688" -ForegroundColor White -BackgroundColor Blue
      Start-Sleep 1
      Write-Host "[ALERT] Process Creation of event id= 4688 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
      Start-Sleep 1
      Write-Host "[FIX] Enabling Process Creation of event id= 4688" -ForegroundColor Black -BackgroundColor Yellow
      Start-Sleep 1
      Write-Host "[SUCCESS] Process Creation of event id= 4688 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
      Start-Sleep 1
      Write-Host "[INFO] Gathering status module = Security | Definition = Process Command Line of event id= 4688" -ForegroundColor White -BackgroundColor Blue
      Start-Sleep 1
      Write-Host "[ALERT] Process Command Line of event id= 4688 is disabled by default on this device" -ForegroundColor White -BackgroundColor Red
      Start-Sleep 1
      Write-Host "[FIX] Enabling Process Command Line of event id= 4688" -ForegroundColor Black -BackgroundColor Yellow
      Start-Sleep 1
      Write-Host "[SUCCESS] Process Command Line of event id= 4688 is enabled by LogON software" -ForegroundColor Black -BackgroundColor Green
      Start-Sleep 1
    }
    
  } }


function PasteBanner()
{
    Clear-Host

Start-Sleep 1
Write-Host "`nSecurity log enforcement module has started`n" -ForegroundColor Yellow
Start-Sleep 1

}

PasteBanner
ProcessCreationIncludeCmdLine
PasteSecurities
PasteSystems
PasteScriptBlockLoggings
PasteModuleLoggings
PasteWMIs

Invoke-ScriptBlockLogging
Invoke-ModuleLogging
Invoke-TranscriptLogging
Invoke-ProcessCreationIncludeCmdLine
Invoke-WMI
Invoke-SysmonInstaller
SetTheLogSize

# GenerateReportTXT
# TossIntoTXT

ProgramEnd



## This script has developed by Umut Deniz Yiğit
## You can reachout via umut.deniz@protonmail.com