# --------------------------------------------------------------------
#   Define the variables
# --------------------------------------------------------------------

$ComputerName = "$env:computername"
if($ComputerName.StartsWith("AC") -or $ComputerName.StartsWith("AS")  ) { 
     $InetPubMOVETODrive = "F"
}
else
{
     $InetPubMOVETODrive = "D"

}

$InetPubRoot = "$($InetPubMOVETODrive):\Inetpub"
$InetpubLogs = "$InetPubRoot\logs\logfiles"
$InetPubOldLocation = "C:\inetpub"
$InstallFiles = Split-Path $MyInvocation.MyCommand.Path # Get current script location

$Rule1 = "Remove_SRV_ResponseHeader"

function Write-Log
{
    Param($Text, [switch]$NoTimeStamp)

    if ($Text -eq "" -or $Text -eq $null)
    {
        $Text = "No Output"
    }
    if ($NoTimeStamp -eq $false)
    {
        $Timestamp = "[" + (get-date -Format "yyyy-MM-dd hh:mm:ss") + "] "
        $Text = $Timestamp + $Text
        if (($Text -like "*Error:*") -or ($text -like "*fail*") -or ($text -like "*exception*"))
        {
            ##write-host  -ForegroundColor Red $Text
        }
        else
        {
            ##write-host  -ForegroundColor White $Text 
        }
    }
    else
    {
        $Timestamp = ""
        ##write-host -ForegroundColor DarkGray $Text -Separator "`n`t"
    }
    $LogFileName = "$($InstallFiles)\Install_IIS.log"
    
    
    
    $Text | Out-File $LogFileName -Append -Force
}

# --------------------------------------------------------------------
#   IaaS IIS VM - Initialize Disks before starting
# --------------------------------------------------------------------

try{

  Initialize-Disk -Number 1 -PartitionStyle MBR -PassThru -ErrorAction Stop| New-Partition -DriveLetter $InetPubMOVETODrive -UseMaximumSize -ErrorAction Stop | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false -ErrorAction Stop | Out-Null
  $DiskValidation = $True
  Write-Log "Disk initialization, partition and format successfully completed"
}
catch {
    try {
        Get-Disk -Number 1 -ErrorAction Stop | ? {$_.PartitionStyle -eq "MBR"} | New-Partition -DriveLetter $InetPubMOVETODrive -UseMaximumSize -ErrorAction Stop | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false -ErrorAction Stop | Out-Null
        $DiskValidation = $True
        Write-Log "Disk already initialized, partition and format successfully completed"
    }
    catch{     
        $DiskValidation = $False
        Write-Log "ERROR: $($_.Exception.Message)"
    }
}


if ($DiskValidation)
{

    # --------------------------------------------------------------------
    #   Initialize Log
    # --------------------------------------------------------------------

    if ( -not (Test-Path '$($InetPubMOVETODrive):\Install_IIS\Logs' -PathType Container) ) 
    { 
        new-item -itemtype "directory" -path "$($InetPubMOVETODrive):\Install_IIS" -name "Logs" -Force -ErrorAction SilentlyContinue | Out-Null 
    }



    #Start-Transcript -IncludeInvocationHeader -path $LogFileName

    
    # --------------------------------------------------------------------
    # Loading Feature Installation Modules
    # --------------------------------------------------------------------

    try
    {
        Write-Log "Importing Module ServerManager"
        Import-Module ServerManager  | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }


    # --------------------------------------------------------------------
    # Installing IIS
    # --------------------------------------------------------------------

    try
    {
        Write-Log "Installing IIS"

        #Add-WindowsFeature -Name Web-webserver,Web-mgmt-console,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-HTTP-Tracing,Web-Stat-Compression,Web-Filtering,Web-IP-Security,Web-Windows-Auth,Web-Net-Ext45,Web-AppInit,Web-ASP,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Mgmt-Compat,Web-Metabase,Web-Lgcy-Scripting,Web-WMI,Web-Scripting-Tools,Web-Mgmt-Service,NET-Framework-45-ASPNET | Out-Null
        # removed: Web-Mgmt-Compat Web-Metabase Web-Lgcy-Scripting Web-WMI added Add Web-Dyn-Compression
        Add-WindowsFeature -Name Web-webserver,Web-mgmt-console,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-HTTP-Tracing,Web-Stat-Compression,Web-Filtering,Web-IP-Security,Web-Windows-Auth,Web-Net-Ext45,Web-AppInit,Web-ASP,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Dyn-Compression,Web-Scripting-Tools,Web-Mgmt-Service,NET-Framework-45-ASPNET | Out-Null

    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------
    # Loading IIS Modules
    # --------------------------------------------------------------------

    try
    {
        Write-Log "Importing Module WebAdministration"
        Import-Module WebAdministration | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------
    #            Copying old WWW Root data to new folder
    # --------------------------------------------------------------------

    try
    {
        Write-Log "Moving WWW Root dat to new folder"
        
        xcopy $InetPubOldLocation $InetPubRoot /E /O /I /Y /Q  | Out-Null
        New-Item -Path $InetPubRoot\logs\logfiles -type directory -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path $InetPubRoot\logs\logfiles\FailedReqLogFiles -type directory -Force -ErrorAction SilentlyContinue | Out-Null
        reg.exe add "HKLM\System\CurrentControlSet\Services\WAS\Parameters" /v ConfigIsolationPath /t REG_SZ /d "$InetPubRoot\temp\appPools" /f | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------
    #            Setting IIS Variables
    # --------------------------------------------------------------------

    try
    {
        Write-Log "Adding and Removing HTTP Reponse Headers"

        $HeadersToAdd = @{
            "X-Frame-Options" = "SAMEORIGIN"
            "X-XSS-Protection" = "1;mode=block"
            "X-Content-Type-Options" = "nosniff"
            "Strict-Transport-Security" = "max-age=31536000; includeSubDomains; preload"
        }
        
        $HeadersToAdd.GetEnumerator() | % {
            $HeaderName = $_.Name
            $HeaderValue = $_.Value
            if(!(Get-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@Name=""$($HeaderName)""]")){
                Add-WebConfiguration -Filter "/system.webServer/httpProtocol/customHeaders" -Value @{Name="$($HeaderName)";Value="$($HeaderValue)"}
            }
        }    
        
        $HeadersToRemove = "X-Powered-By"
        $HeadersToRemove | % {
            $HeaderName = $_
            if(Get-WebConfiguration "/system.webServer/httpProtocol/customHeaders/add[@Name=""$($HeaderName)""]"){
                Clear-WebConfiguration -Filter "/system.webServer/httpProtocol/customHeaders/add[@Name=""$($HeaderName)""]"
            }    
        }
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #-------------------------------------------------------------------------
    #        IIS Remove the Server Response Header: "Microsoft-IIS"
    #-------------------------------------------------------------------------

    try
    {
        Write-Log "IIS Remove the Server Response Header Microsoft-IIS.0"
        
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/security/requestFiltering" -name "removeServerHeader" -value "True" | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    # --------------------------------------------------------------------
    #       Remove X-aspNet-Version Globally
    # --------------------------------------------------------------------

    try
    {
        Write-Log "Remove X-aspNet-Version Globally"
        
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/httpRuntime" -name "enableVersionHeader" -value "False" | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }


    #--------------------------------------------------------------------
    #               Changing Log Location
    #--------------------------------------------------------------------

    try
    { 
        Write-Log "Changing Log Location"
        
        Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults"  -name logfile.directory -value "$InetpubLogs" | Out-Null
        Set-WebConfigurationProperty "/system.applicationHost/sites/siteDefaults"  -name traceFailedRequestsLogging.directory -value "$InetpubLogs\logs\logfiles\FailedReqLogFiles" | Out-Null
        Set-WebConfigurationProperty "/system.applicationHost/log" -name centralBinaryLogFile.directory -value "$InetpubLogs" | Out-Null
        Set-WebConfigurationProperty "/system.applicationHost/log"  -name centralW3CLogFile.directory -value "$InetpubLogs" | Out-Null
        Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\WebManagement\Server" -name "LoggingDirectory" -value "$InetpubLogs\wmsvc" | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #--------------------------------------------------------------------
    #         Configure request filtering
    #--------------------------------------------------------------------

    try
    {
        Write-Log "Configure request filtering"

        set-WebConfiguration -Filter  /system.webServer/security/requestFiltering/verbs  -value (@{verb="TRACE";allowed="false"},@{verb="OPTIONS";allowed="false"},@{verb="PUT";allowed="false"},@{verb="DELETE";allowed="false"},@{verb="GET";allowed="true"},@{verb="POST";allowed="true"}) | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #--------------------------------------------------------------------
    #              Configure ApplicationPools Defaults
    #--------------------------------------------------------------------
    try
    {
        Write-Log "Configure Application Pools Defaults"

        Set-WebConfigurationProperty '/system.applicationHost/applicationPools/applicationPoolDefaults/recycling' -Name logEventOnRecycle -value "Time, Requests, Schedule, Memory, IsapiUnhealthy, OnDemand, ConfigChange, PrivateMemory" | Out-Null
        Set-WebConfigurationProperty '/system.applicationHost/applicationPools/applicationPoolDefaults/recycling/periodicRestart' -Name privateMemory -value 1500000 | Out-Null
        Set-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/logFile' -name logExtFileFlags -value "Date, Time, ClientIP, UserName, ComputerName, ServerIP, Method, UriStem, UriQuery, HttpStatus, Win32Status, BytesSent, BytesRecv, TimeTaken, ServerPort, UserAgent, Cookie, Referer, ProtocolVersion, HttpSubStatus" | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }


    # -------------------------------------------------------------------------------------------
    #      Move config history location, temporary files, the path for the Default Web Site
    #      and the custom error locations
    # -------------------------------------------------------------------------------------------

    try{
        Write-Log "Moving history, temporary and path for default web site"

        Set-WebConfigurationProperty '/system.applicationHost/configHistory' -Name path -value "$InetPubRoot\history" | Out-Null
        Set-WebConfigurationProperty -Filter '/system.webServer/asp/cache' -name diskTemplateCacheDirectory -value "$InetPubRoot\temp\ASP Compiled Templates" | Out-Null
    }
    catch{
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #--------------------------------------------------------------------
    #           Move temporary files
    #--------------------------------------------------------------------

    try {
        Write-Log "Moving Temporary Files"

        #write-host "Changing temp files path"
        Set-WebConfigurationProperty '/system.webServer/httpCompression' -Name directory -value "$InetPubRoot\temp\IIS Temporary Compressed Files"  | Out-Null
        Set-ItemProperty -path "HKLM:\System\CurrentControlSet\Services\WAS\Parameters" -name "ConfigIsolationPath" -value "$InetPubRoot\temp\appPools" | Out-Null
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #----------------------------------------------------------------------------------------
    #           Move custom error locations#write-host"Changing custom error location path"
    #----------------------------------------------------------------------------------------

    try {
        Write-Log "Move custom Erro locastions"

        Set-WebConfigurationProperty /system.webServer/httpErrors/* -Name prefixLanguageFilePath -value "$InetPubRoot\custerr" | Out-Null
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #-------------------------------------------------------------------------------------------------
    #         Make sure Service Pack and Hotfix Installers know where the IIS root directories are
    #         The registry keys aren't created if they don't exist.
    #--------------------------------------------------------------------------------------------------

    try {
        Write-Log "Making sure Service Pack and Hostfix Installers know where the IIS root directories are"

        #write-host "Updating paths in registry for hotfix and service pack installers" -ForegroundColor Yellow
        if (Get-ItemProperty -Path "HKLM:\Software\Microsoft\inetstp" -Name "PathWWWRoot" -ErrorAction "SilentlyContinue")
            {
                Set-ItemProperty -path "HKLM:\Software\Microsoft\inetstp" -name "PathWWWRoot" -value $InetPubRoot\wwwroot | Out-Null
            }

            #Do the same for x64 directories (only on x64 systems) 
        if (Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\inetstp" -Name "PathWWWRoot" -ErrorAction "SilentlyContinue")
            {
                Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\inetstp" -name "PathWWWRoot" -value $InetPubRoot\wwwroot | Out-Null
            }
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #-----------------------------------------------------------------------------------------------	
    #               Changing the Default Website location
    #-----------------------------------------------------------------------------------------------

    #Write-Log "Changing the Default Website Location"

    #Set-ItemProperty 'IIS:\Sites\Default Web Site' -name physicalPath -value "$InetPubRoot\wwwroot" | Out-Null

    # --------------------------------------------------------------------
    #               Resetting IIS
    # --------------------------------------------------------------------

    try
    {
        Write-Log "Resetting IIS"

        $Command = "IISRESET"
        Invoke-Expression -Command $Command | Out-Null
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #----------------------------------------------------------------------
    #               Enable Web remote management
    #----------------------------------------------------------------------

    try
    {
        Write-Log "Enabling Web remote Management"

        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1 | Out-Null
        Set-Service -name WMSVC -StartupType Automatic | Out-Null

    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #--------------------------------------------------------------------
    #               Cleanup
    #--------------------------------------------------------------------

    try
    {
        Write-Log "Cleanup"
        Remove-Item $InetPubRoot\logs\FailedReqLogFiles -Recurse -Force
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #--------------------------------------------------------------------
    #          IIS URL-Rewrite Module
    #    Apparent bug in the new IIS feature requires the URL-Rewrite module to still be installed
    #    Case Opened with MS  Prashant Kumar <prashku@microsoft.com>  REG:117020315271177
    #    Headers removed via Set-WebConfigurationProperty  
    #--------------------------------------------------------------------

    try
    {
        Write-Log "Installing IIS URL rewrite module"

        $currentValue = (Get-ItemProperty "hklm:Software\Microsoft\InetStp").MajorVersion

        if ($currentValue -eq 10) {

            #write-host "Found Windows Server 2016, modifying version"
            $registryPath = "HKLM:\Software\Microsoft\InetStp"
            $Name = "MajorVersion"
            $newvalue = "7"
            New-ItemProperty -Path $registryPath -Name $name -Value $newvalue -PropertyType DWORD -Force | Out-Null 
            #write-host "IIS re-write Module INSTALL" -ForegroundColor Yellow
            (Start-Process "$InstallFiles\rewrite_amd64.msi" -ArgumentList "/passive" -Wait -Passthru).ExitCode | Out-Null
            #write-host "Reverting version value"
            New-ItemProperty -Path $registryPath -Name $name -Value $currentValue -PropertyType DWORD -Force | Out-Null

        } else {

            #write-host "Windows Server 2016 not found, continuing"
            #write-host "IIS re-write Module INSTALL" -ForegroundColor Yellow
            (Start-Process "$InstallFiles\rewrite_amd64.msi" -ArgumentList "/passive" -Wait -Passthru).ExitCode | Out-Null

        }

        #write-host "Rewrite Rules Getting Applied- Hit any key to continue" -ForegroundColor Yellow
        #Pause
    }
    catch
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }


    #--------------------------------------------------------------------
    #         Add Server Global Setting to URLRewrite
    #--------------------------------------------------------------------

    try 
    {
        Write-Log "Add Server Global Setting to URLRewrite"

        Import-Module WebAdministration 

        Add-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/rewrite/outboundrules" -name "." -value @{name=$Rule1} | Out-Null
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.webServer/rewrite/outboundRules/rule[@name='$Rule1']/match" -name "serverVariable" -value "RESPONSE_SERVER" | Out-Null
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.webServer/rewrite/outboundRules/rule[@name='$Rule1']/match" -name "pattern" -value ".*" | Out-Null
        Set-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST"  -filter "system.webServer/rewrite/outboundRules/rule[@name='$Rule1']/action" -name "type" -value "Rewrite" | Out-Null
    }
    catch 
    {
        Write-Log "ERROR: $($_.Exception.Message)"
    }

    #--------------------------------------------------------------------
    #   Remove all pre-existing sites and default app pool
    #--------------------------------------------------------------------

    try 
    {
        Get-WebSite -ErrorAction Stop | % {Remove-WebSite $_.Name -Confirm:$false -ErrorAction Stop}
        Get-ChildItem IIS:\AppPools -ErrorAction Stop | % {Remove-WebAppPool -Name $_.Name -ErrorAction Stop}
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)"
    }


    #--------------------------------------------------------------------
    #     truncate and cycle logs. Diego Sesoldi
    #--------------------------------------------------------------------

    Write-Log "Truncate and Cycle Validation"

    try {
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "period" -value MaxSize -ErrorAction SilentlyContinue
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "truncateSize" -value 500000000 -ErrorAction SilentlyContinue
        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/log/centralW3CLogFile" -name "logExtFileFlags" -value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)" -appendFile $appendFile | out-null
    }

} #end if diskvalidation

#--------------------------------------------------------------------
#     Initiation QA Validations - This is IaC Automation Section
#--------------------------------------------------------------------

Write-Log "Initiating QA Validation Process"

try
{
    #write-host "Initiating QA Process`n`n`n"
    [String[]]$CheckName = @()
    [Int[]]$CheckResult = @()
}
catch
{
    #write-host "Error: $($_.Exception.Message)"
}

#--------------------------------------------------------------------
#     Validations
#--------------------------------------------------------------------

Write-Log "Starting Validation"

try
{
   $CheckName += "DiskValidation"
   $CheckResult += $DiskValidation
}
catch
{
    $CheckResult += $False
}

try
{
   $CheckName += "WebServerRole"
   $CheckResult += (Get-WindowsFeature Web-Server).Installed
}
catch
{
    $CheckResult += $False
} 

try
{
   $WindowsFeatures = Get-WindowsFeature -Name Web-webserver,Web-mgmt-console,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Http-Logging,Web-Log-Libraries,Web-Request-Monitor,Web-HTTP-Tracing,Web-Stat-Compression,Web-Filtering,Web-IP-Security,Web-Windows-Auth,Web-Net-Ext45,Web-AppInit,Web-ASP,Web-Asp-Net45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Dyn-Compression,Web-Scripting-Tools,Web-Mgmt-Service,NET-Framework-45-ASPNET
   $CheckName += "WindowsFeatures"
   $CheckResult += (($WindowsFeatures | select -ExpandProperty Installed) -notcontains $False)
}
catch
{
    $CheckResult += $False
} 

try
{
   $CheckName += "LogFolderValidation"
   $CheckResult += (Test-Path -Path "$($InetPubMOVETODrive):\Inetpub\Logs\Logfiles")
}
catch
{
    $CheckResult += $False
}

try
{
   $CheckName += "PathWWWRootValidation"
   $CheckResult += ((Get-ItemProperty -Path "HKLM:\Software\Microsoft\inetstp" -Name "PathWWWRoot" | select -ExpandProperty PathWWWRoot) -eq "$InetPubRoot\wwwroot")
}
catch
{
    $CheckResult += $False
} 

try
{
   $CheckName += "ReWriteModule"
   $CheckResult += (Test-Path "$env:programfiles\Reference Assemblies\Microsoft\IIS\Microsoft.Web.Iis.Rewrite.dll")
}
catch
{
    $CheckResult += $False
} 

try
{
    
    $CheckName += "SEPStatus"
    $Value = (Get-ItemProperty -path Registry::'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Symantec\Symantec Endpoint Protection\SMC\SYLINK\SyLink').CommunicationStatus
    $CheckResult += (($Value.Split(":")[6] -eq "0") -or ($Value.Split(";")[6] -eq "0") -or ($Value.Split(":")[6] -eq "119") -or ($Value.Split(";")[6] -eq "119"))

}
catch {
    
    $CheckResult += $False
}

try
{
    $CheckName += "TruncateLogs"
    $t1=get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "period" 
    $t2= (get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/siteDefaults/logFile" -name "truncateSize").value
    $t3=get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/log/centralW3CLogFile" -name "logExtFileFlags" 
    $CheckResult += (($t1 -eq "MaxSize") -and ($t2 -eq "500000000") -and ($t3))
}
catch
{
    $CheckResult += $False
}


#--------------------------------------------------------------------
#     QA Validations Result
#--------------------------------------------------------------------

try
{
   $File = New-Object -TypeName psobject
   $QAPath = "$InstallFiles\QA.json"
   #write-host "Writing QA Results:"
   for($i = 0; $i -lt $CheckName.Length; $i++)
   {           
        $Line = $CheckName[$i] + ": " + $CheckResult[$i]
        #write-host $Line
        $File | Add-Member -MemberType NoteProperty -Name $CheckName[$i] -Value $CheckResult[$i]    
   }
   $File | ConvertTo-Json > $QAPath

   $QAFileContent = get-content $QAPath
   Write-Output $QAFileContent
   #remove-item $QAPath -Force

   #write-host "QA Completed`n`n`n"
}
catch
{

    #write-host "Error: $($_.Exception.Message)"
}

#--------------------------------------------------------------------
#     Finishing IaC Automation Section
#--------------------------------------------------------------------

start-sleep 5 | Out-Null

#--------------------------------------------------------------------
#       Reboot Server
#--------------------------------------------------------------------

Write-Log "Server will now be rebooted.  Press Enter to Continue. Log back in after reboot to complete the install"
#write-host "Server will now be rebooted.  Press Enter to Continue. Log back in after reboot to complete the install" 
#pause

 
#restart-computer $ComputerName -Force | Out-Null
#shutdown -r -f -t: 1200
