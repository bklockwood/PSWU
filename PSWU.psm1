#requires -version 2.0
#Set-StrictMode -Version 2.0

function Install-AllUpdates {
<#
.SYNOPSIS
Installs all available, non-hidden updates updates (including optional ones),
rebooting as necessary. You SHOULD NOT be running this function/cmdlet manually.
Run the Install-AllUpdates.ps1 script instead.
.PARAMETER ScriptName
The script name. You SHOULD NOT be providing this parameter manually.
Run Install-AllUpdates.ps1 which handles this for you.
.PARAMETER ScriptPath
The script path. You SHOULD NOT be providing this parameter manually.
Run Install-AllUpdates.ps1 which handles this for you.
.PARAMETER ScriptFullName
The script full path. You SHOULD NOT be providing this parameter manually.
Run Install-AllUpdates.ps1 which handles this for you.
.EXAMPLE
Install-AllUpdates 
.NOTES 
flowchart: http://i.imgur.com/NSV8AH2.png
#>

    
    [CmdletBinding()]
    Param(
         [Parameter(Mandatory=$true,Position=0,
        HelpMessage="Kill this with ctrl-c and run Install-AllUpdates.ps1")]
        [string]$DontRunThisCmdletManually,
        [Parameter(Mandatory=$true,Position=1,
        HelpMessage="Kill this with ctrl-c and run Install-AllUpdates.ps1")]
        [string]$ScriptName,
        [Parameter(Mandatory=$true,Position=2,
        HelpMessage="Kill this with ctrl-c and run Install-AllUpdates.ps1")]
        [string]$ScriptPath,
        [Parameter(Mandatory=$true,Position=3,HelpMessage="Kill this with ctrl-c and run Install-AllUpdates.ps1")]
        [string]$ScriptFullName
    )

    Begin{
        If ($DontRunThisCmdletManually -NE "PermissionGranted") {
            Write-Host -ForegroundColor Red "You SHOULD NOT be running this function/cmdlet manually.
            Run the Install-AllUpdates.ps1 script instead."
            break}
    }
    Process 
    {
        $Logfile = "$env:PUBLIC\Desktop\PSWU.log"
        Write-Log $Logfile " -=-=-=-=-=-=-=-=-=-=-=-"
        Write-Log $Logfile "PSWU system patcher is starting (as $env:username)."

        Write-Log $Logfile "Starting PSWU function 'Install-AllUpdates'"
        if (!(Test-AdminPrivs)) {
            Write-Warning "You must elevate to Admin privs to download or install updates"
            Write-Log $Logfile "You must elevate to Admin privs to download or install updates"
            break 
        }

        if (Test-RebootNeeded) {
            Write-Log $Logfile "Restart needed (for pending Windows Updates)."
            if (!(CheckForScheduledTask "PSWU")) {ScheduleRerunTask "PSWU" $ScriptFullPath}
            Write-Log $Logfile "Restarting in 15 seconds!"
            Start-Sleep -Seconds 15
            Restart-Computer -Force 
            break #Without this, script will continue processing during the shutdown.
        } else {
            Write-Log $Logfile "No reboot needed."
        }

        Write-Log $Logfile "Checking for updates."
        $ISearchResult = Get-UpdateList

        if ($ISearchResult.ResultCode -eq 2) {
            Write-Log $Logfile "Successfully retreived update list"
            $ISearchResult | Hide-Update -KBID 2483139 #hide Language Packs
            $NonHiddenUpdateCount = ($ISearchResult.Updates | Where-Object {$_.IsHidden -eq $false}).Count
            #if ($ISearchResult.Updates.Count -gt 0) {
            if ($NonHiddenUpdateCount -gt 0) {
                Write-Log $Logfile "Non-hidden updates: $NonHiddenUpdateCount"
                [string]$UpdateReport = Show-UpdateList -ISearchResult $ISearchResult
                Write-Log $Logfile $UpdateReport  
                Write-Log $Logfile "Downloading and installing $NonHiddenUpdateCount updates."
                $Install = Install-Update -ISearchResult $ISearchResult -Verbose
                Write-Log $Logfile "Done installing updates. Restarting script to check for more."
                Install-AllUpdates -DontRunThisCmdletManually "PermissionGranted" `
                    -ScriptName $ScriptName `
                    -Scriptpath $ScriptPath `
                    -ScriptFullName $ScriptFullPath `
                    -Verbose
            } else {
                Write-Log $Logfile "Windows is up to date; script cleaning up."
                #check for PSWU Scheduled Task and delete if found
                #use schtasks for win7 compat
                if (CheckForScheduledTask "PSWU") {
                    Write-Log $Logfile "Found PSWU task; removing. "
                    schtasks /delete /tn pswu /F
                    }   
                Write-Log $Logfile "Cleanup complete. Running as $env:username - script exiting."
                Rename-Item -Path $Logfile -NewName "PSWU DONE.log" -Force
                break
            }
        }
    }
    End{}
}

Function Write-Log {
<#
.SYNOPSIS
Logs short statements, with timestamps, to file defined by $Logfile
.PARAMETER Logfile
The full path to the logfile.
.PARAMETER Logstring
The text string to log.
.EXAMPLE
Write-Log c:\logs\logfile.txt "This is a log entry"
#>
   Param 
   (
   [Parameter(Mandatory=$true,Position=0)][string]$Logfile,
   [Parameter(Mandatory=$true,Position=1)][string]$LogString   
   )

   #dotNET datestamp formats http://goo.gl/YkkEXa and http://goo.gl/B5JhW
   $Logtext = "$(get-date -Format yyyyMMdd-HH:mm:ss) $LogString"
   Out-file -FilePath $Logfile -Append -NoClobber -InputObject $Logtext -Encoding ascii
   #Write-Host intentional here! $Logtext must *not* go into pipeline.
   Write-Host $Logtext
}

Function Format-Error {
<#
.SYNOPSIS
Shortened version of Will Steele's technique 
as found in Powershell Deep Dives, chapter 11
http://goo.gl/JQQz0R for his original code.
.NOTES
There are no examples for this function; it is not meant to 
be called by humans. 
#>
    #Param ([Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)] $MyError)

    $timestamp = Get-Date -Format 'yyyyMMdd HH:mm:ss'

@"
----ERROR in $($_.InvocationInfo.ScriptName).----
$timestamp  Error Details: $($_)
$timestamp  Line: $($_.InvocationInfo.Line)
$timestamp  Line Number: $($_.InvocationInfo.ScriptLineNumber) Offset: $($_.InvocationInfo.OffsetInLine)
$timestamp  Command: $($_.InvocationInfo.MyCommand)
"@
}

function Test-AdminPrivs () {
<#
.SYNOPSIS
Test whether currently running with Administrator privs.
.DESCRIPTION
Returns TRUE if the calling account has admin privs; FALSE if not.
.NOTES
I used the technique found here: http://goo.gl/TwmIIf ... modified for readability.
TODO: But what about non-english systems? http://goo.gl/nRIoON and http://goo.gl/O1qh37
.EXAMPLE
Test-AdminPrivs
True
#>

    [bool]$retval = $false
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent() 
    $principal = new-object System.Security.Principal.WindowsPrincipal($identity) 
    $admin = [System.Security.Principal.WindowsBuiltInRole]::Administrator 
    $HasRights = $principal.IsInRole($admin)    
    if ($HasRights) {$retval = $true} 
    return $retval
}

function Test-RebootNeeded {
<#
.SYNOPSIS
Checks whether reboot is needed due to Windows Updates. Returns $true or $false
.PARAMETER Computername
The target computer. Defaults to the local PC.
.NOTES
Thanks to Brian Wilhite who documented several of these check methods at
http://goo.gl/JKZZY and http://goo.gl/OJLSib
.EXAMPLE
Test-RebootNeeded -Computername AaronsPC
#>
    [CmdletBinding()]
    [OutputType([bool])]
    Param([Parameter(ValueFromPipeline=$true, Position=0)] [string]$Computername = ".")

    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #this clause runs when a remote machine has been specified
        #output variable in scriptblock because #26 https://github.com/bklockwood/PSWU/issues/26 
        invoke-Command -ComputerName $Computername -ScriptBlock { import-module PSWU; $output = Test-RebootNeeded; $output } 
    } else {
        [bool]$NeedsReboot = $false
        <#
            #Windows Update ISystemInformation, fails remotely, https://goo.gl/Txmf4S
            $SystemInfo= New-Object -ComObject "Microsoft.Update.SystemInfo" 
            if ($SystemInfo.RebootRequired) {$NeedsReboot = $true} 
            #>
        #Windows Update registry key http://goo.gl/GiJCO8
        $WURegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        if (test-path $WURegKey) {$NeedsReboot = $true}
        #Component Based Servicing http://goo.gl/GiJCO8
        $CBSRegkey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        if (test-path $CBSRegkey) {$NeedsReboot = $true}
        #Pending File Rename Operations
        $PFRORegkey = get-item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\FileRenameOperations"
        if ($PFRORegkey.Property) {$NeedsReboot = $true}
        $NeedsReboot
    }
}

function ScheduleRerunTask ($TaskName, $ScriptPath) {
<#
.SYNOPSIS
Creates a Scheduled Task that restarts this script after reboot.
.PARAMETER TaskName
A name for the task.
.PARAMETER ScriptPath
Full path to the script.
.NOTES
The *ScheduledTask* cmdlets are PS v3 and up;
schtasks used purposely to preserve compat with v2 (win7, 2008r2).
This function is likely to be removed soon. (Use New-PSTask instead!)
.EXAMPLE
ScheduleRerunTask RestartTask c:\myscript.ps1
#>
    #note the funky escaping because of http://goo.gl/SgSLrQ
    [string]$TR = """$PSHome\powershell.exe "
    $TR += " -ExecutionPolicy Unrestricted -File \`"$ScriptPath\`" "
    [string]$sctask = "schtasks /create /RU system "
    $sctask += "/SC onstart /TN $TaskName "
    $sctask += "/RL HIGHEST /TR $TR"""
    cmd /c $sctask
}

function CheckForScheduledTask ($TaskName) {
<#
.Synopsis
Checks to see if the specified scheduled task exists.
.PARAMETER TaskName
Name of task to check for.
.EXAMPLE
TODO
#>
    $return = $true
    #Don't need any error output from Powershell
    $ErrorActionPreference = "SilentlyContinue"
    $output = schtasks /query /tn $TaskName   
    if ($LASTEXITCODE -ne 0) {$return = $false}
    $ErrorActionPreference = "Continue"
    $return
}

function Hide-Update {
<#
.Synopsis
   Hides or un-hides updates as specified by KB article number (KBID).
.PARAMETER Computername
   The target computer. Defaults to the local PC.
.PARAMETER KBID
   One or more KBIDs to hide or un-hide.
.PARAMETER UNHIDE
   Switch parameter. If used, the specified KBID(s) will be UN-hidden.
.PARAMETER ISearchResult
   ISearchResult is delivered from Get-UpdateList and is a COM object.
   (http://goo.gl/pvnUSM)
.NOTES
   Hiding updates is a protected action which cannot be performed remotely,
   per Microoft: https://goo.gl/Afi70J ... so, when a remote computer is 
   specified, this cmdlet will create a Scheduled Task on the remote 
   system, and wait for its completion.
.EXAMPLE
   Hide-Update -Computername t7 -KBID 2483139 -Verbose
   VERBOSE: Task was created
   VERBOSE: PSWU task started on t7, waiting for completion.
   ...
   VERBOSE: PSWU task on t7 is in READY state.
   VERBOSE: PSWU task on t7 last run state: COMPLETED SUCCESSFULLY
   VERBOSE: Task completed; t7 does NOT need reboot.

   The above example hides the KB2483139 update (Language Packs) on a 
   remote computer named "t7" and produces verbose output.

.EXAMPLE
   Hide-Update -Computername t7 -UnHide -KBID 3012973
   ...
   
   The above example UN-hides KB3012973 (upgrade to Windows 10)
   on a remote computer named "t7". While waiting for the scheduled 
   task to complete, one dot is printed to console every ten seconds.    
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true, Position=0)] [string]$Computername = ".",
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$false,Position=1)][string[]]$KBID,
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false,Position=2)][switch]$UnHide,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=3)]$ISearchResult
    )
    
    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #this clause runs when a remote machine has been specified
        #NOTE< reason for this scheduled task explained at "Hateful Note" in Install-Update    
        if ($UnHide) {
            $command = "&import-module pswu;Hide-Update -UnHide -KBID $KBID"
        } else {
            $command = "&import-module pswu;Hide-Update -KBID $KBID"
        }
        Write-Verbose "Sending a Hide-Update task to $Computername"
        New-PSTask -Computername $Computername -Command $command      
    } else {
        if ($ISearchResult -eq $null) {$ISearchResult = Get-UpdateList -SearchObject}
        if ($ISearchResult.pstypenames -notcontains 'System.__ComObject#{d40cff62-e08c-4498-941a-01e25f0fd33c}') {
            Write-Error "$ISearchResult is not an ISearchResult object (http://goo.gl/pvnUSM)"
            break
        }
        foreach ($u in $ISearchResult.Updates){
            if ($UnHide) {
                if ($KBID -contains $($u.KbArticleIDs)) {$u.isHidden = $false}
            } else {
                if ($KBID -contains $($u.KbArticleIDs)) {$u.isHidden = $true}
            }
        }
    }
}

function Get-UpdateHistory {
<#
.SYNOPSIS
Gets update history for the target computer.
.PARAMETER Computername
The target computer. Defaults to the local PC.
.EXAMPLE
get-updatehistory t7
01/23/2016 04:09:16, Install, Success, Security Update for Windows 7 for x64-based Systems (KB3108664)
01/23/2016 04:04:09, Install, Success, Security Update for Windows 7 for x64-based Systems (KB3069762)
01/23/2016 04:02:27, Install, Success, Windows Malicious Software Removal Tool x64 - January 2016 (KB890830)
01/23/2016 04:00:50, Install, Success, Update for Windows 7 for x64-based Systems (KB2970228)
01/23/2016 04:00:35, Install, Success, Security Update for Windows 7 for x64-based Systems (KB2965788)
#>
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true, Position=0)] [string]$Computername = "."
    )

    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        Invoke-Command -ComputerName $Computername -scriptblock {import-module PSWU; $output = Get-UpdateHistory; $output}
    } else {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        #$Searcher.Online = $false #try an offline search!
        $HistoryCount = $Searcher.GetTotalHistoryCount()
        $History = $Searcher.QueryHistory(0, $HistoryCount)            
        foreach ($u in $History) {            
            switch ($($u.Operation)) {
                1 {$operation = "Install"}
                2 {$operation = "Uninstall"}
            }
            switch ($($u.ResultCode)) {
                0 {$resultcode = "NotStarted"}
                1 {$resultcode = "InProgress"}
                2 {$resultcode = "Success"}
                3 {$resultcode = "Success(Errors)"}
                4 {$resultcode = "Fail"}
                5 {$resultcode = "Abort"}
            }
            Write-Output "$(Get-LocalTime $($u.Date)), $operation, $resultcode, $($u.Title)"
            #TODO: make a nice object and a PSWUformat for this
        }
    }

}

function Get-UpdateList {
<#
.SYNOPSIS
Gets list of updates from Windows Update.
.DESCRIPTION
By default, output is columnized as shown in example 1.
The abbreviated column headers are:

 I O T H D R E MB
 | | | | | | |  |- Maximum download size, in megabytes
 | | | | | | |---- "E" if EULA accepted, "-" if not
 | | | | | |------ "R" if reboot required, "-" if not (frequently wrong!)
 | | | | |-------- "D" if the update has been downloaded, "-" if not
 | | | |---------- "H" if the update is hidden, "-" if not
 | | |------------ "S" if software, "D" if driver
 | |-------------- "O" if optional, "*" if not
 |---------------- "I" if installed, "-" if not
.PARAMETER Computername
The target computer. Defaults to the local PC. 
.PARAMETER  Criteria
The search criteria, see http://goo.gl/7nZSPs
Left at default, it will return all software updates that have not yet
been installed. Driver updates are ignored, but Hidden updates are shown
with the "H" flag set.
.PARAMETER SearchObject
This switch is used when an ISearchResult object (http://goo.gl/pvnUSM) must be 
returned. For most manual uses you can ignore this; the module will provide it 
when needed internally.
.NOTES
Returns an IUpdateCollection (http://goo.gl/8C2dbb) named IUpdateCollection
IUpdateCollection is type System.__ComObject#{c1c2f21a-d2f4-4902-b5c6-8a081c19a890}
WU error codes: http://goo.gl/cSWDY8
.EXAMPLE
Get-UpdateList 

KB      T H D R E MB Severity  Published  Title                                                                                               
--      - - - - - -- --------  ---------  -----                                                                                               
3107998 S - - - E 2            11/10/2015 Update for Windows Server 2012 R2 (KB3107998)                                                       
3081320 S - - - E 4  Important 11/10/2015 Security Update for Windows Server 2012 R2 (KB3081320)                                              
3101246 S - - - E 1  Important 11/10/2015 Security Update for Windows Server 2012 R2 (KB3101246)                                              
3102939 S - - - E 2  Important 11/10/2015 Security Update for Windows Server 2012 R2 (KB3102939)                                              
3092601 S - - - E 0  Important 11/10/2015 Security Update for Windows Server 2012 R2 (KB3092601)
.EXAMPLE
(Get-UpdateList).Count
5

Shows that there are 5 updates available.
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true, Position=0)] [string]$Computername = ".",
        [Parameter(ValueFromPipeline=$false, Position=1)] [string]$Criteria = "IsInstalled=0 and Type='Software'",
        [Parameter(Position=2)] [switch]$SearchObject
    )

    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #The following IF clause looks silly, but I could not find a cleaner way to send a switch param to remote PC
        #try this at some point: http://goo.gl/R0oi0F
        Write-Verbose "Invoking Get-UpdateList on $Computername"
        if ($SearchObject) {
            $sb = {import-module PSWU; $output = Get-UpdateList -Computername . -Criteria $Using:Criteria -SearchObject; $output}
        } else {
            $sb = {import-module PSWU; $output = Get-UpdateList -Computername . -Criteria $Using:Criteria; $output}
        }
        Invoke-Command -ComputerName $Computername -ScriptBlock $sb
    } else {
        $Searcher = New-Object -ComObject Microsoft.Update.Searcher
        #$Searcher.Online = $false #try an offline search!
        $ISearchResult = $Searcher.Search($Criteria)
        if ($SearchObject) {$ISearchResult} else {$ISearchResult.Updates}
    }    
}

function Install-Update {
<#
.SYNOPSIS
Downloads and installs updates.
.PARAMETER Computername
The target computer. Defaults to the local PC. 
.PARAMETER SkipOptional
If this switch parameter is given, "Optional" updates will not be installed.
.PARAMETER Reboot
If this switch parameter is provided, the system will be rebooted - but *only*
if the update(s) installed left the system in a 'needs reboot' state.
.PARAMETER ISearchResult
An ISearchResult returned by the Get-UpdateList cmdlet.
If not provided, that cmdlet will be run to fetch one.
.PARAMETER OneByOne
Used for debugging. Allows only one update to be downloaded and installed.
.NOTES
Uses IUpdateDownloader http://goo.gl/hPK49j
and IUpdateInstaller http://goo.gl/jeDijU
WU error codes: http://goo.gl/cSWDY8
.EXAMPLE
Install-Update -Computername BensPC -Reboot
Installs outstanding (non-hidden) updates and reboots the computer if needed.
#>

    [CmdletBinding()]
    Param (
        [parameter(ValueFromPipelineByPropertyName=$true, Position=0)][string]$Computername = ".",        
        [parameter(ValueFromPipelineByPropertyName=$true,Position=1)][switch]$SkipOptional = $false,
        [parameter(ValueFromPipelineByPropertyName=$true,Position=2)][switch]$Reboot = $false,
        [parameter(ValueFromPipeline=$true, Position=3)]$ISearchResult,
        [parameter(Position=2)][switch]$OneByOne        
        )
    [bool]$rebootstatus = Test-RebootNeeded -Computername $Computername
    if ($rebootstatus -eq $true) {
        Write-Error "$Computername pending reboot status is: .$rebootstatus. - please reboot before applying further updates."
        break
    }
    
    if (($Computername -ne ".") -and ($Computername -ne $env:COMPUTERNAME) -and ($Computername -ne "localhost") ) {
        #this clause runs when a remote machine has been specified        
        if ($OneByOne) {
            $command = "&import-module pswu;Install-Update -OneByOne"
        } else {
            $command = "&import-module pswu;Install-Update"
        }
        Write-Verbose "Sending an Install-Update task to $Computername"
        if ($Reboot) {
            New-PSTask -Computername $Computername -Command $command -Reboot -Verbose
        } else {
            New-PSTask -Computername $Computername -Command $command  -Verbose
        }
        <# Hateful Note.             
           Creating/running a task on the remote PC and running is FAR FROM OPTIMAL.
           It's just the best thing I could come up with after multiple failed attempts.
           This is not a question of what user context the (remote) commands run in; I have tried as SYSTEM
           IUpdateDownloader (IUD) and IUpdateInstaller (IUI) refuse to be invoked remotely and they
           seem really good at knowing it, though I still don't know exactly *how* they know.           
           See https://goo.gl/Afi70J
           I tried:
           * http://serverfault.com/a/407379/3437 ... IUD knows it was called remotely
           * http://stackoverflow.com/a/14442352/2383 ... IUD knows
           * Pushing all of PSWU to remotePC then running it:
             * icm remotePC {import-module PSWU;install-update} ... IUD knows
             * icm remotePC {powershell.exe -command '&import-module pswu;install-update'} ... IUD knows
             * enter-pssession <sessionid> then run cmdlets local to remotePC ... IUD knows
             * Invoking powershell process via WMI as in http://goo.gl/Yy1iRP ... IUD knows
           * Kicking off WU itself as in https://goo.gl/Thm9k7 {wuauclt /detectnow ; wuauclt /updatenow}
             * There seems no clean way to rely on this, nor to find out when it completes.
        #>
    } else {
        #this clause runs when the cmdlet is invoked locally
        If ((Test-AdminPrivs) -ne $true) {Write-Error "Admin privs required"; break}
        Write-Verbose "Install-Update is starting (as $env:username)."
        if ($ISearchResult -eq $null) {
            $ISearchResult = Get-UpdateList -SearchObject            
        }
        if ($ISearchResult.pstypenames -notcontains 'System.__ComObject#{d40cff62-e08c-4498-941a-01e25f0fd33c}') {
            Write-Error "$ISearchResult is not an ISearchResult object (http://goo.gl/pvnUSM)"
            Write-Log $Logfile 
            break
        }
        Write-Verbose "Update count: $($ISearchResult.Updates.Count)"
        $DesiredUpdates = New-Object -ComObject Microsoft.Update.UpdateColl 
        $counter = 0
        foreach ($u in $ISearchResult.Updates) {
            Write-Verbose "Adding $counter $($u.Title)"
            [bool]$ApplyUpdate = $true
            #"BrowseOnly" is seen in GUI as "Optional"; Don't apply if SkipOptional param is present    
            if (($SkipOptional -eq $true) -and ($($u.BrowseOnly) -eq $true)) {$ApplyUpdate = $false}
            #Do not apply update if hidden
            if ($($u.IsHidden) -eq $true) {$ApplyUpdate = $false}
            if ($ApplyUpdate -eq $true) { 
                $counter++
                if (!$($u.EulaAccepted)) {$u.AcceptEula()}
                $DesiredUpdates.Add($u) |out-null 
            }            
            if ($OneByOne) { 
                #Used for debugging. One update at a time.
                if ($counter -gt 0) {break}
            }      
        }

        If ($DesiredUpdates.Count -lt 1) { 
            Write-Verbose "No updates to install!"
        } else {
            Write-Verbose "Downloading $($DesiredUpdates.Count) updates"
            #IUpdateDownloader, https://goo.gl/hPK49j
            $Downloader = New-Object -ComObject Microsoft.Update.Downloader
            $Downloader.Updates = $DesiredUpdates
            $DownloadResult = $Downloader.Download()
            #Resultcode 2-success, 3-success with errors. 
            #Using -contains instead of -in for PS v2 compat
            if (2,3 -notcontains $DownloadResult.ResultCode) {
                Write-Error "Downloader error HResult $($DownloadResult.HResult), resultcode $($DownloadResult.ResultCode)"
            } else {
                if ($DownloadResult.ResultCode -eq 3) {Write-Verbose "Downloaded with errors; beginning install."}
                if ($DownloadResult.ResultCode -eq 2) {Write-Verbose "Downloaded successfully; beginning install."}
                Write-Verbose "Installing $($DesiredUpdates.Count) updates"
                $Installer = New-Object -ComObject Microsoft.Update.Installer
                $Installer.Updates = $DesiredUpdates
                $InstallResult = $Installer.Install()
                switch ($InstallResult.ResultCode) {
                    2 {Write-Verbose "Installed updates successfully."}
                    3 {Write-Verbose "Installed updates with errors."}
                    default {Write-Error "Installer error $($InstallResult.HResult), resultcode $($InstallResult.ResultCode)"}
                }
                if ((Test-RebootNeeded) -eq $true) {
                    if ($Reboot) {
                        Write-Warning "Updates installed; rebooting."
                        Restart-Computer -force
                    } else {
                        Write-Warning "Updates installed; please reboot soon."
                    }
                } else {
                    Write-Verbose "Updates installed; reboot NOT needed."
                }
            }
        }
    }
}

function Install-RemotePSWU {
<#
.SYNOPSIS
Installs PSWU to remote computer.
.PARAMETER Computername
The target computer. Defaults to the local PC.
.PARAMETER Update
Updates the remote installation of PSWU to an exact copy of the
local installation.
.NOTES
Follow the rules at https://goo.gl/OjL8Nt
Note that Win7 and below do not have C:\Program Files\WindowsPowerShell\Modules
in $env:PSModulePath. I read the rules as saying it is OK to add that path.
.EXAMPLE
Install-RemotePSWU CathyPC -Update
Installs or updates the PSWU module on the system named CathyPC.
#>

    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true, ValueFromPipeline=$true,Position=0)][string]$Computername,
        [parameter(Position=1)][switch]$Update
        
    )

    Write-Verbose "Beginning Install-RemotePSWU"
    #need a mechanism to remotely check whether module is usable
    #construct a UNC filepath to where the remote PSWU installation should be
    $RemoteSystemDrive = Invoke-Command -ComputerName $Computername {$env:SystemDrive}    
    $RemoteSysDriveShare = $RemoteSystemDrive -replace ":","$"
    $RemotePSWUDir = "\\" + $Computername + "\" + $RemoteSysDriveShare + "\Program Files\WindowsPowerShell\Modules\PSWU"
    [boolean]$PSWUdirExists = $true
    if (!(Test-Path $RemotePSWUDir)) {$Update = $true; $PSWUdirExists = $false}
    #if it is not there, install it
    if ($Update) {
        if ($PSWUdirExists) {
            Write-Verbose "Updating PSWU on $Computername"
        } else {
            Write-Verbose "$RemotePSWUDir DOES NOT exist on $Computername, installing PSWU there"
            New-Item -path $RemotePSWUDir -ItemType Directory | out-null
        }        
        #copy the files, unblock them
        $LocalPSWUPath = (Get-Module PSWU).ModuleBase
        Copy-Item $LocalPSWUPath\* $RemotePSWUDir -Force
        Unblock-File -Path $RemotePSWUDir\*
        #Win7 and below do not have the default PSModulePath '%systemdrive%\Program Files\WindowsPowerShell\Modules'  
        #detect this and add to SYSTEM profile if necessary
        $RemotePSModPath = Invoke-Command $Computername {[System.Environment]::GetEnvironmentVariable("PSModulePath", "Machine")}
        $PathToAdd = $RemoteSystemDrive + '\Program Files\WindowsPowerShell\Modules'        
        if (($RemotePSModPath -split ";") -NotContains $PathToAdd ) {
            $NewRemotePSModPath = $RemotePSModPath + ";" + $PathToAdd
            Invoke-Command $Computername {
                [System.Environment]::SetEnvironmentVariable("PSModulePath", $Using:NewRemotePSModPath, "Machine")
                import-module PSWU
                Get-ExecutionPolicy
            }            
        }
        Write-Verbose "PSWU installed/updated on $Computername"     
    }

}

function New-PSTask {
<#
.SYNOPSIS
Creates, runs, monitors, and finally deletes a Scheduled Task on a remote PC.
.DESCRIPTION
.PARAMETER Computername
The target computer. Defaults to the local PC.
.PARAMETER Command
The Powershell command(s) to be run by the remote scheduled task. 
.PARAMETER Reboot
If this switch parameter is given, the remote PC will be rebooted *if*
it is in a 'needs reboot' state.
.EXAMPLE
New-PSTask -Computername DanaPC -Command "&import-module pswu;Install-Update" -Reboot
The system named DanaPC will immediately run a scheduled task containing an 
Install-Update command. If this leaves DanaPC in a 'needs reboot' state, then it will
be rebooted.
.NOTES

#>
    [CmdletBinding()]
    Param (
        [parameter(Mandatory=$true, ValueFromPipeline=$true,Position=0)][string]$Computername,
        [parameter(Mandatory=$true, ValueFromPipeline=$true,Position=1)][string]$Command,
        [parameter(ValueFromPipeline=$true,Position=2)][switch]$Reboot = $false
    )
    
    #Task Scheduler Scripting Objects https://goo.gl/iFYhlB 
    #Loosely emulating this example - https://goo.gl/9BHrQW
    #TaskService object, https://goo.gl/ewm1Th
    $Scheduler = New-Object -ComObject Schedule.Service
    #TODO: Check for existing task with this name. Especially if it is running!
    $Scheduler.Connect($Computername)
    if ($Scheduler.Connected) {  
        $Task = $Scheduler.NewTask(0)
        #Task Definition Object https://goo.gl/UQbjMA
        $Task.Settings.MultipleInstances = 2 #Don't allow multiple instances of this task
        $Task.RegistrationInfo.Description = "Task created by PSWU script."
        #Principal object, https://goo.gl/u99qVL
        $Task.Principal.Runlevel = 1 #highest

        #Task Action definition https://goo.gl/3qA7Qy
        $Action = $Task.Actions.Create(0) #0 = Executable
        $Action.Path = "powershell.exe"
        $Action.Arguments = "-ExecutionPolicy Unrestricted -Command $Command"      

        #Taskfolder object, https://goo.gl/AWZM9j
        $TaskFolder = $Scheduler.GetFolder("\")
        #TODO - Verify no existing PSWU task 
        $CreatedTask = $TaskFolder.RegisterTaskDefinition("PSWU", $Task, 6, "SYSTEM", $Null, 3)
        
        #Run task if verified in READY state
        if ($($CreatedTask.State) -eq 3) {
            Write-Verbose "Task was created"
            $TaskFolder.GetTask("PSWU").Run(0) |Out-Null
            #Task should enter RUNNING state. Monitor for state change. 
            if ($($CreatedTask.State) -eq 4) {
                Write-Verbose "PSWU task started on $Computername, waiting for completion."
                $i = 0
                While ($($CreatedTask.State) -eq 4) {
                    Start-Sleep -Seconds 10
                    Write-Host -NoNewline "."
                    $i++
                }
                Write-Host
            }

            #Task states https://goo.gl/SugOUy
            switch ($($CreatedTask.State)) {
                0 {$state = "UNKNOWN"}
                1 {$state = "DISABLED"}
                2 {$state = "QUEUED"}
                3 {$state = "READY"}
                4 {$state = "RUNNING"}
            }
            Write-Verbose "PSWU task on $Computername is in $state state."

            #LastTaskResult states from https://goo.gl/rR128s
            #Apparently no MS docs on this; https://goo.gl/GRxUHz
            switch ($($CreatedTask.LastTaskResult)) {
                0 {$lastrunstate = "COMPLETED SUCCESSFULLY"}
                1 {$lastrunstate = "UNKNOWN/INCORRECT FUNCTION CALL"}
                2 {$lastrunstate = "FILE NOT FOUND"}
                10 {$lastrunstate = "INCORRECT ENVIRONMENT"}
            }
            Write-Verbose "PSWU task on $Computername last run state: $lastrunstate"

            #Delete the task, report pending-reboot status
            $TaskFolder.DeleteTask("PSWU",$Null)
            #Probly should move this logic to whichever cmdlet calls New-PSTask
            if ((Test-RebootNeeded -Computername $Computername) -eq $true) {
                if ($Reboot) {
                    Write-Verbose "Task completed; rebooting $Computername."
                    Restart-Computer $Computername -force
                } else {
                    Write-Verbose "Task completed; please reboot $Computername."
                }
            } else {
                Write-Verbose "Task completed; $Computername does NOT need reboot."
            }
        }
    }

}

Function Get-LocalTime($UTCTime) {
<#
.SYNOPSIS
Translates a UTC date to one appropriate to the local timezone.
.PARAMETER UTCTime
The UTC date object which needs to be read as local time.
.NOTES
Thanks Tao Yang: http://goo.gl/R0w1Fk
.EXAMPLE
Get-LocalTime $dateobject
#>

    $strCurrentTimeZone = (Get-WmiObject win32_timezone).StandardName
    $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
    $LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
    Return $LocalTime
}

#function reloadt7 {remove-module pswu;import-module pswu; Install-RemotePSWU t7 -Verbose -Update}
#function reloadt81 {remove-module pswu;import-module pswu; Install-RemotePSWU t81 -Verbose -Update}