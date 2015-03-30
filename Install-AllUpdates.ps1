#requires -version 2.0

#flowchart: http://i.imgur.com/NSV8AH2.png

function Install-AllUpdates {
    [string]$ScriptName = $($MyInvocation.MyCommand.Name)
    [string]$ScriptName = $($ScriptName.Split('.')[0])
    [string]$ScriptPath = $PSCommandPath
    #break
    import-module pswu
    $Logfile = "$env:PUBLIC\Desktop\$ScriptName.log"
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
        if (!(CheckForScheduledTask "PSWU")) {ScheduleRerunTask "PSWU" $ScriptPath}
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
        $NonHiddenUpdateCount = ($ISearchResult.Updates | Where-Object {$_.IsHidden -eq $false}).Count
        #if ($ISearchResult.Updates.Count -gt 0) {
        if ($NonHiddenUpdateCount -gt 0) {
            Write-Log $Logfile "Non-hidden updates: $NonHiddenUpdateCount"
            [string]$UpdateReport = Show-UpdateList -ISearchResult $ISearchResult
            Write-Log $Logfile $UpdateReport  
            Write-Log $Logfile "Downloading and installing $NonHiddenUpdateCount updates."
            $Install = Install-Update -ISearchResult $ISearchResult -Verbose
            Write-Log $Logfile "Done installing updates. Restarting script to check for more."
            Install-AllUpdates
        } else {
            Write-Log $Logfile "Windows is up to date; script cleaning up."
            #check for PSWU Scheduled Task and delete if found
            if (CheckForScheduledTask "PSWU") {
                Write-Log $Logfile "Found PSWU task; removing. "
                #Tried Stop-SceduledTask and Unregister-ScheduledTask
                #Nither will kill the running task. schtasks works.
                schtasks /delete /tn pswu /F
                }
		    #TODO: tell user all done. write to all-users desktop?     
            Write-Log $Logfile "Cleanup complete. Running as $env:username - script exiting."
            New-Item -ItemType File -Path "$env:PUBLIC\Desktop" -Name "DONE UPDATING" -Value "You can delete this file and $Logfile"
            break
        }
    }
}

Install-AllUpdates
