<#
.VERSION
    1.5.1.0.009

.SYNOPSIS
    Event Log and System Health Monitoring Script for CinnTech

.DESCRIPTION
    This version fixes the mapping of logical disks to physical disks using WMI associators and retrieves masked serial numbers correctly.
    It also maintains previous functionality for event log fetching, ping tests, and disk space reporting.

.AUTHOR
    CinnTech

.CHANGELOG
    Version 1.5.1.0.009
    - Corrected mapping between volumes (logical disks), partitions, and physical disks using WMI associators.
    - Properly retrieves masked serial numbers.
#>

# --- Structured Logging Function ---
function Write-Log {
    param (
        [string]$logMessage,
        [string]$logLevel = "INFO"
    )
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timeStamp - $logLevel - $logMessage"
    Add-Content -Path "$scriptLogFileBase.log" -Value $logEntry
}

$eventLogs = @(
    'System',
    'Application', 
    'Security',
    'Microsoft-Windows-DiskDiagnosticDataCollector/Operational',
    'Microsoft-Windows-StorageSpaces-Driver/Operational',
    'Microsoft-Windows-Ntfs/Operational',
    'Microsoft-Windows-DNS-Client/Operational',
    'Microsoft-Windows-NetworkProfile/Operational',
    'Microsoft-Windows-SMBClient/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
    'Microsoft-Windows-Security-Auditing',
    'Microsoft-Windows-Security-Mitigations/Operational'
)

$logPath = "C:\cTemp"
$logBaseName = "MSP_EventLog"
$htmlFileName = "$logPath\MSP_EventLogLatest.html"
$scriptLogFileBase = "$logPath\MSP_ScriptLog"
$maxLogFiles = 5
$previousRunDataFile = "$logPath\PreviousEventCounts.json"
$pingTarget = "8.8.8.8"
$pingResults = @()  # To store ping results

# --- Load Previous Report Run Date ---
$previousRunTimeFile = "$logPath\PreviousRunTime.txt"

# Read last report time from file, or set it to "Unknown" if the file does not exist
if (Test-Path $previousRunTimeFile) {
    $lastRunDate = Get-Content $previousRunTimeFile
    Write-Log "Last report was generated on $lastRunDate."

    # Convert lastRunDate to DateTime
    $lastRunDateTime = [datetime]::Parse($lastRunDate)
    
    # Calculate the time difference between now and the last run
    $timeDifference = New-TimeSpan -Start $lastRunDateTime -End (Get-Date)

    # Generate a human-readable description for the time difference
    if ($timeDifference.TotalMinutes -lt 1) {
        $comparisonDescription = "Comparing data from just now"
    }
    elseif ($timeDifference.TotalMinutes -lt 60) {
        $comparisonDescription = "Comparing data from $($timeDifference.Minutes) minutes ago"
    }
    else {
        $comparisonDescription = "Comparing data from $($timeDifference.Hours) hours and $($timeDifference.Minutes) minutes ago"
    }

} else {
    $lastRunDate = "Unknown"
    Write-Log "No previous report run time found."
    $comparisonDescription = "No previous data to compare"
}

# --- Rotating Logs Function ---
function Rotate-Logs {
    param (
        [string]$logBase,
        [string]$extension = ".log"
    )
    Write-Log "Rotating log files for base $logBase."
    
    for ($i = $maxLogFiles - 1; $i -ge 1; $i--) {
        $oldFile = "$logBase-$i$extension"
        $newFile = "$logBase-$(($i + 1))$extension"
        if (Test-Path $oldFile) {
            if (Test-Path $newFile) {
                Remove-Item $newFile
            }
            Rename-Item $oldFile $newFile
        }
    }

    $mainLogFile = "$logBase$extension"
    if (($global:scriptRunCount -ge 1) -and (Test-Path $mainLogFile)) {
        Rename-Item "$logBase$extension" "$logBase-1$extension"
    }
}

# --- Ping Monitoring ---
function Perform-PingTest {
    param (
        [string]$target,
        [ref]$pingResults
    )
    Write-Log "Running ping test for $target."
    try {
        $pingData = Test-Connection -ComputerName $target -Count 10 -ErrorAction SilentlyContinue

        if ($pingData) {
            $latencies = $pingData | Select-Object -ExpandProperty ResponseTime
            $minLatency = ($latencies | Measure-Object -Minimum).Minimum
            $maxLatency = ($latencies | Measure-Object -Maximum).Maximum
            $avgLatency = ($latencies | Measure-Object -Average).Average
            $successPercentage = ([math]::round(($pingData.Count / 10) * 100, 2))

            $pingResults.Value += [PSCustomObject]@{
                MinLatency = $minLatency
                MaxLatency = $maxLatency
                AvgLatency = $avgLatency
                SuccessPercentage = $successPercentage
            }
        } else {
            Write-Log "Ping failed for target $target." "ERROR"
        }
    }
    catch {
        Write-Log "Error running ping: $_" "ERROR"
    }
}

# --- Get System Uptime ---
function Get-SystemUptime {
    try {
        $lastBootTime = (Get-CimInstance -Class Win32_OperatingSystem).LastBootUpTime
        $uptimeSpan = New-TimeSpan -Start $lastBootTime -End (Get-Date)
        $uptimeFormatted = "{0} days {1} hours {2} minutes" -f $uptimeSpan.Days, $uptimeSpan.Hours, $uptimeSpan.Minutes
        Write-Log "System last boot time: $lastBootTime. Uptime: $uptimeFormatted."
        return $uptimeFormatted
    }
    catch {
        Write-Log "Error fetching system uptime: $_" "ERROR"
        return "Unknown"
    }
}

# --- Fetch Event Logs Optimized ---
function Fetch-EventLogs {
    param([DateTime]$startDate, [array]$logs)

    Write-Log "Fetching event logs for $($logs.Count) log sources starting from $startDate."
    Write-Host "Fetching event logs for $($logs.Count) log sources..." # User-facing progress update
    try {
        $events = $logs | ForEach-Object {
            Get-WinEvent -LogName $_ -MaxEvents 100 -ErrorAction SilentlyContinue |
            Where-Object { ($_.LevelDisplayName -eq 'Error' -or $_.LevelDisplayName -eq 'Warning') -and ($_.TimeCreated -ge $startDate) }
        }
        Write-Log "Successfully fetched $($events.Count) error/warning events."
        return $events
    }
    catch {
        Write-Log "Error fetching event logs: $_" "ERROR"
        throw
    }
}

# --- Process Event Logs ---
function Process-Events {
    param([array]$events, [hashtable]$previousRunData)

    Write-Host "Processing event logs and calculating differences..." # User-facing progress update
    Write-Log "Processing event logs and calculating count differences."

    # Initialize current run data as a hashtable
    $currentRunData = @{}

    $groupedEvents = $events | Group-Object Id, ProviderName | ForEach-Object {
        $LastEvent = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1  # Select most recent

        # Create a unique key for the event based on EventID and Provider
        $eventKey = "$($LastEvent.Id)-$($LastEvent.ProviderName)"

        # Save the current count for this EventID and ProviderName combination
        $currentRunData[$eventKey] = $_.Count

        # Count unique messages for EventID if there are more than one event
        $uniqueMessageCount = ($_.Group | Group-Object Message).Count

        # Check if the event key exists in previous run data
        $previousCount = if ($previousRunData.PSObject.Properties.Match($eventKey)) { 
            $previousRunData.$eventKey 
        } else { 
            0 
        }

        # Calculate the count difference from the previous run
        $countDifference = $_.Count - $previousCount

        # Determine the symbol for the count difference (+, -, None)
        $differenceSymbol = if ($countDifference -gt 0) { "+$countDifference" } 
                            elseif ($countDifference -lt 0) { "$countDifference" } 
                            else { "None" }

        [PSCustomObject]@{
            EventID              = $LastEvent.Id
            UniqueMessages       = if ($_.Count -gt 1) { $uniqueMessageCount } else { "1" }
            Provider             = $LastEvent.ProviderName
            Message              = [System.Web.HttpUtility]::HtmlEncode($LastEvent.Message)
            TotalCount           = $_.Count
            ChangeInTotalCount   = $differenceSymbol
            TimeCreated          = $LastEvent.TimeCreated
            Severity             = $LastEvent.LevelDisplayName
        }
    }

    Write-Log "Successfully processed $($groupedEvents.Count) grouped events."
    return $groupedEvents, $currentRunData
}

# --- Get System Info (Disks and Masked Serial Numbers) ---
function Get-SystemInfo {
    try {
        # Get all logical disks (mounted volumes)
        $logicalDisks = Get-CimInstance -Class Win32_LogicalDisk

        if ($logicalDisks.Count -eq 0) {
            Write-Log "No FileSystem disk drives found." "ERROR"
            return @()
        }

        # Log the number of disks found
        Write-Log "Found $($logicalDisks.Count) logical disks."

        # Process each logical disk and calculate used space, free space, etc.
        $systemInfoData = $logicalDisks | ForEach-Object {
            $logicalDisk = $_
            
            # Use WMI associators to get the corresponding partition for this logical disk
            $partition = Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='$($logicalDisk.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition" -ErrorAction SilentlyContinue

            if ($partition) {
                # Use WMI associators to get the corresponding physical disk for this partition
                $diskDrive = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} WHERE AssocClass=Win32_DiskDriveToDiskPartition" -ErrorAction SilentlyContinue

                if ($logicalDisk.Size -ne $null -and $logicalDisk.FreeSpace -ne $null) {
                    $usedSpaceGB = [math]::round([double](($logicalDisk.Size - $logicalDisk.FreeSpace) / 1GB), 2)
                    $freeSpaceGB = [math]::round([double]($logicalDisk.FreeSpace / 1GB), 2)
                    $totalSizeGB = [math]::round([double]($logicalDisk.Size / 1GB), 2)
                    $freeSpacePercentage = [math]::round(($logicalDisk.FreeSpace / $logicalDisk.Size) * 100, 2)

                    # Masking the serial number for security (only showing last 4 digits)
                    $maskedSerial = if ($diskDrive.SerialNumber) {
                        $serialLength = $diskDrive.SerialNumber.Length
                        "*".PadLeft($serialLength - 4, '*') + $diskDrive.SerialNumber.Substring($serialLength - 4)
                    } else {
                        "N/A"
                    }

                    # Log the current disk being processed
                    Write-Log "Processing disk: $($logicalDisk.DeviceID) - Used: $usedSpaceGB GB, Free: $freeSpaceGB GB"
                    
                    [PSCustomObject]@{
                        Model              = $logicalDisk.DeviceID
                        Status             = "OK"  # Assuming status OK for simplicity
                        SerialNumber       = $maskedSerial  # Masked serial number
                        Size               = "$totalSizeGB GB"  # Total size in GB
                        FreeSpacePercentage = "$freeSpacePercentage%"  # Free space percentage
                        TotalUsedSpace     = "$usedSpaceGB GB"  # Used space in GB
                        FreeSpaceGB        = "$freeSpaceGB GB"  # Free space in GB
                    }
                }
                else {
                    Write-Log "Skipping disk: $($logicalDisk.DeviceID) because it has invalid used/free space."
                }
            } else {
                Write-Log "No partition found for logical disk: $($logicalDisk.DeviceID)"
            }
        }

        if ($systemInfoData.Count -eq 0) {
            Write-Log "No valid disk information to report." "ERROR"
            return @()
        }

        return $systemInfoData
    }
    catch {
        Write-Log "Error retrieving system information: $_" "ERROR"
        return @()  # Return an empty array if something goes wrong
    }
}

# --- Generate HTML Report ---
function Generate-HTMLReport {
    param (
        [string]$systemName,
        [string]$uptimeFormatted,
        [string]$performanceReport,
        [array]$groupedEvents,
        [array]$systemInfoData,
        [array]$pingResults
    )

    $css = @"
    <style>
        body { font-family: Arial, sans-serif; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 10px; border: 1px solid #ddd; }
        th { background-color: #f4f4f4; text-align: left; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        tr:nth-child(odd) { background-color: #fff; }
        .error-eventid { background-color: #f8d7da; color: #721c24; }
        .warning-eventid { background-color: #fff3cd; color: #856404; }
        h2 { color: #2c3e50; }
        p { color: #34495e; }
    </style>
"@

    $htmlContent = "$css <html><head><title>CinnTech Event Log Report</title></head><body>"
    $htmlContent += "<h2>CinnTech Event Log Report for $systemName</h2>"
    $htmlContent += "<p>This report contains Error and Warning logs generated on <strong>$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))</strong>.</p>"
    $htmlContent += "<p><strong>System Uptime:</strong> Last boot: $uptimeFormatted.</p>"
    $htmlContent += "<p><strong>Last Report Run:</strong> $lastRunDate.</p>"
    $htmlContent += "<p><strong>$comparisonDescription</strong></p>"

    # Add Ping Results below System Uptime
    if ($pingResults.Count -gt 0) {
        $pingSummary = $pingResults[0]
        $htmlContent += "<p><strong>Current Ping to ${pingTarget}:</strong></p>"
        $htmlContent += "<ul><li><strong>Min Latency:</strong> $($pingSummary.MinLatency) ms</li>"
        $htmlContent += "<li><strong>Max Latency:</strong> $($pingSummary.MaxLatency) ms</li>"
        $htmlContent += "<li><strong>Avg Latency:</strong> $($pingSummary.AvgLatency) ms</li>"
        $htmlContent += "<li><strong>Success Rate:</strong> $($pingSummary.SuccessPercentage)%</li></ul>"
    } else {
        $htmlContent += "<p>No ping results available.</p>"
    }

    # Add Performance Report Section
    $htmlContent += "$performanceReport"

    # Add title for the Event Log Table
    $htmlContent += "<h3>Event Log Report (Today's Logs Only)</h3>"
    $htmlContent += "<table border='1'><tr><th>EventID</th><th>Unique Messages</th><th>Provider</th><th>Message</th><th>Total Count</th><th>Change in Total Count</th><th>TimeCreated</th></tr>"

    # Add event rows
    foreach ($event in $groupedEvents | Sort-Object TimeCreated -Descending) {
        $eventIdClass = if ($event.Severity -eq 'Error') { 'error-eventid' } elseif ($event.Severity -eq 'Warning') { 'warning-eventid' } else { '' }
        $htmlContent += "<tr><td class='$eventIdClass'>$($event.EventID)</td><td>$($event.UniqueMessages)</td><td>$($event.Provider)</td><td>$($event.Message)</td><td>$($event.TotalCount)</td><td>$($event.ChangeInTotalCount)</td><td>$($event.TimeCreated)</td></tr>"
    }

    $htmlContent += "</table>"

    # System health report section
    $htmlContent += "<h3>System Health Report</h3>"

    if ($systemInfoData.Count -eq 0) {
        $htmlContent += "<p>No system information available.</p>"
    } else {
        $systemHealthHtml = $systemInfoData | ConvertTo-Html -Property Model, Status, SerialNumber, Size, TotalUsedSpace, FreeSpaceGB, FreeSpacePercentage -Head ""
        $htmlContent += "$systemHealthHtml"
    }

    $htmlContent += "</body></html>"
    return $htmlContent
}

# --- Main Script Execution ---

Write-Log "Script version 1.5.1.0.009 started."
Write-Host "Rotating logs..."
Rotate-Logs -logBase $scriptLogFileBase -extension ".log"

$scriptStartTime = Get-Date
$uptimeFormatted = Get-SystemUptime

# Perform ping monitoring at the beginning
Perform-PingTest -target $pingTarget -pingResults ([ref]$pingResults)

# Estimate time for fetching event logs
$logCount = $eventLogs.Count
$timeEstimateLow = $logCount * 10   # Low end of time estimate (10 seconds per log)
$timeEstimateHigh = $logCount * 60  # High end of time estimate (60 seconds per log)
$timeEstimateMinutesLow = [math]::round($timeEstimateLow / 60, 2)
$timeEstimateMinutesHigh = [math]::round($timeEstimateHigh / 60, 2)

# Show estimate in minutes if greater than 60 seconds
if ($timeEstimateLow -lt 60) {
    Write-Host "Fetching today's event logs for $logCount sources. Estimated time: approximately $timeEstimateLow to $timeEstimateHigh seconds..."
    Write-Log "Fetching today's event logs for $logCount sources. Estimated time: $timeEstimateLow to $timeEstimateHigh seconds."
} else {
    Write-Host "Fetching today's event logs for $logCount sources. Estimated time: approximately $timeEstimateMinutesLow to $timeEstimateMinutesHigh minutes..."
    Write-Log "Fetching today's event logs for $logCount sources. Estimated time: $timeEstimateMinutesLow to $timeEstimateMinutesHigh minutes."
}

$events = Fetch-EventLogs -startDate (Get-Date).Date -logs $eventLogs

if ($events.Count -eq 0) {
    Write-Log "No error or warning events found for today. Exiting."
    $htmlContent = "<h2>No Error or Warning logs found for $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').</h2>"
    $htmlContent | Out-File -FilePath $htmlFileName
    Exit
}

# Load previous run data (or initialize if missing)
$previousRunData = if (Test-Path $previousRunDataFile) { 
    $jsonData = Get-Content $previousRunDataFile | ConvertFrom-Json
    $hashtable = @{}
    foreach ($item in $jsonData.PSObject.Properties) {
        $hashtable[$item.Name] = $item.Value
    }
    $hashtable
} else { 
    @{} 
}

# Process events and calculate differences
$groupedEvents, $currentRunData = Process-Events -events $events -previousRunData $previousRunData

Write-Host "Fetching system health information..."
$systemInfoData = Get-SystemInfo

Write-Host "Generating HTML report..."
$htmlContent = Generate-HTMLReport -systemName (Get-CimInstance -Class Win32_ComputerSystem).Name `
                    -uptimeFormatted $uptimeFormatted `
                    -performanceReport $performanceReport `
                    -groupedEvents $groupedEvents `
                    -systemInfoData $systemInfoData `
                    -pingResults $pingResults

# Save the HTML content to file
$htmlContent | Out-File -FilePath $htmlFileName
Write-Log "Generated HTML report: $htmlFileName."

# Save current run data for future comparison
$currentRunData | ConvertTo-Json | Set-Content $previousRunDataFile
Write-Log "Saved current event count data to $previousRunDataFile."

# Save current run time to file
(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') | Set-Content $previousRunTimeFile

# End script logging
$scriptEndTime = Get-Date
$scriptDuration = $scriptEndTime - $scriptStartTime
Write-Log "Script completed in $($scriptDuration.TotalSeconds) seconds."
Write-Host "Script completed in $($scriptDuration.TotalSeconds) seconds."

# Increment global variable for tracking script runs
$global:scriptRunCount++
Write-Host "Script completed."
