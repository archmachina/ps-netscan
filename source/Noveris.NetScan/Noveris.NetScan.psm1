<#
#>

#Requires -Modules @{"ModuleName"="Noveris.SvcProc";"RequiredVersion"="0.1.3"}

########
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

<#
#>
Function New-NetScanRange
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RangeStart,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RangeEnd,

        [Parameter(Mandatory=$false)]
        [bool]$Ping = $true,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int[]]$TcpPorts = [int[]]@(80, 443, 445, 22, 3389)
    )

    process
    {
        $range = [PSCustomObject]@{
            Name = $Name
            RangeStart = $RangeStart
            RangeEnd = $RangeEnd
            Ping = $Ping
            TcpPorts = $TcpPorts
        }

        Get-NetScanRangeData -Range $range | Out-Null

        $range
    }
}

<#
#>
Function Get-NetScanRangeData
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [PSCustomObject]$Range
    )

    process
    {
        # Check for required properties on the Range object
        @("Name", "RangeStart", "RangeEnd", "Ping", "TcpPorts") | ForEach-Object {
            if (($Range | Get-Member).Name -notcontains $_)
            {
                Write-Error "Missing $_ property on Range object"
            }
        }

        # Validate the start address
        $RangeStart = $Range.RangeStart.ToString()
        $beginParsed = [IPAddress]::Parse($RangeStart)
        $beginBytes = $beginParsed.GetAddressBytes()

        # Validate the end address
        $RangeEnd = $Range.RangeEnd.ToString()
        $endParsed = [IPAddress]::Parse($RangeEnd)
        $endBytes = $endParsed.GetAddressBytes()

        # Ensure both addresses are the same family type
        if ($beginParsed.AddressFamily -ne $endParsed.AddressFamily)
        {
            Write-Error "Begin and end address are different address families"
        }

        # Determine address length and make sure it is a supported address type
        $addressLength = 0
        switch ($beginParsed.AddressFamily)
        {
            "InterNetworkV6" {
                $addressLength = 16
            }

            "InterNetwork" {
                $addressLength = 4
            }

            default {
                Write-Error "Unsupported address family type"
            }
        }

        # Convert byte ranges, if we're little endian
        if ([BitConverter]::IsLittleEndian)
        {
            [Array]::Reverse($beginBytes)
            [Array]::Reverse($endBytes)
        }

        # Convert to BigInteger, so we can work with them as integers
        $beginAddress = [System.Numerics.BigInteger]::New($beginBytes)
        $endAddress = [System.Numerics.BigInteger]::New($endBytes)
        Write-Verbose "Begin Address (int): $beginAddress"
        Write-Verbose "End Address (int): $endAddress"

        # Make sure the begin address is less than or equal to the end address
        if ($beginAddress.CompareTo($endAddress) -gt 0)
        {
            Write-Error "Begin address is greater than the end address"
        }

        [PSCustomObject]@{
            Name = [string]($Range.Name)
            RangeStartInt = $beginAddress
            RangeEndInt = $endAddress
            AddressLength = $addressLength
            Ping = [bool]$Range.Ping
            TcpPorts = [int[]]($Range.TcpPorts)
        }
    }
}

<#
#>
Function Test-NetScanRangeConnectivity
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$Ranges,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$ConcurrentChecks = 32,

        [Parameter(Mandatory=$false)]
        [switch]$ExcludeUnavailable = $false,

        [Parameter(Mandatory=$false)]
        [switch]$LogProgress = $false
    )

    process
    {
        # Convert ranges to range data and check validity
        Write-Verbose "Converting and checking range data"
        $RangeData = $Ranges | ForEach-Object {
            Get-NetScanRangeData -Range $_
        }

        # Create storage for connectivity state
        $connectionState = [Ordered]@{}

        # Create runspace environment
        Write-Verbose "Creating runspace pool"
        $pool = [RunSpaceFactory]::CreateRunspacePool(1, $ConcurrentChecks)
        $pool.ApartmentState = "MTA"
        $pool.Open()
        $runspaces = New-Object System.Collections.Generic.List[PSCustomObject]

        # Script block for processing completed runspaces
        $processScript = {
            param($result)

            $ErrorActionPreference = "Stop"
            Set-StrictMode -Version 2

            #Write-Host "Received Result: $result"
            $state = $result | ConvertFrom-Json
            $targetState = $connectionState[$state.Target]
            #Write-Host ("TargetState eq null: " + ($targetState -eq $null))
            #Write-Host $connectionState.Keys
            #Write-Host ("Connection State contains target: " + ($connectionState.Keys -contains $state.Target))

            # If this port or icmp check returned available, overall, the system is available
            if ($state.Available)
            {
                $targetState.Available = $true
            }

            # Update the ping attribute, if this was a ping check
            if ($state.Check -eq "Ping")
            {
                $targetState.Ping = [string]$state.Available
            }

            if ($state.Check -eq "TCP")
            {
                if ($state.Available)
                {
                    if (![string]::IsNullOrEmpty($targetState.TcpPorts))
                    {
                        $targetState.TcpPorts += ","
                    }

                    $targetState.TcpPorts += [string]$state.Port
                }
            }
        }

        # Script for scanning target
        $checkScript = {
            param(
                [Parameter(Mandatory=$true)]
                [ValidateNotNull()]
                [IPAddress]$Target,

                [Parameter(Mandatory=$false)]
                [bool]$Ping = $false,

                [Parameter(Mandatory=$false)]
                [int]$TcpPort
            )

            $ErrorActionPreference = "Stop"
            Set-StrictMode -Version 2

            $status = @{
                Target = $Target.ToString()
                Available = $false
                Port = 0
                Check = "unknown"
                Error = ""
            }

            try {
                if ($Ping)
                {
                    # Ping the remote host
                    $status["Check"] = "Ping"
                    $status["Available"] = $false
                    $pingRequest = New-Object System.Net.NetworkInformation.Ping
                    $replies = @()
                    $total = 4

                    # Send a series of echo requests to the target
                    for ($count = 0; $count -lt $total ; $count++) {
                        $replies += $pingRequest.Send($Target)
                        if ($count -lt ($total-1)) {
                            Start-Sleep 1
                        }
                    }

                    # If we received any replies, change availability to true
                    if ($replies.Status -contains "Success")
                    {
                        $status["Available"] = $true
                    }
                }

                if ($PSBoundParameters.Keys -contains "TcpPort")
                {
                    $status["Check"] = "TCP"
                    $status["Port"] = $TcpPort
                    $status["Available"] = $false

                    # Check this tcp port on the remote host
                    $client = [System.Net.Sockets.TCPClient]::New()
                    try {
                        # We don't care about the result of the task, just whether the client
                        # became connected within the timeout period
                        $client.ConnectAsync($Target, $TcpPort) | Out-Null

                        for ($count = 0; $count -lt 5 ; $count++)
                        {
                            if ($client.Connected)
                            {
                                $status["Available"] = $true
                                break
                            }

                            Start-Sleep -Seconds 1
                        }
                    } catch {
                        # Ignore error here. Either way, it is unavailable.
                    }

                    try {
                        $client.Close()
                        $client.Dispose()
                    } catch {
                    }
                }
    
            } catch {
                $status["Error"] = $_.ToString()
            }

            $result = [PSCustomObject]$status | ConvertTo-Json
            #Write-Host "Result: $result"
            $result
        }

        # Loop through all of the ranges supplied
        foreach ($range in $RangeData) {
            $rangeName = $range.Name
            $rangeStartInt = $range.RangeStartInt
            $rangeEndInt = $range.RangeEndInt
            $addressLength = $range.AddressLength
            $ping = $range.Ping
            $tcpPorts = $range.TcpPorts

            if ($LogProgress)
            {
                Write-Information "Current Range: $rangeName"
            }

            # Loop through each address in the range
            $currentAddress = $rangeStartInt
            while ($currentAddress.CompareTo($rangeEndInt) -le 0)
            {
                # Construct a usable address
                $target = [array]::CreateInstance([byte], $addressLength)
                $bytes = $currentAddress.ToByteArray()
                [array]::Copy($bytes, $target, $bytes.Length)

                if ([BitConverter]::IsLittleEndian)
                {
                    [array]::Reverse($bytes)
                }

                $addr = [IPAddress]::New($bytes)
                $addrStr = $addr.ToString()
                Write-Verbose "Current Address: $addrStr"

                if ($LogProgress)
                {
                    Write-Information "Current Address: $addrStr"
                }

                # Add this address to the connection state now to preserve ordering
                $connectionState[$addrStr] = [PSCustomObject]@{
                    Range = $rangeName
                    Name = $addrStr
                    Available = $false
                    Ping = "unknown"
                    TcpPorts = ""
                }

                # Wait for runspace count to reach low water mark before proceeding
                $runspaces = (Wait-NetScanCompletedRunspaces -Runspaces $runspaces -LowWatermark 300 -ProcessScript $processScript).Runspaces

                # Schedule a ping check, if requested
                if ($Ping)
                {
                    Write-Verbose "Scheduling ping check"
                    $runspace = [PowerShell]::Create()
                    $runspace.AddScript($checkScript) | Out-Null
                    $runspace.AddParameter("Target", $addr) | Out-Null
                    $runspace.AddParameter("Ping", $true) | Out-Null
                    $runspace.RunspacePool = $pool

                    $runspaces.Add([PSCustomObject]@{
                        Runspace = $runspace
                        Status = $runspace.BeginInvoke()
                    })
                }

                # Loop through all tcp ports to check and schedule check
                foreach ($port in $TcpPorts) {
                    Write-Verbose "Scheduling tcp check: $port"
                    $runspace = [PowerShell]::Create()
                    $runspace.AddScript($checkScript) | Out-Null
                    $runspace.AddParameter("Target", $addr) | Out-Null
                    $runspace.AddParameter("TcpPort", $port) | Out-Null
                    $runspace.RunspacePool = $pool

                    $runspaces.Add([PSCustomObject]@{
                        Runspace = $runspace
                        Status = $runspace.BeginInvoke()
                    })
                }

                # Increment current address using BigInteger static method
                $currentAddress = [System.Numerics.BigInteger]::Add($currentAddress, 1)
            }
        }

        # Wait for the runspace count to reach zero
        if ($LogProgress)
        {
            Write-Information "Waiting for remainder of runspaces to finish"
        }
        Write-Verbose "Waiting for remainder of runspaces to finish"
        $runspaces = (Wait-NetScanCompletedRunspaces -Runspaces $runspaces -LowWatermark 0 -ProcessScript $processScript).Runspaces

        # Close off the runspace pool
        $pool.Close()
        $pool.Dispose()

        # Generate an array of the systems and state
        $results = $connectionState.Keys | ForEach-Object {
            $connectionState[$_]
        }

        # Exclude systems that are unavailable, if specified
        if ($ExcludeUnavailable)
        {
            $results = $results | Where-Object {$_.Available -eq $true}
        }

        # Output results
        $results
    }
}

Function Wait-NetScanCompletedRunspaces
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [System.Collections.Generic.List[PSCustomObject]]$Runspaces,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$LowWaterMark,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ScriptBlock]$ProcessScript
    )

    process
    {
        $working = $Runspaces

        # Process completed tasks until the low water mark is reached
        while (($working | Measure-Object).Count -gt $LowWaterMark)
        {
            # Separate runspaces in to completed and non-completed
            # Don't use Where-Object here to avoid checking IsCompleted twice, which
            # may change between checks.
            # This process only performs the IsCompleted check once, which is more reliable
            # when processes are running concurrently.
            $tempList = New-Object System.Collections.Generic.List[PSCustomObject]
            $completeList = New-Object System.Collections.Generic.List[PSCustomObject]
            $working | ForEach-Object {
                if ($_.Status.IsCompleted)
                {
                    $completeList.Add($_)
                } else {
                    $tempList.Add($_)
                }
            }
            $working = $tempList

            # Display diagnostic information on completed runspaces
            $completeCount = ($completeList | Measure-Object).Count
            if ($completeCount -gt 0)
            {
                Write-Verbose "Found $completeCount runspaces to finalise"
            }

            # Process completed runspaces
            $completeList | ForEach-Object {
                $runspace = $_

                $result = $null
                try {
                    $result = $runspace.Runspace.EndInvoke($runspace.Status)

                    try {
                        # Call supplied script block with result of run
                        Invoke-Command -ScriptBlock $ProcessScript -ArgumentList $result | Out-Null
                    } catch {
                        Write-Warning "Error during call of processing script: $_"
                    }
                } catch {
                    Write-Warning "Error reading return from runspace job: $_"
                }

                $runspace.Runspace.Dispose()
                $runspace.Status = $null
            }

            Start-Sleep -Seconds 1
        }

        [PSCustomObject]@{
            Runspaces = $working
        }
    }
}

<#
#>
Function Test-NetScanValidConfig
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Config
    )

    process
    {
        "Name", "RangeStart", "RangeEnd" | ForEach-Object {
            $prop = $_
            if (($config | Get-Member).Name -notcontains $prop -or [string]::IsNullOrEmpty($config.$prop))
            {
                Write-Error "Missing $prop in configuration"
            }
        }
    }
}

<#
#>
Function Test-NetScanRangeFromConfig
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigPath
    )

    # Read configuration from file
    $entries = $null
    try {
        $entries = Get-Content -Encoding UTF8 $ConfigPath | ConvertFrom-Json -Depth 3
        $entries | ForEach-Object { Test-NetScanValidConfig -Config $_ }
    } catch {
        Write-Information "Failed to import configuration: $_"
        throw $_
    }

    # Iterate through each configuration entry
    $ranges = $entries | ForEach-Object {
        $scanParams = @{
            Name = $_.Name
            RangeStart = $_.RangeStart
            RangeEnd = $_.RangeEnd
        }

        if (($_ | Get-Member).Name -contains "Ping")
        {
            $scanParams["Ping"] = $_.Ping
        }

        if (($_ | Get-Member).Name -contains "TcpPorts")
        {
            $scanParams["TcpPorts"] = $_.TcpPorts
        }

        New-NetScanRange @scanParams
    }

    # Perform scan using the scan ranges
    Test-NetScanRangeConnectivity -Ranges $ranges -LogProgress
}

<#
#>
Function Invoke-NetScanService
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfigPath,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$Iterations = 1,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Start", "Finish")]
        [string]$WaitFrom = "Start",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$WaitSeconds = 0,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$LogPath = "",

        [Parameter(Mandatory=$false)]
        [int]$RotateSizeKB = 128,

        [Parameter(Mandatory=$false)]
        [int]$PreserveCount = 5,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    process
    {
        # Service command block
        $block = {
            $results = Test-NetScanRangeFromConfig -ConfigPath $ConfigPath

            $ranges = $results | ForEach-Object { $_.Range } | Select-Object -Unique
            foreach ($range in $ranges)
            {
                $outputFile = [System.IO.Path]::Combine($OutputPath, $range)
                $results | Where-Object { $_.Range -eq $range } | Export-CSV -NoTypeInformation -Path $outputFile
            }
        }

        # Build service parameters
        $serviceParams = @{
            ScriptBlock = $block
            Iterations = $Iterations
            WaitFrom = $WaitFrom
            WaitSeconds = $WaitSeconds
            LogPath = $LogPath
            RotateSizeKB = $RotateSizeKB
            PreserveCount = $PreserveCount
        }

        # Actual service invocation
        Invoke-ServiceRun @serviceParams
    }
}
