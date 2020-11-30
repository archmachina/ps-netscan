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
Function Convert-BigIntegerToIPAddress
{
    [CmdletBinding()]
    [OutputType([System.Net.IPAddress])]
    param(
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [System.Numerics.BigInteger]$Address,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateSet(4,16)]
        [int]$Length
    )

    process
    {
        # Create an empty array to hold the BigInteger
        $target = [array]::CreateInstance([byte], $Length)

        # Validate can fit in relevant address family
        $bytes = $Address.ToByteArray()
        if ($bytes.Length -gt $Length)
        {
            Write-Error "BigInteger is too large to fit address family"
        }

        # Copy BigInteger over array and reverse if we are little endian
        [array]::Copy($bytes, $target, $bytes.Length)
        if ([BitConverter]::IsLittleEndian)
        {
            [array]::Reverse($bytes)
        }

        # Create a new IPAddress based on the byte array and output
        [IPAddress]::New($bytes)
    }
}

<#
#>
Function Convert-IPAddressToBigInteger
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [IPAddress]$IPAddress
    )

    process
    {
        $bytes = $IPAddress.GetAddressBytes()

        # Convert byte ranges, if we're little endian
        if ([BitConverter]::IsLittleEndian)
        {
            [Array]::Reverse($bytes)
        }

        # Create the BigInteger
        $address = [System.Numerics.BigInteger]::New($bytes)

        # Determine the address length
        $addressLength = 0
        switch ($IPAddress.AddressFamily)
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

        [PSCustomObject]@{
            Length = $addressLength
            Address = $address
        }
    }
}

<#
#>
Function New-NetScanCollection
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
    )

    process
    {
        [PSCustomObject]@{
            Processing = New-Object 'System.Collections.Generic.List[HashTable]'
            IPv4Systems = @{}
            IPv6Systems = @{}
            Ranges = @{}
        }
    }
}

<#
#>
Function Test-NetScanValidCollection
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection
    )

    process
    {
        if (($Collection | Get-Member).Name -notcontains "Processing" -or
            $Collection.Processing.GetType() -ne ([System.Collections.Generic.List[HashTable]]))
        {
            Write-Error "Invalid or missing Processing parameter in collection"
        }

        if (($Collection | Get-Member).Name -notcontains "IPv4Systems" -or
            $Collection.IPv4Systems.GetType() -ne ([HashTable]))
        {
            Write-Error "Invalid or missing IPv4Systems parameter in collection"
        }

        if (($Collection | Get-Member).Name -notcontains "IPv6Systems" -or
            $Collection.IPv6Systems.GetType() -ne ([HashTable]))
        {
            Write-Error "Invalid or missing IPv6Systems parameter in collection"
        }

        if (($Collection | Get-Member).Name -notcontains "Ranges" -or
            $Collection.Ranges.GetType() -ne ([HashTable]))
        {
            Write-Error "Invalid or missing Ranges parameter in collection"
        }
    }
}

<#
#>
Function Add-NetScanSystemEntry
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [IPAddress]$IPAddress,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [HashTable]$Properties = @{},

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$PropertyPrefix = ""
    )

    process
    {
        # Verify the collection
        Test-NetScanValidCollection -Collection $Collection

        # Check that we have a supported address family
        switch ($IPAddress.AddressFamily)
        {
            "InterNetworkV6" {
                $systems = $Collection.IPv6Systems
                break
            }

            "InterNetwork" {
                $systems = $Collection.IPv4Systems
                break
            }

            default { Write-Error "Unsupported address family type" }
        }

        # Generate a BigInteger from the address for indexing
        $addressInt = Convert-IPAddressToBigInteger -IPAddress $IPAddress

        # Add the entry, if it doesn't already exist
        # Include the 'IPAddress' object in the entry
        if (!$systems.ContainsKey($addressInt.Address))
        {
            $systems[$addressInt.Address] = [ordered]@{
                Address = $IPAddress
            }
        }

        $system = $systems[$addressInt.Address]

        # Add any properties that are defined for this system
        foreach ($key in $Properties.Keys)
        {
            $newKey = ("{0}{1}" -f $PropertyPrefix, $key)

            # Filter out any reserved property names and add anything else
            switch ($newKey)
            {
                "Address" { break }
                "Error" { break }
                default { $system[$newKey] = $Properties[$key] }
            }
        }

        # Pass the HashTable on in the pipeline
        $system
    }
}

<#
#>
Function Get-NetScanRanges
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection
    )

    process
    {
        $Collection.Ranges.Keys | ForEach-Object {
            $Collection.Ranges[$_]
        }
    }
}

<#
#>
Function Add-NetScanRange
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection = (New-NetScanCollection),

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [IPAddress]$RangeStart,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [IPAddress]$RangeEnd,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [HashTable]$Properties = @{},

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$PropertyPrefix = ""
    )

    process
    {
        # Verify the collection
        Test-NetScanValidCollection -Collection $Collection

        # Convert and verify the start and end addresses
        $rangeStartInt = Convert-IPAddressToBigInteger -IPAddress $RangeStart
        $rangeEndInt = Convert-IPAddressToBigInteger -IPAddress $RangeEnd

        # Ensure both addresses are the same family type
        if ($RangeStart.AddressFamily -ne $RangeEnd.AddressFamily)
        {
            Write-Error "Begin and end address are different address families"
        }

        # Make sure the begin address is less than or equal to the end address
        if ($rangeStartInt.Address.CompareTo($rangeEndInt.Address) -gt 0)
        {
            Write-Error "Start address is greater than the end address"
        }

        # Iterate through the addresses using BigIntegers
        $current = $rangeStartInt.Address
        while ($current.CompareTo($rangeEndInt.Address) -le 0)
        {
            # Convert index/BigInteger to IPAddress
            $ipAddress = Convert-BigIntegerToIPAddress -Address $current -Length $rangeStartInt.Length

            # Add the IPAddress to the collection
            Add-NetScanAddress -Collection $Collection -IPAddress $ipAddress -Properties $Properties -PropertyPrefix $PropertyPrefix | Out-Null

            $current = [System.Numerics.BigInteger]::Add($current, 1)
        }

        # Add the range to the collection, if a name has been supplied
        if ($PSBoundParameters.Keys -contains "Name")
        {
            $Collection.Ranges[$Name] = [PSCustomObject]@{
                Name = $Name
                RangeStart = $RangeStart
                RangeEnd = $RangeEnd
            }
        }

        # Pass collection on in pipeline
        $Collection
    }
}

<#
#>
Function Select-NetScanSystems
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding(DefaultParameterSetName="All")]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline,ParameterSetName="All")]
        [Parameter(Mandatory=$true,ValueFromPipeline,ParameterSetName="Range")]
        [ValidateNotNull()]
        [PSCustomObject]$Collection,

        [Parameter(Mandatory=$true,ParameterSetName="All")]
        [switch]$All,

        [Parameter(Mandatory=$true,ParameterSetName="Range")]
        [ValidateNotNull()]
        [IPAddress]$RangeStart,

        [Parameter(Mandatory=$true,ParameterSetName="Range")]
        [ValidateNotNull()]
        [IPAddress]$RangeEnd
    )

    process
    {
        # Verify the collection
        Test-NetScanValidCollection -Collection $Collection

        switch ($PSCmdlet.ParameterSetName)
        {
            "Range" {
                # Convert and verify the start and end addresses
                $rangeStartInt = Convert-IPAddressToBigInteger -IPAddress $RangeStart
                $rangeEndInt = Convert-IPAddressToBigInteger -IPAddress $RangeEnd

                # Ensure both addresses are the same family type
                if ($RangeStart.AddressFamily -ne $RangeEnd.AddressFamily)
                {
                    Write-Error "Begin and end address are different address families"
                }

                # Make sure the begin address is less than or equal to the end address
                if ($rangeStartInt.Address.CompareTo($rangeEndInt.Address) -gt 0)
                {
                    Write-Error "Start address is greater than the end address"
                }

                # Check that we have a supported address family
                $systems = $null
                switch ($RangeStart.AddressFamily)
                {
                    "InterNetworkV6" {
                        $systems = $Collection.IPv6Systems
                        break
                    }

                    "InterNetwork" {
                        $systems = $Collection.IPv4Systems
                        break
                    }

                    default { Write-Error "Unsupported address family type" }
                }

                # Iterate through the addresses using BigIntegers
                $matchSystems = $systems.Keys |
                    Where-Object { $_.CompareTo($rangeStartInt.Address) -ge 0 -and $_.CompareTo($rangeEndInt.Address) -le 0} |
                    ForEach-Object {
                        [PSCustomObject]($systems[$_])
                    }

                $matchSystems
                break
            }

            "All" {
                @($Collection.IPv4Systems, $Collection.IPv6Systems) | ForEach-Object {
                    $_.Values | ForEach-Object {
                        [PSCustomObject]$_
                    }
                }
                break
            }

            default { Write-Error "Unknown ParameterSetName" }
        }

    }
}

<#
#>
Function Add-NetScanAddress
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection = (New-NetScanCollection),

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [IPAddress]$IPAddress,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [HashTable]$Properties = @{},

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$PropertyPrefix = ""
    )

    process
    {
        Add-NetScanSystemEntry -Collection $Collection -IPAddress $IPAddress -Properties $Properties -PropertyPrefix $PropertyPrefix | Out-Null

        # Pass collection on in pipeline
        $Collection
    }
}

<#
#>
Function Add-NetScanPingCheck
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection = (New-NetScanCollection)
    )

    process
    {
        # Verify the collection
        Test-NetScanValidCollection -Collection $Collection

        # Add the ping check script to the processing list
        $Collection.Processing.Add(@{
            Name = "Ping"
            Script = {
                param(
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                    [HashTable]$System
                )

                $ErrorActionPreference = "Stop"
                Set-StrictMode -Version 2

                $address = $System["Address"]

                $status = @{
                    Address = $address
                    Ping = $false
                    Error = ""
                }

                try {
                    # Ping the remote host
                    $pingRequest = New-Object System.Net.NetworkInformation.Ping
                    $total = 4

                    # Send a series of echo requests to the target. Stop on first success.
                    for ($count = 0; $count -lt $total ; $count++) {
                        $reply = $pingRequest.Send($Address)
                        if ($reply.Status -eq "Success")
                        {
                            $status["Ping"] = $true
                            break
                        }

                        Start-Sleep 1
                    }
                } catch {
                    $status["Error"] = $_.ToString()
                }

                $status
            }
        })

        # Pass the collection on in the pipeline
        $Collection
    }
}

<#
#>
Function Add-NetScanTcpCheck
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection = (New-NetScanCollection),

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int[]]$Ports = @(80, 443, 445, 22, 3389)
    )

    process
    {
        # Verify the collection
        Test-NetScanValidCollection -Collection $Collection

        $Collection.Processing.Add(@{
            Name = "Tcp"
            Args = @{
                Ports = $Ports
            }
            Script = {
                param(
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                    [HashTable]$System,

                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                    [int[]]$Ports
                )

                $ErrorActionPreference = "Stop"
                Set-StrictMode -Version 2

                $address = $System["Address"]

                $status = @{
                    Address = $address
                    TcpPorts = New-Object System.Collections.Generic.List[int]
                    Error = ""
                }

                foreach ($port in $Ports) {
                    # Check this tcp port on the remote host
                    $client = [System.Net.Sockets.TCPClient]::New()
                    try {
                        # We don't care about the result of the task, just whether the client
                        # became connected within the timeout period
                        $client.ConnectAsync($address, $port) | Out-Null

                        for ($count = 0; $count -lt 5 ; $count++)
                        {
                            if ($client.Connected)
                            {
                                $status["TcpPorts"].Add($port)
                                break
                            }

                            Start-Sleep -Seconds 1
                        }
                    } catch {
                        # Ignore error here. Either way, it is unavailable.
                        $status["Error"] = $_
                    }

                    try {
                        $client.Close()
                        $client.Dispose()
                    } catch {
                        $status["Error"] = $_.ToString()
                        break
                    }
                }

                $status
            }
        })

        # Pass collection on in pipeline
        $Collection
    }
}

<#
#>
Function Add-NetScanReverseLookup
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection = (New-NetScanCollection)
    )

    process
    {
        # Verify the collection
        Test-NetScanValidCollection -Collection $Collection

        # Add processing script to processing list
        $Collection.Processing.Add(@{
            Name = "ReverseLookup"
            Script = {
                param(
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                    [HashTable]$System
                )

                $ErrorActionPreference = "Stop"
                Set-StrictMode -Version 2

                $address = $System["Address"]

                $status = @{
                    Address = $address
                    ReverseHostname = ""
                    Error = ""
                }

                try {
                    $resolve = [System.Net.Dns]::GetHostByAddress($address)
                    if (![string]::IsNullOrEmpty($resolve.HostName))
                    {
                        $status["ReverseHostname"] = $resolve.HostName
                    }
                } catch {
                }

                $status
            }
        })

        # Pass collection on in pipeline
        $Collection
    }
}

<#
#>
Function Update-NetScanConnectivityInfo
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$Collection,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$ConcurrentChecks = 32,

        [Parameter(Mandatory=$false)]
        [switch]$LogProgress = $false
    )

    process
    {
        # Create runspace environment
        Write-Verbose "Creating runspace pool"
        $pool = [RunSpaceFactory]::CreateRunspacePool(1, $ConcurrentChecks)
        if (($pool | Get-Member).Name -contains "ApartmentState")
        {
            $pool.ApartmentState = "MTA"
        }
        $pool.Open()
        $runspaces = New-Object System.Collections.Generic.List[PSCustomObject]

        # Script block for processing completed runspaces
        $processScript = {
            param($result)

            $ErrorActionPreference = "Stop"
            Set-StrictMode -Version 2

            #Write-Host "Received Result: $result"
            #Write-Host ("TargetState eq null: " + ($targetState -eq $null))
            #Write-Host $connectionState.Keys
            #Write-Host ("Connection State contains target: " + ($connectionState.Keys -contains $state.Target))

            #$state = $result | ConvertFrom-Json
            $state = $result
            if ($state.ContainsKey("Error") -and ![string]::IsNullOrEmpty($state["Error"]))
            {
                Write-Warning ("Error during check on address {0}: {1}" -f $state["Address"], $state["Error"])
                return
            }

            # Add/Update the system entry
            Add-NetScanSystemEntry -Collection $Collection -IPAddress $state["Address"] -Properties $state | Out-Null
        }

        foreach ($entry in $Collection.Processing)
        {
            foreach ($systemCollection in @($Collection.IPv4Systems, $Collection.IPv6Systems))
            {
                foreach ($key in $systemCollection.Keys)
                {
                    # Wait for runspace count to reach low water mark before proceeding
                    $runspaces = (Wait-NetScanCompletedRunspaces -Runspaces $runspaces -LowWatermark 300 -ProcessScript $processScript).Runspaces

                    $system = $systemCollection[$key]

                    $script = $entry["Script"]
                    $name = $entry["Name"]

                    Write-Verbose ("Scheduling processing script ({0}) for ({1})" -f $name, $system["Address"])
                    $runspace = [PowerShell]::Create()
                    $runspace.AddScript($script) | Out-Null
                    $runspace.AddParameter("System", ([HashTable]$system).Clone()) | Out-Null
                    if ($entry.ContainsKey("Args"))
                    {
                        foreach ($argName in $entry["Args"].Keys)
                        {
                            $runspace.AddParameter($argName, $entry["Args"][$argName])
                        }
                    }
                    $runspace.RunspacePool = $pool

                    $runspaces.Add([PSCustomObject]@{
                        Runspace = $runspace
                        Status = $runspace.BeginInvoke()
                    })
                }
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

        # Fill all properties across all objects
        Write-Verbose "Determining properties across all objects"
        $properties = $($Collection.IPv4Systems, $Collection.IPv6Systems) | ForEach-Object {
            $_.Values | ForEach-Object { $_.Keys }
        } | Select-Object -Unique

        Write-Information "Properties: $properties"

        $memberAdditions = 0
        $($Collection.IPv4Systems, $Collection.IPv6Systems) | ForEach-Object {
            $_.Values | ForEach-Object {
                foreach ($prop in $properties)
                {
                    if ($_.Keys -notcontains $prop)
                    {
                        $_[$prop] = $null
                        $memberAdditions++
                    }
                }
            }
        }

        Write-Verbose "Filled $memberAdditions properties across objects"

        # Pass collection on in pipeline
        $Collection
    }
}

<#
#>
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
