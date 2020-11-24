<#
#>

########
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

<#
#>
Function Test-NetIPv4RangeConnectivity
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RangeStart,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RangeEnd,

        [Parameter(Mandatory=$false)]
        [switch]$NoPing = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int[]]$TcpPorts = [int[]]@(80, 443, 445, 22, 3389)
    )

    process
    {
        # Validate the begin address
        $beginParsed = [IPAddress]::Parse($RangeStart)
        $beginBytes = $beginParsed.GetAddressBytes()

        # Validate the end address
        $endParsed = [IPAddress]::Parse($RangeEnd)
        $endBytes = $endParsed.GetAddressBytes()

        # Ensure both addresses are the same family type
        if ($beginParsed.AddressFamily -ne $endParsed.AddressFamily)
        {
            Write-Error "Begin and end address are different address families"
            return
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
                return
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
            return
        }

        # Create runspace environment
        Write-Verbose "Creating runspace pool"
        $pool = [RunSpaceFactory]::CreateRunspacePool(1, $Env:NUMBER_OF_PROCESSORS*2)
        $pool.ApartmentState = "MTA"
        $pool.Open()
        $runspaces = @()

        # Script for scanning target
        $script = {
            param(
                [Parameter(Mandatory=$true)]
                [ValidateNotNullOrEmpty()]
                [IPAddress]$Target,

                [Parameter(Mandatory=$true)]
                [switch]$NoPing,

                [Parameter(Mandatory=$true)]
                [ValidateNotNull()]
                [int[]]$TcpPorts
            )

            "Target: $Target"
            "NoPing: $NoPing"
            ("TcpPorts: " + ($TcpPorts -join ","))

            $status = @{
                Target = $Target.ToString()
                Ping = "N/A"
            }

            if (!$NoPing)
            {
                # Ping the remote host
            }

            $TcpPorts | ForEach-Object {
                # Check this TCP port on the remote host
            }

            [PSCustomObject]$status | ConvertTo-Json
        }

        $currentAddress = $beginAddress
        while (($runspaces | Measure-Object).Count -gt 0 -or $currentAddress.CompareTo($endAddress) -le 0)
        {
            # Add additional runspaces
            while ($currentAddress.CompareTo($endAddress) -le 0 -and ($runspaces | Measure-Object).Count -le 10)
            {
                $target = [array]::CreateInstance([byte], $addressLength)
                $bytes = $currentAddress.ToByteArray()
                [array]::Copy($bytes, $target, $bytes.Length)

                if ([BitConverter]::IsLittleEndian)
                {
                    [array]::Reverse($bytes)
                }

                $addr = [IPAddress]::New($bytes)
                Write-Verbose "Scheduling Address: $addr"

                $runspace = [PowerShell]::Create()
                $runspace.AddScript($script) | Out-Null
                $runspace.AddParameter("Target", $addr) | Out-Null
                $runspace.AddParameter("NoPing", $NoPing) | Out-Null
                $runspace.AddParameter("TcpPorts", $TcpPorts) | Out-Null
                $runspace.RunspacePool = $pool

                $runspaces += [PSCustomObject]@{
                    Runspace = $runspace
                    Status = $runspace.BeginInvoke()
                }

                $currentAddress = [System.Numerics.BigInteger]::Add($currentAddress, 1)
            }

            # Separate runspaces in to completed and non-completed runspaces
            $tempList = @()
            $completeList = @()
            $runspaces | ForEach-Object {
                if ($_.Status.IsCompleted)
                {
                    $completeList += $_
                } else {
                    $tempList += $_
                }
            }
            $runspaces = $tempList

            # Process completed runspaces
            $completeList | ForEach-Object {
                $runspace = $_

                try {
                    $content = $runspace.Runspace.EndInvoke($runspace.Status)
                    Write-Information "Received: $content"
                } catch {
                    Write-Warning "Error reading return from runspace job: $_"
                }

                $runspace.Runspace.Dispose()
                $runspace.Status = $null
            }

            Start-Sleep -Seconds 1
        }

        $pool.Close()
        $pool.Dispose()
    }
}