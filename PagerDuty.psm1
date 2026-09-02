<#
    .NAME
        Send-PagerDutyAlert
    .VERSION
        1.0.0
    .AUTHOR
        Erik Meyer
    .SYNOPSIS
        Sends an event to the PagerDuty Events API v2.
    .DESCRIPTION
        This function can be used from scripts or modules to trigger
        alerts in PagerDuty using the Events API v2.

        Typical usage:
            Send-PagerDutyAlert -EndPoint 'https://events.pagerduty.com/v2/enqueue' `
                                -Token '<ROUTING_KEY>' `
                                -Summary 'Something broke' `
                                -Source 'my-app' `
                                -Severity 'error'
#>
function Send-PagerDutyEvent {
    [CmdletBinding()]
    param(
        # PagerDuty Events API v2 endpoint, usually:
        # https://events.pagerduty.com/v2/enqueue
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EndPoint,

        # Routing key (integration key) from PagerDuty service integration
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Token,

        # "trigger", "acknowledge" or "resolve"
        [Parameter(Mandatory = $true)]
        [ValidateSet('trigger', 'acknowledge', 'resolve')]
        [string]$EventAction,

        # Short description of the incident
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Summary,

        # Where this event is coming from (hostname, service, system name, etc.)
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,

        # PagerDuty severities: info, warning, error, critical
        [Parameter(Mandatory = $false)]
        [ValidateSet('info', 'warning', 'error', 'critical')]
        [string]$Severity = 'error',

        # Optional dedup key to correlate trigger/ack/resolve events
        [Parameter(Mandatory = $false)]
        [string]$DedupKey,

        # Optional component, group, and class fields
        [Parameter(Mandatory = $false)]
        [string]$Component,

        [Parameter(Mandatory = $false)]
        [string]$Group,

        [Parameter(Mandatory = $false)]
        [string]$Class,

        # Optional timestamp; if not provided we’ll use now in UTC
        [Parameter(Mandatory = $false)]
        [datetime]$TimeStamp,

        # Arbitrary custom details to add to payload.custom_details
        # e.g. @{ JobName = 'XYZ'; Server = 'ABC01'; ErrorCode = 500 }
        [Parameter(Mandatory = $false)]
        [hashtable]$CustomDetails,

        # Optional image URLs
        [Parameter(Mandatory = $false)]
        [string[]]$ImageUrls,

        # Optional URL to link back to (e.g. runbook, dashboard, ticket)
        [Parameter(Mandatory = $false)]
        [string]$LinkHref,

        [Parameter(Mandatory = $false)]
        [string]$LinkText = 'More details'
    )

    begin {
        # Build headers – Events v2 uses Content-Type application/json
        $headers = @{
            'Content-Type' = 'application/json'
        }

        if (-not $TimeStamp) {
            $TimeStamp = [datetime]::UtcNow
        }

        # Base body
        $body = @{
            routing_key  = $Token
            event_action = $EventAction
        }

        if ($DedupKey) {
            $body.dedup_key = $DedupKey
        }

        # Payload is only required for "trigger" events.
        if ($EventAction -eq 'trigger') {
            $payload = @{
                summary   = $Summary
                source    = $Source
                severity  = $Severity
                timestamp = $TimeStamp.ToString("o")  # ISO 8601
            }

            if ($Component) { $payload.component = $Component }
            if ($Group)     { $payload.group     = $Group }
            if ($Class)     { $payload.class     = $Class }

            if ($CustomDetails) {
                $payload.custom_details = $CustomDetails
            }

            $body.payload = $payload
        }
        else {
            # For ack/resolve, PagerDuty only needs routing_key + event_action + dedup_key
            if (-not $DedupKey) {
                throw "EventAction '$EventAction' requires -DedupKey to correlate with a triggered incident."
            }
        }

        # Optional images
        if ($ImageUrls -and $ImageUrls.Count -gt 0) {
            $images = @()
            foreach ($url in $ImageUrls) {
                if (-not [string]::IsNullOrWhiteSpace($url)) {
                    $images += @{
                        src = $url
                    }
                }
            }
            if ($images.Count -gt 0) {
                $body.images = $images
            }
        }

        # Optional link
        if ($LinkHref) {
            $body.links = @(
                @{
                    href = $LinkHref
                    text = $LinkText
                }
            )
        }

        $jsonBody = $body | ConvertTo-Json -Depth 10
    }

    process {
        try {
            Write-Verbose "Sending PagerDuty event to $EndPoint"
            Write-Verbose "Request body: $jsonBody"

            $response = Invoke-RestMethod -Method Post -Uri $EndPoint -Headers $headers -Body $jsonBody

            return $response
        }
        catch {
            Write-Error "Failed to send PagerDuty event: $($_.Exception.Message)"
            # Optionally rethrow if you want calling code to handle it:
            # throw
        }
    }
}

function Get-PDOpenIncidents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApiKey,

        [Parameter(Mandatory)]
        [string]$ServiceId
    )

    $Endpoint = "https://api.pagerduty.com/incidents"
    $headers = @{
        'Authorization' = "Token token=$ApiKey"
        'Accept'        = 'application/vnd.pagerduty+json;version=2'
    }

    # include[]=alerts is the key part here
    $query = @(
        "service_ids[]=$ServiceId"
        "statuses[]=triggered"
        "statuses[]=acknowledged"
        "limit=50"
        "include[]=alerts"
    ) -join '&'

    $uri = "$Endpoint`?$query"

    $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET

    $response.incidents | ForEach-Object {
        $dedup = $null
        if ($_.alerts -and $_.alerts.Count -gt 0) {
            # usually first alert is fine, but you can loop if needed
            $dedup = $_.alerts[0].dedup_key
        }

        $created = [datetime]$_.created_at
        $created_local = $created.ToLocalTime()
        $ageHours = (New-TimeSpan -Start $created -End (Get-Date).ToUniversalTime()).TotalHours

        [pscustomobject]@{
            IncidentNumber = $_.incident_number
            Status         = $_.status
            Summary        = $_.summary
            CreatedAt      = $created
            Local_time     = $created_local
            AgeHours       = [math]::Round($ageHours, 2)
            DedupKey       = $dedup
            Raw            = $_
        }
    }
}

[Reflection.Assembly]::LoadWithPartialName("System.Security")
#################
# This function is to Encrypt A String.
# $string is the string to encrypt, $passphrase is a second security "password" that has to be passed to decrypt.
# $salt is used during the generation of the crypto password to prevent password guessing.
# $init is used to compute the crypto hash -- a checksum of the encryption
#################
function invoke-EncryptString($String, $Passphrase, $salt="SaltCrypto", $init="IV_Password", [switch]$arrayOutput)
{
	# Create a COM Object for RijndaelManaged Cryptography
	$r = new-Object System.Security.Cryptography.RijndaelManaged
	# Convert the Passphrase to UTF8 Bytes
	$pass = [Text.Encoding]::UTF8.GetBytes($Passphrase)
	# Convert the Salt to UTF Bytes
	$salt = [Text.Encoding]::UTF8.GetBytes($salt)

	# Create the Encryption Key using the passphrase, salt and SHA1 algorithm at 256 bits
	$r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8
	# Create the Intersecting Vector Cryptology Hash with the init
	$r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15]
	
	# Starts the New Encryption using the Key and IV   
	$c = $r.CreateEncryptor()
	# Creates a MemoryStream to do the encryption in
	$ms = new-Object IO.MemoryStream
	# Creates the new Cryptology Stream --> Outputs to $MS or Memory Stream
	$cs = new-Object Security.Cryptography.CryptoStream $ms,$c,"Write"
	# Starts the new Cryptology Stream
	$sw = new-Object IO.StreamWriter $cs
	# Writes the string in the Cryptology Stream
	$sw.Write($String)
	# Stops the stream writer
	$sw.Close()
	# Stops the Cryptology Stream
	$cs.Close()
	# Stops writing to Memory
	$ms.Close()
	# Clears the IV and HASH from memory to prevent memory read attacks
	$r.Clear()
	# Takes the MemoryStream and puts it to an array
	[byte[]]$result = $ms.ToArray()
	# Converts the array from Base 64 to a string and returns
	return [Convert]::ToBase64String($result)
}

function invoke-DecryptString($Encrypted, $Passphrase, $salt="SaltCrypto", $init="IV_Password")
{
	# If the value in the Encrypted is a string, convert it to Base64
	if($Encrypted -is [string]){
		$Encrypted = [Convert]::FromBase64String($Encrypted)
   	}

	# Create a COM Object for RijndaelManaged Cryptography
	$r = new-Object System.Security.Cryptography.RijndaelManaged
	# Convert the Passphrase to UTF8 Bytes
	$pass = [Text.Encoding]::UTF8.GetBytes($Passphrase)
	# Convert the Salt to UTF Bytes
	$salt = [Text.Encoding]::UTF8.GetBytes($salt)

	# Create the Encryption Key using the passphrase, salt and SHA1 algorithm at 256 bits
	$r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8
	# Create the Intersecting Vector Cryptology Hash with the init
	$r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15]


	# Create a new Decryptor
	$d = $r.CreateDecryptor()
	# Create a New memory stream with the encrypted value.
	$ms = new-Object IO.MemoryStream @(,$Encrypted)
	# Read the new memory stream and read it in the cryptology stream
	$cs = new-Object Security.Cryptography.CryptoStream $ms,$d,"Read"
	# Read the new decrypted stream
	$sr = new-Object IO.StreamReader $cs
	# Return from the function the stream
	Write-Output $sr.ReadToEnd()
	# Stops the stream	
	$sr.Close()
	# Stops the crypology stream
	$cs.Close()
	# Stops the memory stream
	$ms.Close()
	# Clears the RijndaelManaged Cryptology IV and Key
	$r.Clear()
}

function Get-IncomingFileStatus {
    param(
        [string[]]$ExpectedExtensions,
        [hashtable]$Thresholds,
        [string[]]$Paths
    )

    $now = Get-Date

    # Pull all files from all paths
    $fileList = foreach ($path in $paths) {
        Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
    }

    # Group and pick the latest file for each extension
    $filesByExt = $fileList |
        Group-Object { $_.Extension.TrimStart('.').ToUpper() } |
        ForEach-Object {
            $ext        = $_.Name
            $latestFile = $_.Group | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            [PSCustomObject]@{
                Extension  = $ext
                LatestFile = $latestFile
            }
        } | Group-Object Extension -AsHashTable -AsString

    # Build a result row for each expected extension
    $result = foreach ($ext in $ExpectedExtensions) {

        $upperExt = $ext.ToUpper()

        if (-not $filesByExt.ContainsKey($upperExt)) {
            [PSCustomObject]@{
                Extension     = $upperExt
                Status        = 'MISSING'
                LatestFile    = $null
                LastWriteTime = $null
                Age           = $null
                Threshold     = $Thresholds[$upperExt]
            }
            continue
        }

        $latestFile = $filesByExt[$upperExt].LatestFile
        $age        = $now - $latestFile.LastWriteTime
        $threshold  = $Thresholds[$upperExt]

        $status = if ($threshold -and $age -le $threshold) { 'OK' } else { 'STALE' }

        [PSCustomObject]@{
            Extension     = $upperExt
            Status        = $status
            LatestFile    = $latestFile.FullName
            LastWriteTime = $latestFile.LastWriteTime
            Age           = $age          # keep as TimeSpan, format later if needed
            Threshold     = $threshold    # also TimeSpan
        }
    }

    return $result
}


# SIG # Begin signature block
# MIIb1AYJKoZIhvcNAQcCoIIbxTCCG8ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5TNo8JFpbjqqhhUFa2Xsue55
# ucegghZEMIIDBjCCAe6gAwIBAgIQEBhQPUc10ahAl/Rc6gVKqzANBgkqhkiG9w0B
# AQsFADAbMRkwFwYDVQQDDBBTT1QgQXV0aGVudGljb2RlMB4XDTI1MDMyNzE4NDUy
# MVoXDTI2MDMyNzE5MDUyMVowGzEZMBcGA1UEAwwQU09UIEF1dGhlbnRpY29kZTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN3sN1zCeitPV5zENSgiiTg/
# jr58n5xmfiVwQ9JXphYC3Wk3a/bQ/cIhdokERjvyXALoYD+x43Hzfa6IENBrao5B
# 434CQ7EtuX8fM+MVLwER0SUdBcaGkV4ITif74ztVERTYNk/f6mBxj5gYhkN6jOgm
# I9SSK4ZNGVarT6ZiMxDhZ1D0SeI2bgcNOAfk5DuQQ0SjZxYSfaF5BO/b0c+FMMPj
# QzhAGhZOxn1asf3kGmZpqSGGBPjlkZZCTlBsnfovR5UrhK2kT3QXjUsaSNwWj19H
# TXggWjzIr0chkVSFOuDPKQEDzjd60EVGl0BDxH/SuYdfPhWfa1ogHIbdad/vEzUC
# AwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0G
# A1UdDgQWBBSI06UD9MDTyWYS6SpTz1Xg6SxlBjANBgkqhkiG9w0BAQsFAAOCAQEA
# Ejm/GdMhy2Lm4W3WHa9tXREv0QK2HB4fcE3osMX1vjMuox+GPk43xXomaTd07CFf
# XitJutKuhB731F0XzOHdBpabQaFd8yhvXtOfN2RMvLoQxrUl541HAw3F7ZBq3THZ
# LDjDyciTj8fkjtjZsnIO42oUQ5Ip+/OsGn9KDxfek6Ja8Y6JLUNEjIYokWgrX5qQ
# rTsFzPNThV3UtYeNLFxPm5dLClwAbQ6Sn1G9tn/AHYeuqqgMVodbrvSbmRrthzlo
# 3G8Mj8cKg1FYBfLiyCzy3+/ezbO5QsE9eBmT9JVpq97IcaLVCcTRT0HfxwU3SKkb
# 1TIZ9v7laduQP8LFI7eZezCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFow
# DQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNl
# cnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIz
# NTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3Rl
# ZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2je
# u+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bG
# l20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBE
# EC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/N
# rDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A
# 2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8
# IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfB
# aYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaa
# RBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZi
# fvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXe
# eqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g
# /KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB
# /wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQY
# MBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1Ud
# IAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22
# Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih
# 9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYD
# E3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c
# 2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88n
# q2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5
# lDCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBU
# cnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysdduj
# Rmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S
# 9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+
# 42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg6
# 2IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21
# Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8
# y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQ
# NfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gao
# u30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6g
# qztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJD
# psZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D
# 8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEA
# MB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5k
# aWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSG
# Mmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQu
# Y3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0B
# AQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6F
# TGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mC
# efSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57m
# QfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9
# ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dB
# wp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdq
# fMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2
# puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAO
# k5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL
# 0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBun
# vAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE
# 1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNI
# QTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHf
# yjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPx
# NyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpk
# BaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFv
# ZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1zn
# OM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8f
# cpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ah
# fvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUD
# y9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9
# w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTn
# nkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKa
# cJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7
# /PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ
# 7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYI
# KwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
# LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEu
# Y3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0Ex
# LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcN
# AQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF
# 0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKq
# dT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbU
# UO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTe
# HihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG
# 7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NB
# qycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6
# +iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaA
# yBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyP
# ehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3F
# NwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIE+jCC
# BPYCAQEwLzAbMRkwFwYDVQQDDBBTT1QgQXV0aGVudGljb2RlAhAQGFA9RzXRqECX
# 9FzqBUqrMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRNLYdtNjjZv93XnoXBFnrlk67SJDANBgkq
# hkiG9w0BAQEFAASCAQDG8zsFZU7IqnJjLHQy+CktN4+mJySIRjlYuQkdeBDOChxD
# xx1X3KW70ZuH2etsfGazIS7KV3FY6cggb/jSfqo95j4XE00wktl61N/LUZx1I6zV
# pkKvuPL6ubecqwTo/0MeOZvDbwX2TIgQ8EEyobYZSA8J21YGpgIlTNx3cgo2wr/m
# apT1B9tTR2RVrBDivS1vdzaa7pJAWth4vo84kBSdlAuCWLXnrte/C3t7tz4IebEn
# c6xMHKzD4ODXWPo57x/tMlvKu6VZCxCG6bFswpUFDO7GRPe3cfmGW6MmT7SpOB2c
# uFIntwQRYReCH6jQ8i3BEGie6x5RzZbAqkx8P4/poYIDJjCCAyIGCSqGSIb3DQEJ
# BjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglg
# hkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcN
# AQkFMQ8XDTI1MTIwMjE5MjQzMlowLwYJKoZIhvcNAQkEMSIEIMWfoC27OvFisbWU
# MN0E0pr5C5RHjRf/As8JQ/OsGsVTMA0GCSqGSIb3DQEBAQUABIICACDkLu8iQzgV
# aSqbZYUgluycm4daHqyyvlILxArttHEsmSlqs7Hh+5ko7Pwy4gSDoh9auhhmVVzB
# OiHQcoZNnuG6lwuL3M7j60R2oFrY+fz+q6ZCkEW0tw0hWh40v9HgFToseA+egLIt
# njLOYB1EIVZfWXbrPLFloljY4aTaMLAm6KErZdnABKxfrfuFJpmNsC9R2VCDGdH+
# pJhOPBi+gD00UjwhJsFskreTkImFDVrGR1nWSCvXDQOzpY+pmAxOCUMciq1+y9oj
# OZqF7Ofe73z2XH9HttwRULUe4Dk8ZY8jhMtlHciziYL9QEVqyXw8FB7djhbJtEmh
# d3CywtvjVX3/a5qO8pdWwznp2+/hYsOm6XI2x2QU2gSLCKlLuxmQCdvLpCFeGPgT
# 9T0FVxapIS10oN6hqzREtlo0WwnzFDDL//v303T/SJJl9eEvuzfvu3s+mk/ovqeR
# blPi6l6ecE+dKIUHVVBEFuYjxPa8Unrz3bGm4dS11zhor0cSKTjfydPx4r7ggv3K
# H0WZn4Xc8ZCg73v9YX4Ws3E6MSODfDOH9TtBcoQ6FHMLKeRaC9jRaYB112VxB3DD
# nnKQ3nmnw38xdRhAzl/hQ/ehOeOKVR7cxvd4P2ntqO6Vh4lDPKWE5c18vXUobWzk
# W5qNTFy6w9IUJMSdtA3AgONf4DQxuMsn
# SIG # End signature block
