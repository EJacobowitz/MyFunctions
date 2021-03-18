#I am using this space to create a new function to then add it to the PSTools.ps1 script

<#
.Synopsis
   convert time derived in minutes to an actual time
.DESCRIPTION
   This is to help convert time in minutes from a db or other source into readable time
.EXAMPLE
   convert-mintotime -Min 234
.Example
    [datetime] $localtime = convert-mintotime -Min 234
    This will add current date to the localtime variable, but can then convert or manuipulate returned variable
    $localtime.ToShortTimeString()
    $localtime.ToUniversalTime()
    $localtime.tostring("HH:mm:ss")

#>
function convert-mintotime {
    [CmdletBinding()]
    [Alias()]
    [OutputType([datetime])]
    Param
    (
        #time in minutes input, Number from 0 - 1440 only
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [int]$Min
    )
    Begin {
        Add-Type -AssemblyName PresentationFramework
        [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
    }
    Process {
        if ( ([Microsoft.VisualBasic.Information]::IsNumeric($Min) -eq $true) -and ($Min -ge 0) -and ($Min -le 1440)) {
            $t = New-TimeSpan -Minutes $Min
            $CT = "{0}" -f $t
        }
        Else {
            $CT = 'Time input is out of bounds, must be between 0 and 1440'
        }
    }
    End {
        return $CT
    }

}