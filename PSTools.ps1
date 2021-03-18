#Tools for powershell scripting
#Table of contents:

# Function Name                         Line #
# Encrypt-String                         16
# Decrypt-String                         54
# write-customlog                        106
# Get-PendingRebootStatus                145
# right                                  260
# Send-MailMessage                       284
# Create-DSN                             871
# Listen-Port                            940
# Remove-UserProfile                     995
# Get-PendingReboot                      1147
# start-pause                            1367
# Add-MvaNetFirewallRemoteAdressFilter   1380
# Get-odbcdata                           1445
# Folder Exists                          1516
# Get-NetworkStatistics                  1525
# Uptime                                 1908
# Convert-mintotime                      1977
#--------------------------#

#################
# Powershell Allows The Loading of .NET Assemblies
# Load the Security assembly to use with this script 
#################
[Reflection.Assembly]::LoadWithPartialName("System.Security")

#################
# This function is to Encrypt A String.
# $string is the string to encrypt, $passphrase is a second security "password" that has to be passed to decrypt.
# $salt is used during the generation of the crypto password to prevent password guessing.
# $init is used to compute the crypto hash -- a checksum of the encryption
#################
function Encrypt-String($String, $Passphrase, $salt = "SaltCrypto", $init = "IV_Password", [switch]$arrayOutput) {
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
    $cs = new-Object Security.Cryptography.CryptoStream $ms, $c, "Write"
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

function Decrypt-String($Encrypted, $Passphrase, $salt = "SaltCrypto", $init = "IV_Password") {
    # If the value in the Encrypted is a string, convert it to Base64
    if ($Encrypted -is [string]) {
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
    $ms = new-Object IO.MemoryStream @(, $Encrypted)
    # Read the new memory stream and read it in the cryptology stream
    $cs = new-Object Security.Cryptography.CryptoStream $ms, $d, "Read"
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

# This clears the screen of the output from the loading of the assembly.
Clear-Host
<#
.Synopsis
   Write to event log
.DESCRIPTION
   This cmdlet is to write custom events to the application event log
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>

function write-customlog {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Enter a string to identify the source (Example: -Event_Source "My App")
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        $EventSource,

        #Enter a message to detail the alert
        [Parameter(Mandatory = $true, Position = 1)]
        [String]$EventMessage,

        [Parameter(Mandatory = $true, Position = 2)]
        # Enter a number for the event ID (Example: 9999)
        [int] $EventNum,

        [ValidateSet("Error", "Warning", "Information")][String]$EventType = "Error",

        #Enter the log name
        [ValidateSet("Application", "System", "Security")][String]$eventlogname = "Application" 
    )

    Begin {
    }
    Process {
        if ([system.diagnostics.eventlog]::SourceExists($EventSource) -eq $false ) { New-EventLog -LogName Application -Source $EventSource }
        Write-EventLog -LogName $eventlogname -Source $EventSource -EventID $EventNum -EntryType $EventType -Message $EventMessage
    }
    End {
    }
}

Function Get-PendingRebootStatus {
 
    <#
.Synopsis
    This will check to see if a server or computer has a reboot pending.
    For updated help and examples refer to -Online version.
  
 
.DESCRIPTION
    This will check to see if a server or computer has a reboot pending.
    For updated help and examples refer to -Online version.
 
 
.NOTES  
    Name: Get-PendingRebootStatus
    Author: The Sysadmin Channel
    Version: 1.00
    DateCreated: 2018-Jun-6
    DateUpdated: 2018-Jun-6
 
.LINK
    <a class="vglnk" href="https://thesysadminchannel.com/remotely-check-pending-reboot-status-powershell" rel="nofollow"><span>https</span><span>://</span><span>thesysadminchannel</span><span>.</span><span>com</span><span>/</span><span>remotely</span><span>-</span><span>check</span><span>-</span><span>pending</span><span>-</span><span>reboot</span><span>-</span><span>status</span><span>-</span><span>powershell</span></a> -
 
 
.PARAMETER ComputerName
    By default it will check the local computer.
 
     
    .EXAMPLE
    Get-PendingRebootStatus -ComputerName PAC-DC01, PAC-WIN1001
 
    Description:
    Check the computers PAC-DC01 and PAC-WIN1001 if there are any pending reboots.
 
#>
 
    [CmdletBinding()]
    Param (
        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
 
        [string[]]     $ComputerName = $env:COMPUTERNAME,
 
        [switch]       $ShowErrors
 
    )
 
 
    BEGIN {
        $ErrorsArray = @()
    }
 
    PROCESS {
        foreach ($Computer in $ComputerName) {
            try {
                $PendingReboot = $false
 
 
                $HKLM = [UInt32] "0x80000002"
                $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
 
                if ($WMI_Reg) {
                    if (($WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') { $PendingReboot = $true }
                    if (($WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') { $PendingReboot = $true }
 
                    #Checking for SCCM namespace
                    $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore
                    if ($SCCM_Namespace) {
                        if (([WmiClass]"\\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq 'True') { $PendingReboot = $true }   
                    }
 
 
                    if ($PendingReboot -eq $true) {
                        $Properties = @{ComputerName = $Computer.ToUpper()
                            PendingReboot            = 'True'
                        }
                        $Object = New-Object -TypeName PSObject -Property $Properties | Select-Object ComputerName, PendingReboot
                    }
                    else {
                        $Properties = @{ComputerName = $Computer.ToUpper()
                            PendingReboot            = 'False'
                        }
                        $Object = New-Object -TypeName PSObject -Property $Properties | Select-Object ComputerName, PendingReboot
                    }
                }
                 
            }
            catch {
                $Properties = @{ComputerName = $Computer.ToUpper()
                    PendingReboot            = 'Error'
                }
                $Object = New-Object -TypeName PSObject -Property $Properties | Select-Object ComputerName, PendingReboot
 
                $ErrorMessage = $Computer + " Error: " + $_.Exception.Message
                $ErrorsArray += $ErrorMessage
 
            }
            finally {
                Write-Output $Object
 
                $Object = $null
                $ErrorMessage = $null
                $Properties = $null
                $WMI_Reg = $null
                $SCCM_Namespace = $null
            }
        }
        if ($ShowErrors) {
            Write-Output "`n"
            Write-Output $ErrorsArray
        }
    }
 
    END {}
}

Function right {
    [CmdletBinding()]
 
    Param (
        [Parameter(Position = 0, Mandatory = $True, HelpMessage = "Enter a string of text")]
        [String]$text,
        [Parameter(Mandatory = $True)]
        [Int]$Length
    )
    $startchar = [math]::min($text.length - $Length, $text.length)
    $startchar = [math]::max(0, $startchar)
    $right = $text.SubString($startchar , [math]::min($text.length, $Length))
    $right
}
filter Assert-FolderExists {
    $exists = Test-Path -Path $_ -PathType Container
    if (!$exists) { 
        Write-Warning "$_ did not exist. Folder created."
        $null = New-Item -Path $_ -ItemType Directory 
    }
}
#requires -Version 2.0

function Send-MailMessage {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [Alias('PsPath')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${Attachments},

        [ValidateNotNullOrEmpty()]
        [Collections.HashTable]
        ${InlineAttachments},
        
        [ValidateNotNullOrEmpty()]
        [Net.Mail.MailAddress[]]
        ${Bcc},
    
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Body},
        
        [Alias('BAH')]
        [switch]
        ${BodyAsHtml},
    
        [ValidateNotNullOrEmpty()]
        [Net.Mail.MailAddress[]]
        ${Cc},
    
        [Alias('DNO')]
        [ValidateNotNullOrEmpty()]
        [Net.Mail.DeliveryNotificationOptions]
        ${DeliveryNotificationOption},
    
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Net.Mail.MailAddress]
        ${From},
    
        [Parameter(Mandatory = $true, Position = 3)]
        [Alias('ComputerName')]
        [string]
        ${SmtpServer},
    
        [ValidateNotNullOrEmpty()]
        [Net.Mail.MailPriority]
        ${Priority},
        
        [Parameter(Mandatory = $true, Position = 1)]
        [Alias('sub')]
        [ValidateNotNullOrEmpty()]
        [string]
        ${Subject},
    
        [Parameter(Mandatory = $true, Position = 0)]
        [Net.Mail.MailAddress[]]
        ${To},
    
        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        ${Credential},
    
        [switch]
        ${UseSsl},
    
        [ValidateRange(0, 2147483647)]
        [int]
        ${Port} = 25
    )
    
    begin {
        function FileNameToContentType {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string]
                $FileName
            )

            $mimeMappings = @{
                '.323'         = 'text/h323'
                '.aaf'         = 'application/octet-stream'
                '.aca'         = 'application/octet-stream'
                '.accdb'       = 'application/msaccess'
                '.accde'       = 'application/msaccess'
                '.accdt'       = 'application/msaccess'
                '.acx'         = 'application/internet-property-stream'
                '.afm'         = 'application/octet-stream'
                '.ai'          = 'application/postscript'
                '.aif'         = 'audio/x-aiff'
                '.aifc'        = 'audio/aiff'
                '.aiff'        = 'audio/aiff'
                '.application' = 'application/x-ms-application'
                '.art'         = 'image/x-jg'
                '.asd'         = 'application/octet-stream'
                '.asf'         = 'video/x-ms-asf'
                '.asi'         = 'application/octet-stream'
                '.asm'         = 'text/plain'
                '.asr'         = 'video/x-ms-asf'
                '.asx'         = 'video/x-ms-asf'
                '.atom'        = 'application/atom+xml'
                '.au'          = 'audio/basic'
                '.avi'         = 'video/x-msvideo'
                '.axs'         = 'application/olescript'
                '.bas'         = 'text/plain'
                '.bcpio'       = 'application/x-bcpio'
                '.bin'         = 'application/octet-stream'
                '.bmp'         = 'image/bmp'
                '.c'           = 'text/plain'
                '.cab'         = 'application/octet-stream'
                '.calx'        = 'application/vnd.ms-office.calx'
                '.cat'         = 'application/vnd.ms-pki.seccat'
                '.cdf'         = 'application/x-cdf'
                '.chm'         = 'application/octet-stream'
                '.class'       = 'application/x-java-applet'
                '.clp'         = 'application/x-msclip'
                '.cmx'         = 'image/x-cmx'
                '.cnf'         = 'text/plain'
                '.cod'         = 'image/cis-cod'
                '.cpio'        = 'application/x-cpio'
                '.cpp'         = 'text/plain'
                '.crd'         = 'application/x-mscardfile'
                '.crl'         = 'application/pkix-crl'
                '.crt'         = 'application/x-x509-ca-cert'
                '.csh'         = 'application/x-csh'
                '.css'         = 'text/css'
                '.csv'         = 'application/octet-stream'
                '.cur'         = 'application/octet-stream'
                '.dcr'         = 'application/x-director'
                '.deploy'      = 'application/octet-stream'
                '.der'         = 'application/x-x509-ca-cert'
                '.dib'         = 'image/bmp'
                '.dir'         = 'application/x-director'
                '.disco'       = 'text/xml'
                '.dll'         = 'application/x-msdownload'
                '.dll.config'  = 'text/xml'
                '.dlm'         = 'text/dlm'
                '.doc'         = 'application/msword'
                '.docm'        = 'application/vnd.ms-word.document.macroEnabled.12'
                '.docx'        = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                '.dot'         = 'application/msword'
                '.dotm'        = 'application/vnd.ms-word.template.macroEnabled.12'
                '.dotx'        = 'application/vnd.openxmlformats-officedocument.wordprocessingml.template'
                '.dsp'         = 'application/octet-stream'
                '.dtd'         = 'text/xml'
                '.dvi'         = 'application/x-dvi'
                '.dwf'         = 'drawing/x-dwf'
                '.dwp'         = 'application/octet-stream'
                '.dxr'         = 'application/x-director'
                '.eml'         = 'message/rfc822'
                '.emz'         = 'application/octet-stream'
                '.eot'         = 'application/octet-stream'
                '.eps'         = 'application/postscript'
                '.etx'         = 'text/x-setext'
                '.evy'         = 'application/envoy'
                '.exe'         = 'application/octet-stream'
                '.exe.config'  = 'text/xml'
                '.fdf'         = 'application/vnd.fdf'
                '.fif'         = 'application/fractals'
                '.fla'         = 'application/octet-stream'
                '.flr'         = 'x-world/x-vrml'
                '.flv'         = 'video/x-flv'
                '.gif'         = 'image/gif'
                '.gtar'        = 'application/x-gtar'
                '.gz'          = 'application/x-gzip'
                '.h'           = 'text/plain'
                '.hdf'         = 'application/x-hdf'
                '.hdml'        = 'text/x-hdml'
                '.hhc'         = 'application/x-oleobject'
                '.hhk'         = 'application/octet-stream'
                '.hhp'         = 'application/octet-stream'
                '.hlp'         = 'application/winhlp'
                '.hqx'         = 'application/mac-binhex40'
                '.hta'         = 'application/hta'
                '.htc'         = 'text/x-component'
                '.htm'         = 'text/html'
                '.html'        = 'text/html'
                '.htt'         = 'text/webviewhtml'
                '.hxt'         = 'text/html'
                '.ico'         = 'image/x-icon'
                '.ics'         = 'application/octet-stream'
                '.ief'         = 'image/ief'
                '.iii'         = 'application/x-iphone'
                '.inf'         = 'application/octet-stream'
                '.ins'         = 'application/x-internet-signup'
                '.isp'         = 'application/x-internet-signup'
                '.IVF'         = 'video/x-ivf'
                '.jar'         = 'application/java-archive'
                '.java'        = 'application/octet-stream'
                '.jck'         = 'application/liquidmotion'
                '.jcz'         = 'application/liquidmotion'
                '.jfif'        = 'image/pjpeg'
                '.jpb'         = 'application/octet-stream'
                '.jpe'         = 'image/jpeg'
                '.jpeg'        = 'image/jpeg'
                '.jpg'         = 'image/jpeg'
                '.js'          = 'application/x-javascript'
                '.jsx'         = 'text/jscript'
                '.latex'       = 'application/x-latex'
                '.lit'         = 'application/x-ms-reader'
                '.lpk'         = 'application/octet-stream'
                '.lsf'         = 'video/x-la-asf'
                '.lsx'         = 'video/x-la-asf'
                '.lzh'         = 'application/octet-stream'
                '.m13'         = 'application/x-msmediaview'
                '.m14'         = 'application/x-msmediaview'
                '.m1v'         = 'video/mpeg'
                '.m3u'         = 'audio/x-mpegurl'
                '.man'         = 'application/x-troff-man'
                '.manifest'    = 'application/x-ms-manifest'
                '.map'         = 'text/plain'
                '.mdb'         = 'application/x-msaccess'
                '.mdp'         = 'application/octet-stream'
                '.me'          = 'application/x-troff-me'
                '.mht'         = 'message/rfc822'
                '.mhtml'       = 'message/rfc822'
                '.mid'         = 'audio/mid'
                '.midi'        = 'audio/mid'
                '.mix'         = 'application/octet-stream'
                '.mmf'         = 'application/x-smaf'
                '.mno'         = 'text/xml'
                '.mny'         = 'application/x-msmoney'
                '.mov'         = 'video/quicktime'
                '.movie'       = 'video/x-sgi-movie'
                '.mp2'         = 'video/mpeg'
                '.mp3'         = 'audio/mpeg'
                '.mpa'         = 'video/mpeg'
                '.mpe'         = 'video/mpeg'
                '.mpeg'        = 'video/mpeg'
                '.mpg'         = 'video/mpeg'
                '.mpp'         = 'application/vnd.ms-project'
                '.mpv2'        = 'video/mpeg'
                '.ms'          = 'application/x-troff-ms'
                '.msi'         = 'application/octet-stream'
                '.mso'         = 'application/octet-stream'
                '.mvb'         = 'application/x-msmediaview'
                '.mvc'         = 'application/x-miva-compiled'
                '.nc'          = 'application/x-netcdf'
                '.nsc'         = 'video/x-ms-asf'
                '.nws'         = 'message/rfc822'
                '.ocx'         = 'application/octet-stream'
                '.oda'         = 'application/oda'
                '.odc'         = 'text/x-ms-odc'
                '.ods'         = 'application/oleobject'
                '.one'         = 'application/onenote'
                '.onea'        = 'application/onenote'
                '.onetoc'      = 'application/onenote'
                '.onetoc2'     = 'application/onenote'
                '.onetmp'      = 'application/onenote'
                '.onepkg'      = 'application/onenote'
                '.osdx'        = 'application/opensearchdescription+xml'
                '.p10'         = 'application/pkcs10'
                '.p12'         = 'application/x-pkcs12'
                '.p7b'         = 'application/x-pkcs7-certificates'
                '.p7c'         = 'application/pkcs7-mime'
                '.p7m'         = 'application/pkcs7-mime'
                '.p7r'         = 'application/x-pkcs7-certreqresp'
                '.p7s'         = 'application/pkcs7-signature'
                '.pbm'         = 'image/x-portable-bitmap'
                '.pcx'         = 'application/octet-stream'
                '.pcz'         = 'application/octet-stream'
                '.pdf'         = 'application/pdf'
                '.pfb'         = 'application/octet-stream'
                '.pfm'         = 'application/octet-stream'
                '.pfx'         = 'application/x-pkcs12'
                '.pgm'         = 'image/x-portable-graymap'
                '.pko'         = 'application/vnd.ms-pki.pko'
                '.pma'         = 'application/x-perfmon'
                '.pmc'         = 'application/x-perfmon'
                '.pml'         = 'application/x-perfmon'
                '.pmr'         = 'application/x-perfmon'
                '.pmw'         = 'application/x-perfmon'
                '.png'         = 'image/png'
                '.pnm'         = 'image/x-portable-anymap'
                '.pnz'         = 'image/png'
                '.pot'         = 'application/vnd.ms-powerpoint'
                '.potm'        = 'application/vnd.ms-powerpoint.template.macroEnabled.12'
                '.potx'        = 'application/vnd.openxmlformats-officedocument.presentationml.template'
                '.ppam'        = 'application/vnd.ms-powerpoint.addin.macroEnabled.12'
                '.ppm'         = 'image/x-portable-pixmap'
                '.pps'         = 'application/vnd.ms-powerpoint'
                '.ppsm'        = 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12'
                '.ppsx'        = 'application/vnd.openxmlformats-officedocument.presentationml.slideshow'
                '.ppt'         = 'application/vnd.ms-powerpoint'
                '.pptm'        = 'application/vnd.ms-powerpoint.presentation.macroEnabled.12'
                '.pptx'        = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                '.prf'         = 'application/pics-rules'
                '.prm'         = 'application/octet-stream'
                '.prx'         = 'application/octet-stream'
                '.ps'          = 'application/postscript'
                '.psd'         = 'application/octet-stream'
                '.psm'         = 'application/octet-stream'
                '.psp'         = 'application/octet-stream'
                '.pub'         = 'application/x-mspublisher'
                '.qt'          = 'video/quicktime'
                '.qtl'         = 'application/x-quicktimeplayer'
                '.qxd'         = 'application/octet-stream'
                '.ra'          = 'audio/x-pn-realaudio'
                '.ram'         = 'audio/x-pn-realaudio'
                '.rar'         = 'application/octet-stream'
                '.ras'         = 'image/x-cmu-raster'
                '.rf'          = 'image/vnd.rn-realflash'
                '.rgb'         = 'image/x-rgb'
                '.rm'          = 'application/vnd.rn-realmedia'
                '.rmi'         = 'audio/mid'
                '.roff'        = 'application/x-troff'
                '.rpm'         = 'audio/x-pn-realaudio-plugin'
                '.rtf'         = 'application/rtf'
                '.rtx'         = 'text/richtext'
                '.scd'         = 'application/x-msschedule'
                '.sct'         = 'text/scriptlet'
                '.sea'         = 'application/octet-stream'
                '.setpay'      = 'application/set-payment-initiation'
                '.setreg'      = 'application/set-registration-initiation'
                '.sgml'        = 'text/sgml'
                '.sh'          = 'application/x-sh'
                '.shar'        = 'application/x-shar'
                '.sit'         = 'application/x-stuffit'
                '.sldm'        = 'application/vnd.ms-powerpoint.slide.macroEnabled.12'
                '.sldx'        = 'application/vnd.openxmlformats-officedocument.presentationml.slide'
                '.smd'         = 'audio/x-smd'
                '.smi'         = 'application/octet-stream'
                '.smx'         = 'audio/x-smd'
                '.smz'         = 'audio/x-smd'
                '.snd'         = 'audio/basic'
                '.snp'         = 'application/octet-stream'
                '.spc'         = 'application/x-pkcs7-certificates'
                '.spl'         = 'application/futuresplash'
                '.src'         = 'application/x-wais-source'
                '.ssm'         = 'application/streamingmedia'
                '.sst'         = 'application/vnd.ms-pki.certstore'
                '.stl'         = 'application/vnd.ms-pki.stl'
                '.sv4cpio'     = 'application/x-sv4cpio'
                '.sv4crc'      = 'application/x-sv4crc'
                '.swf'         = 'application/x-shockwave-flash'
                '.t'           = 'application/x-troff'
                '.tar'         = 'application/x-tar'
                '.tcl'         = 'application/x-tcl'
                '.tex'         = 'application/x-tex'
                '.texi'        = 'application/x-texinfo'
                '.texinfo'     = 'application/x-texinfo'
                '.tgz'         = 'application/x-compressed'
                '.thmx'        = 'application/vnd.ms-officetheme'
                '.thn'         = 'application/octet-stream'
                '.tif'         = 'image/tiff'
                '.tiff'        = 'image/tiff'
                '.toc'         = 'application/octet-stream'
                '.tr'          = 'application/x-troff'
                '.trm'         = 'application/x-msterminal'
                '.tsv'         = 'text/tab-separated-values'
                '.ttf'         = 'application/octet-stream'
                '.txt'         = 'text/plain'
                '.u32'         = 'application/octet-stream'
                '.uls'         = 'text/iuls'
                '.ustar'       = 'application/x-ustar'
                '.vbs'         = 'text/vbscript'
                '.vcf'         = 'text/x-vcard'
                '.vcs'         = 'text/plain'
                '.vdx'         = 'application/vnd.ms-visio.viewer'
                '.vml'         = 'text/xml'
                '.vsd'         = 'application/vnd.visio'
                '.vss'         = 'application/vnd.visio'
                '.vst'         = 'application/vnd.visio'
                '.vsto'        = 'application/x-ms-vsto'
                '.vsw'         = 'application/vnd.visio'
                '.vsx'         = 'application/vnd.visio'
                '.vtx'         = 'application/vnd.visio'
                '.wav'         = 'audio/wav'
                '.wax'         = 'audio/x-ms-wax'
                '.wbmp'        = 'image/vnd.wap.wbmp'
                '.wcm'         = 'application/vnd.ms-works'
                '.wdb'         = 'application/vnd.ms-works'
                '.wks'         = 'application/vnd.ms-works'
                '.wm'          = 'video/x-ms-wm'
                '.wma'         = 'audio/x-ms-wma'
                '.wmd'         = 'application/x-ms-wmd'
                '.wmf'         = 'application/x-msmetafile'
                '.wml'         = 'text/vnd.wap.wml'
                '.wmlc'        = 'application/vnd.wap.wmlc'
                '.wmls'        = 'text/vnd.wap.wmlscript'
                '.wmlsc'       = 'application/vnd.wap.wmlscriptc'
                '.wmp'         = 'video/x-ms-wmp'
                '.wmv'         = 'video/x-ms-wmv'
                '.wmx'         = 'video/x-ms-wmx'
                '.wmz'         = 'application/x-ms-wmz'
                '.wps'         = 'application/vnd.ms-works'
                '.wri'         = 'application/x-mswrite'
                '.wrl'         = 'x-world/x-vrml'
                '.wrz'         = 'x-world/x-vrml'
                '.wsdl'        = 'text/xml'
                '.wvx'         = 'video/x-ms-wvx'
                '.x'           = 'application/directx'
                '.xaf'         = 'x-world/x-vrml'
                '.xaml'        = 'application/xaml+xml'
                '.xap'         = 'application/x-silverlight-app'
                '.xbap'        = 'application/x-ms-xbap'
                '.xbm'         = 'image/x-xbitmap'
                '.xdr'         = 'text/plain'
                '.xla'         = 'application/vnd.ms-excel'
                '.xlam'        = 'application/vnd.ms-excel.addin.macroEnabled.12'
                '.xlc'         = 'application/vnd.ms-excel'
                '.xlm'         = 'application/vnd.ms-excel'
                '.xls'         = 'application/vnd.ms-excel'
                '.xlsb'        = 'application/vnd.ms-excel.sheet.binary.macroEnabled.12'
                '.xlsm'        = 'application/vnd.ms-excel.sheet.macroEnabled.12'
                '.xlsx'        = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                '.xlt'         = 'application/vnd.ms-excel'
                '.xltm'        = 'application/vnd.ms-excel.template.macroEnabled.12'
                '.xltx'        = 'application/vnd.openxmlformats-officedocument.spreadsheetml.template'
                '.xlw'         = 'application/vnd.ms-excel'
                '.xml'         = 'text/xml'
                '.xof'         = 'x-world/x-vrml'
                '.xpm'         = 'image/x-xpixmap'
                '.xps'         = 'application/vnd.ms-xpsdocument'
                '.xsd'         = 'text/xml'
                '.xsf'         = 'text/xml'
                '.xsl'         = 'text/xml'
                '.xslt'        = 'text/xml'
                '.xsn'         = 'application/octet-stream'
                '.xtp'         = 'application/octet-stream'
                '.xwd'         = 'image/x-xwindowdump'
                '.z'           = 'application/x-compress'
                '.zip'         = 'application/x-zip-compressed'
            }

            $extension = [System.IO.Path]::GetExtension($FileName)
            $contentType = $mimeMappings[$extension]

            if ([string]::IsNullOrEmpty($contentType)) {
                return New-Object System.Net.Mime.ContentType
            }
            else {
                return New-Object System.Net.Mime.ContentType($contentType)
            }
        }

        try {
            $_smtpClient = New-Object Net.Mail.SmtpClient
        
            $_smtpClient.Host = $SmtpServer
            $_smtpClient.Port = $Port
            $_smtpClient.EnableSsl = $UseSsl

            if ($null -ne $Credential) {
                # In PowerShell 2.0, assigning the results of GetNetworkCredential() to the SMTP client sometimes fails (with gmail, in testing), but
                # building a new NetworkCredential object containing only the UserName and Password works okay.

                $_tempCred = $Credential.GetNetworkCredential()
                $_smtpClient.Credentials = New-Object Net.NetworkCredential($Credential.UserName, $_tempCred.Password)
            }
            else {
                $_smtpClient.UseDefaultCredentials = $true
            }

            $_message = New-Object Net.Mail.MailMessage
        
            $_message.From = $From
            $_message.Subject = $Subject
            
            if ($BodyAsHtml) {
                $_bodyPart = [Net.Mail.AlternateView]::CreateAlternateViewFromString($Body, 'text/html')
            }
            else {
                $_bodyPart = [Net.Mail.AlternateView]::CreateAlternateViewFromString($Body, 'text/plain')
            }   

            $_message.AlternateViews.Add($_bodyPart)

            if ($PSBoundParameters.ContainsKey('DeliveryNotificationOption')) { $_message.DeliveryNotificationOptions = $DeliveryNotificationOption }
            if ($PSBoundParameters.ContainsKey('Priority')) { $_message.Priority = $Priority }

            foreach ($_address in $To) {
                if (-not $_message.To.Contains($_address)) { $_message.To.Add($_address) }
            }

            if ($null -ne $Cc) {
                foreach ($_address in $Cc) {
                    if (-not $_message.CC.Contains($_address)) { $_message.CC.Add($_address) }
                }
            }

            if ($null -ne $Bcc) {
                foreach ($_address in $Bcc) {
                    if (-not $_message.Bcc.Contains($_address)) { $_message.Bcc.Add($_address) }
                }
            }
        }
        catch {
            $_message.Dispose()
            throw
        }

        if ($PSBoundParameters.ContainsKey('InlineAttachments')) {
            foreach ($_entry in $InlineAttachments.GetEnumerator()) {
                $_file = $_entry.Value.ToString()
                
                if ([string]::IsNullOrEmpty($_file)) {
                    $_message.Dispose()
                    throw "Send-MailMessage: Values in the InlineAttachments table cannot be null."
                }

                try {
                    $_contentType = FileNameToContentType -FileName $_file
                    $_attachment = New-Object Net.Mail.LinkedResource($_file, $_contentType)
                    $_attachment.ContentId = $_entry.Key

                    $_bodyPart.LinkedResources.Add($_attachment)
                }
                catch {
                    $_message.Dispose()
                    throw
                }
            }
        }
    }

    process {
        if ($null -ne $Attachments) {
            foreach ($_file in $Attachments) {
                try {
                    $_contentType = FileNameToContentType -FileName $_file
                    $_message.Attachments.Add((New-Object Net.Mail.Attachment($_file, $_contentType)))
                }
                catch {
                    $_message.Dispose()
                    throw
                }
            }
        }
    }
    
    end {
        try {
            $_smtpClient.Send($_message)
        }
        catch {
            throw
        }
        finally {
            $_message.Dispose()
        }
    }

} # function Send-MailMessage
<#
.Synopsis
   Create Pervasive DSN
.DESCRIPTION
   Create Pervasive Flite or Crew DSN to connect to Movement contrl or Crewtrac DB
.EXAMPLE
   Create-DSN -DSNName "MC_Stage1" -DBName "FTPVSERVERDB" -ServerName "jbvstmpdbs2000"

.EXAMPLE
   Create-DSN -DSNName "MC_Stage1" -DBName "FTPVSERVERDB" -ServerName "jbvstmpdbs2000" -OS32Bit

#>

function Create-DSN {
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Name you want to use to connect to
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        $DSNName,

        # Name of the DB on the server connecting to
        [Parameter(Mandatory = $true, Position = 1)]
        $DBName,

        #Name of the DB Server
        [Parameter(Mandatory = $true)]
        $ServerName,

        #If used will create 32 DSN
        [Parameter(Mandatory = $false)]
        [switch]$OS32bit



    )

    Begin {
        if ($OS32bit) {
            $HKLMPath1 = "HKLM:SOFTWARE\Wow6432Node\ODBC\ODBC.INI\" + $DSNName
            $HKLMPath2 = "HKLM:SOFTWARE\Wow6432Node\ODBC\ODBC.INI\ODBC Data Sources\"
            $Driver = "C:\Program Files (x86)\Actian\PSQL\bin\w3odbcci.dll"
            $Description = "Pervasive ODBC Client Interface"
        }
        Else {

            $HKLMPath1 = "HKLM:SOFTWARE\ODBC\ODBC.INI\" + $DSNName
            $HKLMPath2 = "HKLM:SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources\"
            $Driver = "C:\Program Files\Actian\PSQL\bin\odbcci64.dll"
            $Description = "Pervasive ODBC Interface"
        }
    }
    Process {

        If (!(Test-path $HKLMPath1)) { mkdir $HKLMPath1 -ErrorAction silentlycontinue }
        If (!(Test-path $HKLMPath2)) { mkdir $HKLMPath2 -ErrorAction silentlycontinue }
        set-itemproperty -path $HKLMPath1 -name Driver -value $Driver
        set-itemproperty -path $HKLMPath1 -name Description -value $Description
        set-itemproperty -path $HKLMPath1 -name ServerName -value "$($ServerName).1583"
        set-itemproperty -path $HKLMPath1 -name ArrayBufferSize -value "8"
        set-itemproperty -path $HKLMPath1 -name ArrayFetchOn -value "1"
        set-itemproperty -path $HKLMPath1 -name DBQ -value $DBName
        set-itemproperty -path $HKLMPath1 -name PvTranslate -value ""
        set-itemproperty -path $HKLMPath1 -name TCPPort -value "1583"
        set-itemproperty -path $HKLMPath1 -name TranslationDLL -value ""
        set-itemproperty -path $HKLMPath1 -name TranslationOption -value ""
        set-itemproperty -path $HKLMPath1 -name TransportHint -value "TCP:SPX"

        set-itemproperty -path $HKLMPath2 -name "$DSNName" -value $Description
    }
    End {
    }
}

function Listen-Port ($port = 80) {
    <#
.DESCRIPTION
Temporarily listen on a given port for connections dumps connections to the screen - useful for troubleshooting
firewall rules.

.PARAMETER Port
The TCP port that the listener should attach to

.EXAMPLE
PS C:\> listen-port 443
Listening on port 443, press CTRL+C to cancel

DateTime                                      AddressFamily Address                                                Port
--------                                      ------------- -------                                                ----
3/1/2016 4:36:43 AM                            InterNetwork 192.168.20.179                                        62286
Listener Closed Safely

.INFO
Created by Shane Wright. Neossian@gmail.com

#>
    $endpoint = new-object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)    
    $listener = new-object System.Net.Sockets.TcpListener $endpoint
    $listener.server.ReceiveTimeout = 3000
    $listener.start()    
    try {
        Write-Host "Listening on port $port, press CTRL+C to cancel"
        While ($true) {
            if (!$listener.Pending()) {
                Start-Sleep -Seconds 1; 
                continue; 
            }
            $client = $listener.AcceptTcpClient()
            $client.client.RemoteEndPoint | Add-Member -NotePropertyName DateTime -NotePropertyValue (get-date) -PassThru
            $client.close()
        }
    }
    catch {
        Write-Error $_          
    }
    finally {
        $listener.stop()
        Write-host "Listener Closed Safely"
    }

}

#PowerShell Script Containing Function Used to Remove User Profiles & Additional Remnants of C:\Users Directory
#Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)
#Date: 12/22/14

#Requires -Version 2.0

function Remove-UserProfile {
    <#
    .SYNOPSIS
    Removes user profiles and additional contents of the C:\Users 
    directory if specified.
    .DESCRIPTION
    Gathers a list of profiles to be removed from the local computer, 
    passing on exceptions noted via the Exclude parameter and/or 
    profiles newer than the date specified via the Before parameter.  
    If desired, additional files and folders within C:\Users can also 
    be removed via use of the DirectoryCleanup parameter.

    Once gathered, miscellaneous items are first removed from the 
    C:\Users directory if specified, followed by the profile objects 
    themselves and all associated registry keys per profile.  A listing 
    of current items within the C:\Users directory is returned 
    following the profile removal process.
    .PARAMETER Exclude
    Specifies one or more profile names to exclude from the removal 
    process.
    .PARAMETER Before
    Specifies a date from which to remove profiles before that haven't 
    been accessed since that date.
    .PARAMETER DirectoryCleanup
    Removes additional files/folders (i.e. non-profiles) within the 
    C:\Users directory.
    .EXAMPLE
    Remove-UserProfile
    Remove all non-active and non-system designated user profiles 
    from the local computer.
    .EXAMPLE
    Remove-UserProfile -Before (Get-Date).AddMonths(-1) -Verbose
    Remove all non-active and non-system designated user profiles 
    not used within the past month, displaying verbose output as well.
    .EXAMPLE
    Remove-UserProfile -Exclude @("labadmin", "desktopuser") -DirectoryCleanup
    Remove all non-active and non-system designated user profiles 
    except "labadmin" and "desktopuser", and remove additional 
    non-profile files/folders within C:\Users as well.
    .NOTES
    Even when not specifying the Exclude parameter, the following 
    profiles are not removed when utilizing this cmdlet:
    C:\Windows\ServiceProfiles\NetworkService 
    C:\Windows\ServiceProfiles\LocalService 
    C:\Windows\system32\config\systemprofile 
    C:\Users\Public
    C:\Users\Default

    Aside from the original profile directory (within C:\Users) 
    itself, the following registry items are also cleared upon 
    profile removal via WMI:
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{SID of User}"
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileGuid\{GUID}" SidString = {SID of User}
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\{SID of User}"

    Additionally, any currently loaded/in use profiles will not be 
    removed.  Regarding miscellaneous non-profile items, hidden items 
    are not enumerated or removed from C:\Users during this process.

    This cmdlet requires adminisrative privileges to run effectively.
      
    This cmdlet is not intended to be used on Virtual Desktop 
    Infrastructure (VDI) environments or others which utilize 
    persistent storage on alternate disks, or any configurations 
    which utilize another directory other than C:\Users to store 
    user profiles.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $false)]
        [String[]]$Exclude,
        [Parameter(Position = 1, Mandatory = $false)]
        [DateTime]$Before,
        [Parameter(Position = 2, Mandatory = $false)]
        [Switch]$DirectoryCleanup
    )

    Write-Verbose "Gathering List of Profiles on $env:COMPUTERNAME to Remove..."

    $userProfileFilter = "Loaded = 'False' AND Special = 'False'"
    $cleanupExclusions = @("Public", "Default")

    if ($Exclude) {
        foreach ($exclusion in $Exclude) {
            $userProfileFilter += "AND NOT LocalPath LIKE '%$exclusion'"
            $cleanupExclusions += $exclusion
        }
    }

    if ($Before) {
        $userProfileFilter += "AND LastUseTime < '$Before'"

        $keepUserProfileFilter = "Special = 'False' AND LastUseTime >= '$Before'"
        $profilesToKeep = Get-WmiObject -Class Win32_UserProfile -Filter $keepUserProfileFilter -ErrorAction Stop

        foreach ($profileToKeep in $profilesToKeep) {
            try {
                $userSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier($($profileToKeep.SID))
                $userName = $userSID.Translate([System.Security.Principal.NTAccount])
                
                $keepUserName = $userName.Value -replace ".*\\", ""
                $cleanupExclusions += $keepUserName
            }
            catch [System.Security.Principal.IdentityNotMappedException] {
                Write-Warning "Cannot Translate SID to UserName - Not Adding Value to Exceptions List"
            }
        }
    }

    $profilesToDelete = Get-WmiObject -Class Win32_UserProfile -Filter $userProfileFilter -ErrorAction Stop

    if ($DirectoryCleanup) {
        $usersChildItem = Get-ChildItem -Path "C:\Users" -Exclude $cleanupExclusions

        foreach ($usersChild in $usersChildItem) {
            if ($profilesToDelete.LocalPath -notcontains $usersChild.FullName) {    
                try {
                    Write-Verbose "Additional Directory Cleanup - Removing $($usersChild.Name) on $env:COMPUTERNAME..."
                    
                    Remove-Item -Path $($usersChild.FullName) -Recurse -Force -ErrorAction Stop
                }
                catch [System.InvalidOperationException] {
                    Write-Verbose "Skipping Removal of $($usersChild.Name) on $env:COMPUTERNAME as Item is Currently In Use..."
                }
            }
        }
    }

    foreach ($profileToDelete in $profilesToDelete) {
        Write-Verbose "Removing Profile $($profileToDelete.LocalPath) & Associated Registry Keys on $env:COMPUTERNAME..."
                
        Remove-WmiObject -InputObject $profileToDelete -ErrorAction Stop
    }

    $finalChildItem = Get-ChildItem -Path "C:\Users" | Select-Object -Property Name, FullName, LastWriteTime
                
    return $finalChildItem
}

Function Get-PendingReboot {
    <#
.SYNOPSIS
    Gets the pending reboot status on a local or remote computer.

.DESCRIPTION
    This function will query the registry on a local or remote computer and determine if the
    system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
    Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
    CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
    and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
	
    CBServicing = Component Based Servicing (Windows 2008+)
    WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
    CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
    PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
    PendFileRename = PendingFileRenameOperations (Windows 2003+)
    PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                     Virus leverage this key for def/dat removal, giving a false positive PendingReboot

.PARAMETER ComputerName
    A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

.PARAMETER ErrorLog
    A single path to send error data to a log file.

.EXAMPLE
    PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
	
    Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
    -------- ----------- ------------- ------------ -------------- -------------- -------------
    DC01           False         False                       False                        False
    DC02           False         False                       False                        False
    FS01           False         False                       False                        False

    This example will capture the contents of C:\ServerList.txt and query the pending reboot
    information from the systems contained in the file and display the output in a table. The
    null values are by design, since these systems do not have the SCCM 2012 client installed,
    nor was the PendingFileRenameOperations value populated.

.EXAMPLE
    PS C:\> Get-PendingReboot
	
    Computer           : WKS01
    CBServicing        : False
    WindowsUpdate      : True
    CCMClient          : False
    PendComputerRename : False
    PendFileRename     : False
    PendFileRenVal     : 
    RebootPending      : True
	
    This example will query the local machine for pending reboot information.
	
.EXAMPLE
    PS C:\> $Servers = Get-Content C:\Servers.txt
    PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
	
    This example will create a report that contains pending reboot information.

.LINK
    Component-Based Servicing:
    http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
	
    PendingFileRename/Auto Update:
    http://support.microsoft.com/kb/2723674
    http://technet.microsoft.com/en-us/library/cc960241.aspx
    http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

    SCCM 2012/CCM_ClientSDK:
    http://msdn.microsoft.com/en-us/library/jj902723.aspx

.NOTES
    Author:  Brian Wilhite
    Email:   bcwilhite (at) live.com
    Date:    29AUG2012
    PSVer:   2.0/3.0/4.0/5.0
    Updated: 27JUL2015
    UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
             Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
             Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
             Added CCMClient property - Used with SCCM 2012 Clients only
             Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
             Removed $Data variable from the PSObject - it is not needed
             Bug with the way CCMClientSDK returned null value if it was false
             Removed unneeded variables
             Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
             Removed .Net Registry connection, replaced with WMI StdRegProv
             Added ComputerPendingRename
#>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("CN", "Computer")]
        [String[]]$ComputerName = "$env:COMPUTERNAME",
        [String]$ErrorLog
    )

    Begin {  }## End Begin Script Block
    Process {
        Foreach ($Computer in $ComputerName) {
            Try {
                ## Setting pending values to false to cut down on the number of else statements
                $CompPendRen, $PendFileRename, $Pending, $SCCM = $false, $false, $false, $false
                        
                ## Setting CBSRebootPend to null since not all versions of Windows has this value
                $CBSRebootPend = $null
						
                ## Querying WMI for build version
                $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

                ## Making registry connection to the local/remote computer
                $HKLM = [UInt32] "0x80000002"
                $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
						
                ## If Vista/2008 & Above query the CBS Reg Key
                If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
                    $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
                    $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
                }
							
                ## Query WUAU from the registry
                $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
                $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
						
                ## Query PendingFileRenameOperations from the registry
                $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\Session Manager\", "PendingFileRenameOperations")
                $RegValuePFRO = $RegSubKeySM.sValue

                ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
                $Netlogon = $WMI_Reg.EnumKey($HKLM, "SYSTEM\CurrentControlSet\Services\Netlogon").sNames
                $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

                ## Query ComputerName and ActiveComputerName from the registry
                $ActCompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\", "ComputerName")            
                $CompNm = $WMI_Reg.GetStringValue($HKLM, "SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\", "ComputerName")

                If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
                    $CompPendRen = $true
                }
						
                ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
                If ($RegValuePFRO) {
                    $PendFileRename = $true
                }

                ## Determine SCCM 2012 Client Reboot Pending Status
                ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
                $CCMClientSDK = $null
                $CCMSplat = @{
                    NameSpace    = 'ROOT\ccm\ClientSDK'
                    Class        = 'CCM_ClientUtilities'
                    Name         = 'DetermineIfRebootPending'
                    ComputerName = $Computer
                    ErrorAction  = 'Stop'
                }
                ## Try CCMClientSDK
                Try {
                    $CCMClientSDK = Invoke-WmiMethod @CCMSplat
                }
                Catch [System.UnauthorizedAccessException] {
                    $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
                    If ($CcmStatus.Status -ne 'Running') {
                        Write-Warning "$Computer`: Error - CcmExec service is not running."
                        $CCMClientSDK = $null
                    }
                }
                Catch {
                    $CCMClientSDK = $null
                }

                If ($CCMClientSDK) {
                    If ($CCMClientSDK.ReturnValue -ne 0) {
                        Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
                    }
                    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
                        $SCCM = $true
                    }
                }
            
                Else {
                    $SCCM = $null
                }

                ## Creating Custom PSObject and Select-Object Splat
                $SelectSplat = @{
                    Property = (
                        'Computer',
                        'CBServicing',
                        'WindowsUpdate',
                        'CCMClientSDK',
                        'PendComputerRename',
                        'PendFileRename',
                        'PendFileRenVal',
                        'RebootPending'
                    )
                }
                New-Object -TypeName PSObject -Property @{
                    Computer           = $WMI_OS.CSName
                    CBServicing        = $CBSRebootPend
                    WindowsUpdate      = $WUAURebootReq
                    CCMClientSDK       = $SCCM
                    PendComputerRename = $CompPendRen
                    PendFileRename     = $PendFileRename
                    PendFileRenVal     = $RegValuePFRO
                    RebootPending      = ($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
                } | Select-Object @SelectSplat

            }
            Catch {
                Write-Warning "$Computer`: $_"
                ## If $ErrorLog, log the file to a user specified location/path
                If ($ErrorLog) {
                    Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
                }				
            }			
        }## End Foreach ($Computer in $ComputerName)			
    }## End Process

    End {  }## End End

}## End Function Get-PendingReboot

function start-pause {
    #Press any key to continue
    if ($PSise) {

        read-host “Press ENTER to continue...”

    }
    Else {

        Write-Host "Press any key to continue..."
        $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function Add-MvaNetFirewallRemoteAdressFilter {
    <#
.SYNOPSIS
This function adds one or more ipaddresses to the firewall remote address filter
.DESCRIPTION
With the default Set-NetFirewallAddressFilter you can set an address filter for a firewall rule. You can not use it to
add a ip address to an existing address filter. The existing address filter will be replaced by the new one.
The Add-MvaNetFirewallRemoteAdressFilter function will add the ip address. Which is very usefull when there are already
many ip addresses in de address filter.
.PARAMETER fwAddressFilter
This parameter conntains the AddressFilter that you want to change. It accepts pipeline output from the command
Get-NetFirewallAddressFilter
.PARAMETER IPaddresses
This parameter is mandatory and can contain one or more ip addresses. You can also use a subnet.
.EXAMPLE
Get-NetFirewallrule -DisplayName 'Test-Rule' | Get-NetFirewallAddressFilter | Add-MvaNetFirewallRemoteAdressFilter -IPAddresses 192.168.5.5
Add a single IP address to the remote address filter of the firewall rule 'Test-Rule'
.EXAMPLE
Get-NetFirewallrule -DisplayName 'Test-Rule' | Get-NetFirewallAddressFilter | Add-MvaNetFirewallRemoteAdressFilter -IPAddresses 192.168.5.5, 192.168.6.6, 192.168.7.0/24
Add multiple IP address to the remote address filter of the firewall rule 'Test-Rule'
.LINK
https://get-note.net/2018/12/31/edit-firewall-rule-scope-with-powershell/
.INPUTS
Microsoft.Management.Infrastructure.CimInstance#root/standardcimv2/MSFT_NetAddressFilter
.OUTPUTS
None
.NOTES
You need to be Administator to manage the firewall.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true,
            Mandatory = $True)]
        [psobject]$fwAddressFilter,

        # Parameter help description
        [Parameter(Position = 0,
            Mandatory = $True,
            HelpMessage = "Enter one or more IP Addresses.")]
        [string[]]$IPAddresses
    )

    process {
        try {
            #Get the current list of remote addresses
            [string[]]$remoteAddresses = $fwAddressFilter.RemoteAddress
            Write-Verbose -Message "Current address filter contains: $remoteAddresses"

            #Add new ip address to the current list
            if ($remoteAddresses -in 'Any', 'LocalSubnet', 'LocalSubnet6', 'PlayToDevice') {
                $remoteAddresses = $IPAddresses
            }
            else {
                $remoteAddresses += $IPAddresses
            }
            #set new address filter
            $fwAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $remoteAddresses -ErrorAction Stop
            Write-Verbose -Message "New remote address filter is set to: $remoteAddresses"
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSitem)
        }
    }
}

function Get-odbcdata {
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        $query = $(throw 'query is required.'),

        [Parameter(Mandatory = $True,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        $DSN


    )

    Begin {
        
    }
    Process {

        
        $conn = New-Object System.Data.Odbc.OdbcConnection
        $conn.ConnectionString = "DSN=$($DSN);"
        $conn.open()
        $cmd = New-object System.Data.Odbc.OdbcCommand($query, $conn)
        $ds = New-Object system.Data.DataSet
        (New-Object system.Data.odbc.odbcDataAdapter($cmd)).fill($ds) | out-null
        $conn.close()
        $ds.Tables[0]

    }
    End {
    }
}

#Examples of usage
# making sure a bunch of folders exist
#'C:\test1', 'C:\test2' | Assert-FolderExists
# making sure the path assigned to a variable exists
#($Path = 'c:\test3') | Assert-FolderExists 
filter Assert-FolderExists {
    $exists = Test-Path -Path $_ -PathType Container
    if (!$exists) { 
        Write-Warning "$_ did not exist. Folder created."
        $null = New-Item -Path $_ -ItemType Directory 
    }
}

function Get-NetworkStatistics {
    <#
    .SYNOPSIS
	    Display current TCP/IP connections for local or remote system

    .FUNCTIONALITY
        Computers

    .DESCRIPTION
	    Display current TCP/IP connections for local or remote system.  Includes the process ID (PID) and process name for each connection.
	    If the port is not yet established, the port number is shown as an asterisk (*).	
	
    .PARAMETER ProcessName
	    Gets connections by the name of the process. The default value is '*'.
	
    .PARAMETER Port
	    The port number of the local computer or remote computer. The default value is '*'.

    .PARAMETER Address
	    Gets connections by the IP address of the connection, local or remote. Wildcard is supported. The default value is '*'.

    .PARAMETER Protocol
	    The name of the protocol (TCP or UDP). The default value is '*' (all)
	
    .PARAMETER State
	    Indicates the state of a TCP connection. The possible states are as follows:
		
	    Closed       - The TCP connection is closed. 
	    Close_Wait   - The local endpoint of the TCP connection is waiting for a connection termination request from the local user. 
	    Closing      - The local endpoint of the TCP connection is waiting for an acknowledgement of the connection termination request sent previously. 
	    Delete_Tcb   - The transmission control buffer (TCB) for the TCP connection is being deleted. 
	    Established  - The TCP handshake is complete. The connection has been established and data can be sent. 
	    Fin_Wait_1   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint or for an acknowledgement of the connection termination request sent previously. 
	    Fin_Wait_2   - The local endpoint of the TCP connection is waiting for a connection termination request from the remote endpoint. 
	    Last_Ack     - The local endpoint of the TCP connection is waiting for the final acknowledgement of the connection termination request sent previously. 
	    Listen       - The local endpoint of the TCP connection is listening for a connection request from any remote endpoint. 
	    Syn_Received - The local endpoint of the TCP connection has sent and received a connection request and is waiting for an acknowledgment. 
	    Syn_Sent     - The local endpoint of the TCP connection has sent the remote endpoint a segment header with the synchronize (SYN) control bit set and is waiting for a matching connection request. 
	    Time_Wait    - The local endpoint of the TCP connection is waiting for enough time to pass to ensure that the remote endpoint received the acknowledgement of its connection termination request. 
	    Unknown      - The TCP connection state is unknown.
	
	    Values are based on the TcpState Enumeration:
	    http://msdn.microsoft.com/en-us/library/system.net.networkinformation.tcpstate%28VS.85%29.aspx
        
        Cookie Monster - modified these to match netstat output per here:
        http://support.microsoft.com/kb/137984

    .PARAMETER ComputerName
        If defined, run this command on a remote system via WMI.  \\computername\c$\netstat.txt is created on that system and the results returned here

    .PARAMETER ShowHostNames
        If specified, will attempt to resolve local and remote addresses.

    .PARAMETER tempFile
        Temporary file to store results on remote system.  Must be relative to remote system (not a file share).  Default is "C:\netstat.txt"

    .PARAMETER AddressFamily
        Filter by IP Address family: IPv4, IPv6, or the default, * (both).

        If specified, we display any result where both the localaddress and the remoteaddress is in the address family.

    .EXAMPLE
	    Get-NetworkStatistics | Format-Table

    .EXAMPLE
	    Get-NetworkStatistics iexplore -computername k-it-thin-02 -ShowHostNames | Format-Table

    .EXAMPLE
	    Get-NetworkStatistics -ProcessName md* -Protocol tcp

    .EXAMPLE
	    Get-NetworkStatistics -Address 192* -State LISTENING

    .EXAMPLE
	    Get-NetworkStatistics -State LISTENING -Protocol tcp

    .EXAMPLE
        Get-NetworkStatistics -Computername Computer1, Computer2

    .EXAMPLE
        'Computer1', 'Computer2' | Get-NetworkStatistics

    .OUTPUTS
	    System.Management.Automation.PSObject

    .NOTES
	    Author: Shay Levy, code butchered by Cookie Monster
	    Shay's Blog: http://PowerShay.com
        Cookie Monster's Blog: http://ramblingcookiemonster.github.io/

    .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Get-NetworkStatistics-66057d71
    #>	
    [OutputType('System.Management.Automation.PSObject')]
    [CmdletBinding()]
    param(
		
        [Parameter(Position = 0)]
        [System.String]$ProcessName = '*',
		
        [Parameter(Position = 1)]
        [System.String]$Address = '*',		
		
        [Parameter(Position = 2)]
        $Port = '*',

        [Parameter(Position = 3,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True)]
        [System.String[]]$ComputerName = $env:COMPUTERNAME,

        [ValidateSet('*', 'tcp', 'udp')]
        [System.String]$Protocol = '*',

        [ValidateSet('*', 'Closed', 'Close_Wait', 'Closing', 'Delete_Tcb', 'DeleteTcb', 'Established', 'Fin_Wait_1', 'Fin_Wait_2', 'Last_Ack', 'Listening', 'Syn_Received', 'Syn_Sent', 'Time_Wait', 'Unknown')]
        [System.String]$State = '*',

        [switch]$ShowHostnames,
        
        [switch]$ShowProcessNames = $true,	

        [System.String]$TempFile = "C:\netstat.txt",

        [validateset('*', 'IPv4', 'IPv6')]
        [string]$AddressFamily = '*'
    )
    
    begin {
        #Define properties
        $properties = 'ComputerName', 'Protocol', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'State', 'ProcessName', 'PID'

        #store hostnames in array for quick lookup
        $dnsCache = @{}
            
    }
	
    process {

        foreach ($Computer in $ComputerName) {

            #Collect processes
            if ($ShowProcessNames) {
                Try {
                    $processes = Get-Process -ComputerName $Computer -ErrorAction stop | Select-Object name, id
                }
                Catch {
                    Write-warning "Could not run Get-Process -computername $Computer.  Verify permissions and connectivity.  Defaulting to no ShowProcessNames"
                    $ShowProcessNames = $false
                }
            }
	    
            #Handle remote systems
            if ($Computer -ne $env:COMPUTERNAME) {

                #define command
                [string]$cmd = "cmd /c c:\windows\system32\netstat.exe -ano >> $tempFile"
            
                #define remote file path - computername, drive, folder path
                $remoteTempFile = "\\{0}\{1}`${2}" -f "$Computer", (split-path $tempFile -qualifier).TrimEnd(":"), (Split-Path $tempFile -noqualifier)

                #delete previous results
                Try {
                    $null = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c del $tempFile" -ComputerName $Computer -ErrorAction stop
                }
                Catch {
                    Write-Warning "Could not invoke create win32_process on $Computer to delete $tempfile"
                }

                #run command
                Try {
                    $processID = (Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $cmd -ComputerName $Computer -ErrorAction stop).processid
                }
                Catch {
                    #If we didn't run netstat, break everything off
                    Throw $_
                    Break
                }

                #wait for process to complete
                while (
                    #This while should return true until the process completes
                    $(
                        try {
                            get-process -id $processid -computername $Computer -ErrorAction Stop
                        }
                        catch {
                            $FALSE
                        }
                    )
                ) {
                    start-sleep -seconds 2 
                }
            
                #gather results
                if (test-path $remoteTempFile) {
                    
                    Try {
                        $results = Get-Content $remoteTempFile | Select-String -Pattern '\s+(TCP|UDP)'
                    }
                    Catch {
                        Throw "Could not get content from $remoteTempFile for results"
                        Break
                    }

                    Remove-Item $remoteTempFile -force

                }
                else {
                    Throw "'$tempFile' on $Computer converted to '$remoteTempFile'.  This path is not accessible from your system."
                    Break
                }
            }
            else {
                #gather results on local PC
                $results = netstat -ano | Select-String -Pattern '\s+(TCP|UDP)'
            }

            #initialize counter for progress
            $totalCount = $results.count
            $count = 0
    
            #Loop through each line of results    
            foreach ($result in $results) {
            
                $item = $result.line.split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
    
                if ($item[1] -notmatch '^\[::') {
                    
                    #parse the netstat line for local address and port
                    if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') {
                        $localAddress = $la.IPAddressToString
                        $localPort = $item[1].split('\]:')[-1]
                    }
                    else {
                        $localAddress = $item[1].split(':')[0]
                        $localPort = $item[1].split(':')[-1]
                    }
                    
                    #parse the netstat line for remote address and port
                    if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') {
                        $remoteAddress = $ra.IPAddressToString
                        $remotePort = $item[2].split('\]:')[-1]
                    }
                    else {
                        $remoteAddress = $item[2].split(':')[0]
                        $remotePort = $item[2].split(':')[-1]
                    }

                    #Filter IPv4/IPv6 if specified
                    if ($AddressFamily -ne "*") {
                        if ($AddressFamily -eq 'IPv4' -and $localAddress -match ':' -and $remoteAddress -match ':|\*' ) {
                            #Both are IPv6, or ipv6 and listening, skip
                            Write-Verbose "Filtered by AddressFamily:`n$result"
                            continue
                        }
                        elseif ($AddressFamily -eq 'IPv6' -and $localAddress -notmatch ':' -and ( $remoteAddress -notmatch ':' -or $remoteAddress -match '*' ) ) {
                            #Both are IPv4, or ipv4 and listening, skip
                            Write-Verbose "Filtered by AddressFamily:`n$result"
                            continue
                        }
                    }
    	    		
                    #parse the netstat line for other properties
                    $procId = $item[-1]
                    $proto = $item[0]
                    $status = if ($item[0] -eq 'tcp') { $item[3] } else { $null }	

                    #Filter the object
                    if ($remotePort -notlike $Port -and $localPort -notlike $Port) {
                        write-verbose "remote $Remoteport local $localport port $port"
                        Write-Verbose "Filtered by Port:`n$result"
                        continue
                    }

                    if ($remoteAddress -notlike $Address -and $localAddress -notlike $Address) {
                        Write-Verbose "Filtered by Address:`n$result"
                        continue
                    }
    	    			     
                    if ($status -notlike $State) {
                        Write-Verbose "Filtered by State:`n$result"
                        continue
                    }

                    if ($proto -notlike $Protocol) {
                        Write-Verbose "Filtered by Protocol:`n$result"
                        continue
                    }
                   
                    #Display progress bar prior to getting process name or host name
                    Write-Progress  -Activity "Resolving host and process names"`
                        -Status "Resolving process ID $procId with remote address $remoteAddress and local address $localAddress"`
                        -PercentComplete (( $count / $totalCount ) * 100)
    	    		
                    #If we are running showprocessnames, get the matching name
                    if ($ShowProcessNames -or $PSBoundParameters.ContainsKey -eq 'ProcessName') {
                        
                        #handle case where process spun up in the time between running get-process and running netstat
                        if ($procName = $processes | Where-Object { $_.id -eq $procId } | Select-Object -ExpandProperty name ) { }
                        else { $procName = "Unknown" }

                    }
                    else { $procName = "NA" }

                    if ($procName -notlike $ProcessName) {
                        Write-Verbose "Filtered by ProcessName:`n$result"
                        continue
                    }
    	    						
                    #if the showhostnames switch is specified, try to map IP to hostname
                    if ($showHostnames) {
                        $tmpAddress = $null
                        try {
                            if ($remoteAddress -eq "127.0.0.1" -or $remoteAddress -eq "0.0.0.0") {
                                $remoteAddress = $Computer
                            }
                            elseif ($remoteAddress -match "\w") {
                                        
                                #check with dns cache first
                                if ($dnsCache.containskey( $remoteAddress)) {
                                    $remoteAddress = $dnsCache[$remoteAddress]
                                    write-verbose "using cached REMOTE '$remoteAddress'"
                                }
                                else {
                                    #if address isn't in the cache, resolve it and add it
                                    $tmpAddress = $remoteAddress
                                    $remoteAddress = [System.Net.DNS]::GetHostByAddress("$remoteAddress").hostname
                                    $dnsCache.add($tmpAddress, $remoteAddress)
                                    write-verbose "using non cached REMOTE '$remoteAddress`t$tmpAddress"
                                }
                            }
                        }
                        catch { }

                        try {

                            if ($localAddress -eq "127.0.0.1" -or $localAddress -eq "0.0.0.0") {
                                $localAddress = $Computer
                            }
                            elseif ($localAddress -match "\w") {
                                #check with dns cache first
                                if ($dnsCache.containskey($localAddress)) {
                                    $localAddress = $dnsCache[$localAddress]
                                    write-verbose "using cached LOCAL '$localAddress'"
                                }
                                else {
                                    #if address isn't in the cache, resolve it and add it
                                    $tmpAddress = $localAddress
                                    $localAddress = [System.Net.DNS]::GetHostByAddress("$localAddress").hostname
                                    $dnsCache.add($localAddress, $tmpAddress)
                                    write-verbose "using non cached LOCAL '$localAddress'`t'$tmpAddress'"
                                }
                            }
                        }
                        catch { }
                    }
    
                    #Write the object	
                    New-Object -TypeName PSObject -Property @{
                        ComputerName  = $Computer
                        PID           = $procId
                        ProcessName   = $procName
                        Protocol      = $proto
                        LocalAddress  = $localAddress
                        LocalPort     = $localPort
                        RemoteAddress = $remoteAddress
                        RemotePort    = $remotePort
                        State         = $status
                    } | Select-Object -Property $properties								

                    #Increment the progress counter
                    $count++
                }
            }
        }
    }
}

<# 
.SYNOPSIS 
Get-Uptime retrieves boot up information from a computer. 
.DESCRIPTION 
Get-Uptime uses WMI to retrieve the Win32_OperatingSystem 
LastBootuptime property. It displays the start up time 
as well as the uptime. 
 
Created By: Jason Wasser @wasserja 
Modified: 8/13/2015 01:59:53 PM   
Version 1.4 
 
Changelog: 
 * Added Credential parameter 
 * Changed to property hash table splat method 
 * Converted to function to be added to a module. 
 
.PARAMETER ComputerName 
The Computer name to query. Default: Localhost. 
.EXAMPLE 
Get-Uptime -ComputerName SERVER-R2 
Gets the uptime from SERVER-R2 
.EXAMPLE 
Get-Uptime -ComputerName (Get-Content C:\Temp\Computerlist.txt) 
Gets the uptime from a list of computers in c:\Temp\Computerlist.txt. 
.EXAMPLE 
Get-Uptime -ComputerName SERVER04 -Credential domain\serveradmin 
Gets the uptime from SERVER04 using alternate credentials. 
#> 
Function Get-Uptime { 
    [CmdletBinding()] 
    param ( 
        [Parameter(Mandatory = $false, 
            Position = 0, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true)] 
        [Alias("Name")] 
        [string[]]$ComputerName = $env:COMPUTERNAME, 
        $Credential = [System.Management.Automation.PSCredential]::Empty 
    ) 
 
    begin {} 
 
    #Need to verify that the hostname is valid in DNS 
    process { 
        foreach ($Computer in $ComputerName) { 
            try { 
                $hostdns = [System.Net.DNS]::GetHostEntry($Computer) 
                $OS = Get-WmiObject win32_operatingsystem -ComputerName $Computer -ErrorAction Stop -Credential $Credential 
                $BootTime = $OS.ConvertToDateTime($OS.LastBootUpTime) 
                $Uptime = $OS.ConvertToDateTime($OS.LocalDateTime) - $boottime 
                $propHash = [ordered]@{ 
                    ComputerName = $Computer 
                    BootTime     = $BootTime 
                    Uptime       = $Uptime 
                } 
                $objComputerUptime = New-Object PSOBject -Property $propHash 
                $objComputerUptime 
            }  
            catch [Exception] { 
                Write-Output "$computer $($_.Exception.Message)" 
                #return 
            } 
        } 
    } 
    end {} 
}

<#
.Synopsis
   convert time derived in minutes to an actual time
.DESCRIPTION
   This is to help convert time in minutes from a db or other source into readable time
.EXAMPLE
   convert-mintotime -Min 234
.Example
    [datetime] $localtime = convert-mintotime -Min 234
    This will add current date to the local date/time variable, but can then convert or manuipulate returned variable
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