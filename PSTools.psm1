#Tools for powershell scripting

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

# This clears the screen of the output from the loading of the assembly.
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

function write-customlog
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Enter a string to identify the source (Example: -Event_Source "My App")
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $EventSource,

        #Enter a message to detail the alert
        [Parameter(Mandatory=$true, Position=1)]
        [String]$EventMessage,

                [Parameter(Mandatory=$true, Position=2)]
        # Enter a number for the event ID (Example: 9999)
        [int] $EventNum,

        [ValidateSet("Error", "Warning", "Information")][String]$EventType = "Error",

        #Enter the log name
        [ValidateSet("Application", "System", "Security")][String]$eventlogname = "Application" 
    )

    Begin
    {
    }
    Process
    {
         if ([system.diagnostics.eventlog]::SourceExists($EventSource) -eq $false ) {New-EventLog -LogName Application -Source $EventSource}
         Write-EventLog -LogName $eventlogname -Source $EventSource -EventID $EventNum -EntryType $EventType -Message $EventMessage
    }
    End
    {
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
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            Position=0)]
 
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
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")).sNames -contains 'RebootPending') {$PendingReboot = $true}
                    if (($WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")).sNames -contains 'RebootRequired') {$PendingReboot = $true}
 
                    #Checking for SCCM namespace
                    $SCCM_Namespace = Get-WmiObject -Namespace ROOT\CCM\ClientSDK -List -ComputerName $Computer -ErrorAction Ignore
                    if ($SCCM_Namespace) {
                        if (([WmiClass]"\\$Computer\ROOT\CCM\ClientSDK:CCM_ClientUtilities").DetermineIfRebootPending().RebootPending -eq 'True') {$PendingReboot = $true}   
                    }
 
 
                    if ($PendingReboot -eq $true) {
                        $Properties = @{ComputerName   = $Computer.ToUpper()
                                        PendingReboot  = 'True'
                                        }
                        $Object = New-Object -TypeName PSObject -Property $Properties | Select ComputerName, PendingReboot
                    } else {
                        $Properties = @{ComputerName   = $Computer.ToUpper()
                                        PendingReboot  = 'False'
                                        }
                        $Object = New-Object -TypeName PSObject -Property $Properties | Select ComputerName, PendingReboot
                    }
                }
                 
            } catch {
                $Properties = @{ComputerName   = $Computer.ToUpper()
                                PendingReboot  = 'Error'
                                }
                $Object = New-Object -TypeName PSObject -Property $Properties | Select ComputerName, PendingReboot
 
                $ErrorMessage = $Computer + " Error: " + $_.Exception.Message
                $ErrorsArray += $ErrorMessage
 
            } finally {
                Write-Output $Object
 
                $Object         = $null
                $ErrorMessage   = $null
                $Properties     = $null
                $WMI_Reg        = $null
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

Function get-rightstring {
   [CmdletBinding()]
 
   Param (
      [Parameter(Position=0, Mandatory=$True,HelpMessage="Enter a string of text")]
      [String]$text,
      [Parameter(Mandatory=$True)]
      [Int]$Length
   )
$startchar = [math]::min($text.length - $Length,$text.length)
$startchar = [math]::max(0, $startchar)
$right = $text.SubString($startchar ,[math]::min($text.length, $Length))
$right
}

function New-FolderIfMissing {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [string]$Path
    )
    process {
        if (-not (Test-Path -Path $Path -PathType Container)) {
            Write-Warning "$Path did not exist. Folder created."
            $null = New-Item -Path $Path -ItemType Directory
        }
    }
}


<#
.Synopsis
   Create PSQL User DSN
.DESCRIPTION
   This function will help create a user DSN to connect to Crewtrac or Movement control database. 
   This will allow differnt crewtrac environments on the same server under sepperate sessions, 
   a user DSN is needed instead of a system DSN for this to work.
.EXAMPLE
   add-psqldsn -environment 'Stage1' -Platform '32-bit' -application 'Movement Control' -DSNname 'FTPVServerDB'
   add-psqldsn -environment 'Stage1' -Platform '32-bit' -application 'Crewtrac' -DSNname 'Crewdata'
.EXAMPLE
   add-psqldsn -environment 'Stage2' -Platform '32-bit' -application 'Movement Control' -DSNname 'FliteStg2'
   add-psqldsn -environment 'Stage2' -Platform '32-bit' -application 'Crewtrac' -DSNname 'CrewStage2'
.EXAMPLE
   add-psqldsn -environment 'Stage3' -Platform '32-bit' -application 'Movement Control' -DSNname 'FTPVServerDB'
   add-psqldsn -environment 'Stage3' -Platform '32-bit' -application 'Crewtrac' -DSNname 'Crewdata'
.EXAMPLE
   add-psqldsn -environment 'Dev' -Platform '32-bit' -application 'Movement Control' -DSNname 'FTPVServerDB'
   add-psqldsn -environment 'Dev' -Platform '32-bit' -application 'Crewtrac' -DSNname 'Crewdata'
.EXAMPLE
   add-psqldsn -environment 'Training' -Platform '32-bit' -application 'Movement Control' -DSNname 'FTPVServerDB'
   add-psqldsn -environment 'Training' -Platform '32-bit' -application 'Crewtrac' -DSNname 'Crewdata'
#>
function add-psqldsn
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Choose an environment
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [Validateset("Prod","Stage1","Stage2","Stage3","Dev","Training")]
        $environment,

        # choose a platform 32-bit/64-bit
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [Validateset("32-bit","64-bit")]
        $Platform,

        #Choose which application Movement Control or Crewtrac
        [Parameter(Mandatory=$true)]
        [Validateset("Movement Control","Crewtrac")]
        $application,

        #name your odbc connection, default crewdata
        $DSNname="crewdata"

    )

    Begin
    {
        #configure DSN connection string
        switch ($environment)
        {
            'Prod' { 
                switch ($application)
                {
                    'Movement Control' {$parameter = @("ServerName=JBVSTMPDBS1000", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                    'Crewtrac' {$parameter = @("ServerName=JBVSTMPDBS1002", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                }
            }
            
            'Stage1' { 
                switch ($application)
                {
                    'Movement Control' {$parameter = @("ServerName=JBVSTMPDBS2000", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                    'Crewtrac' {$parameter = @("ServerName=JBVSTMPDBS2002", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                }
            }
            
            'Stage2' { 
                switch ($application)
                {
                    'Movement Control' {$parameter = @("ServerName=jbvstmpdbs2203", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                    'Crewtrac' {$parameter = @("ServerName=jbvstmpdbs2204", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                }
            }
            
            'Stage3' { 
                switch ($application)
                {
                    'Movement Control' {$parameter = @("ServerName=JBVSTMPDBS2301", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                    'Crewtrac' {$parameter = @("ServerName=JBVSTMPDBS2302", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                }
            }

            'Dev' { 
                switch ($application)
                {
                    'Movement Control' {$parameter = @("ServerName=JBVSTMPDBS9001", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                    'Crewtrac' {$parameter = @("ServerName=JBVSTMPDBS9002", "ArrayFetchOn=1", "DBQ=$($DSNname)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                }
            }

            'Training' { 
                switch ($application)
                {
                    'Movement Control' {$parameter = @("ServerName=JBVSTMPDBS9901", "ArrayFetchOn=1", "DBQ=$($DBName)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                    'Crewtrac' {$parameter = @("ServerName=JBVSTMPDBS9902", "ArrayFetchOn=1", "DBQ=$($DBName)", "PvTranslate=auto", "TCPPort=1583", "ArrayBufferSize=8", "TransportHint=TCP")}
                }
            }
        }

        #remove any existing DSN
        if ((Get-OdbcDsn -Name $DSNname -DsnType All -Platform All -ErrorAction SilentlyContinue) -ne $null){Remove-OdbcDsn -Name $DSNname -Platform $Platform -DsnType All }
    }
    Process
    {
        write-host "Creating user DSN...."
        Add-OdbcDsn  -Name $DSNname -DriverName "Pervasive ODBC Client Interface" -DsnType User -SetPropertyValue $parameter

    }
    End
    {
        if ((Get-OdbcDsn -Name $DSNname -DsnType User -Platform $Platform -ErrorAction SilentlyContinue) -ne $null) {Write-Information -MessageData "odbc created successfully"} else {Write-Error -Message "Error creating ODBC"}
    }
}

function Start-TcpListener ($port=80){
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
    While ($true){
        if (!$listener.Pending())
        {
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
    finally{
            $listener.stop()
            Write-host "Listener Closed Safely"
    }

}

#PowerShell Script Containing Function Used to Remove User Profiles & Additional Remnants of C:\Users Directory
#Developer: Andrew Saraceni (saraceni@wharton.upenn.edu)
#Date: 12/22/14

#Requires -Version 2.0

function Remove-UserProfile
{
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
        [Parameter(Position=0,Mandatory=$false)]
        [String[]]$Exclude,
        [Parameter(Position=1,Mandatory=$false)]
        [DateTime]$Before,
        [Parameter(Position=2,Mandatory=$false)]
        [Switch]$DirectoryCleanup
    )

    Write-Verbose "Gathering List of Profiles on $env:COMPUTERNAME to Remove..."

    $userProfileFilter = "Loaded = 'False' AND Special = 'False'"
    $cleanupExclusions = @("Public", "Default")

    if ($Exclude)
    {
        foreach ($exclusion in $Exclude)
        {
            $userProfileFilter += "AND NOT LocalPath LIKE '%$exclusion'"
            $cleanupExclusions += $exclusion
        }
    }

    if ($Before)
    {
        $userProfileFilter += "AND LastUseTime < '$Before'"

        $keepUserProfileFilter = "Special = 'False' AND LastUseTime >= '$Before'"
        $profilesToKeep = Get-WmiObject -Class Win32_UserProfile -Filter $keepUserProfileFilter -ErrorAction Stop

        foreach ($profileToKeep in $profilesToKeep)
        {
            try
            {
                $userSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier($($profileToKeep.SID))
                $userName = $userSID.Translate([System.Security.Principal.NTAccount])
                
                $keepUserName = $userName.Value -replace ".*\\", ""
                $cleanupExclusions += $keepUserName
            }
            catch [System.Security.Principal.IdentityNotMappedException]
            {
                Write-Warning "Cannot Translate SID to UserName - Not Adding Value to Exceptions List"
            }
        }
    }

    $profilesToDelete = Get-WmiObject -Class Win32_UserProfile -Filter $userProfileFilter -ErrorAction Stop

    if ($DirectoryCleanup)
    {
        $usersChildItem = Get-ChildItem -Path "C:\Users" -Exclude $cleanupExclusions

        foreach ($usersChild in $usersChildItem)
        {
            if ($profilesToDelete.LocalPath -notcontains $usersChild.FullName)
            {    
                try
                {
                    Write-Verbose "Additional Directory Cleanup - Removing $($usersChild.Name) on $env:COMPUTERNAME..."
                    
                    Remove-Item -Path $($usersChild.FullName) -Recurse -Force -ErrorAction Stop
                }
                catch [System.InvalidOperationException]
                {
                    Write-Verbose "Skipping Removal of $($usersChild.Name) on $env:COMPUTERNAME as Item is Currently In Use..."
                }
            }
        }
    }

    foreach ($profileToDelete in $profilesToDelete)
    {
        Write-Verbose "Removing Profile $($profileToDelete.LocalPath) & Associated Registry Keys on $env:COMPUTERNAME..."
                
        Remove-WmiObject -InputObject $profileToDelete -ErrorAction Stop
    }

    $finalChildItem = Get-ChildItem -Path "C:\Users" | Select-Object -Property Name, FullName, LastWriteTime
                
    return $finalChildItem
}

Function Get-PendingReboot
{
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
	[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
	[Alias("CN","Computer")]
	[String[]]$ComputerName="$env:COMPUTERNAME",
	[String]$ErrorLog
	)

Begin {  }## End Begin Script Block
Process {
  Foreach ($Computer in $ComputerName) {
	Try {
	    ## Setting pending values to false to cut down on the number of else statements
	    $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
                        
	    ## Setting CBSRebootPend to null since not all versions of Windows has this value
	    $CBSRebootPend = $null
						
	    ## Querying WMI for build version
	    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

	    ## Making registry connection to the local/remote computer
	    $HKLM = [UInt32] "0x80000002"
	    $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
						
	    ## If Vista/2008 & Above query the CBS Reg Key
	    If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
		    $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
		    $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
	    }
							
	    ## Query WUAU from the registry
	    $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
	    $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
						
	    ## Query PendingFileRenameOperations from the registry
	    $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
	    $RegValuePFRO = $RegSubKeySM.sValue

	    ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
	    $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
	    $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

	    ## Query ComputerName and ActiveComputerName from the registry
	    $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
	    $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")

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
	        NameSpace='ROOT\ccm\ClientSDK'
	        Class='CCM_ClientUtilities'
	        Name='DetermineIfRebootPending'
	        ComputerName=$Computer
	        ErrorAction='Stop'
	    }
	    ## Try CCMClientSDK
	    Try {
	        $CCMClientSDK = Invoke-WmiMethod @CCMSplat
	    } Catch [System.UnauthorizedAccessException] {
	        $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
	        If ($CcmStatus.Status -ne 'Running') {
	            Write-Warning "$Computer`: Error - CcmExec service is not running."
	            $CCMClientSDK = $null
	        }
	    } Catch {
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
	        Property=(
	            'Computer',
	            'CBServicing',
	            'WindowsUpdate',
	            'CCMClientSDK',
	            'PendComputerRename',
	            'PendFileRename',
	            'PendFileRenVal',
	            'RebootPending'
	        )}
	    New-Object -TypeName PSObject -Property @{
	        Computer=$WMI_OS.CSName
	        CBServicing=$CBSRebootPend
	        WindowsUpdate=$WUAURebootReq
	        CCMClientSDK=$SCCM
	        PendComputerRename=$CompPendRen
	        PendFileRename=$PendFileRename
	        PendFileRenVal=$RegValuePFRO
	        RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
	    } | Select-Object @SelectSplat

	} Catch {
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

function start-pause
{
    #Press any key to continue
    if ($PSise){

        read-host "Press ENTER to continue..."

    }Else{

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

function Get-odbcdata
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        $query=$(throw 'query is required.'),

        [Parameter(Mandatory = $True,
        ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        $DSN


    )

    Begin
    {
        
    }
    Process
    {

        
       $conn = New-Object System.Data.Odbc.OdbcConnection
       $conn.ConnectionString = "DSN=$($DSN);"
       $conn.open()
       $cmd = New-object System.Data.Odbc.OdbcCommand($query,$conn)
       $ds = New-Object system.Data.DataSet
       (New-Object system.Data.odbc.odbcDataAdapter($cmd)).fill($ds) | out-null
       $conn.close()
       $ds.Tables[0]

    }
    End
    {
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
		
		[Parameter(Position=0)]
		[System.String]$ProcessName='*',
		
		[Parameter(Position=1)]
		[System.String]$Address='*',		
		
		[Parameter(Position=2)]
		$Port='*',

		[Parameter(Position=3,
                   ValueFromPipeline = $True,
                   ValueFromPipelineByPropertyName = $True)]
        [System.String[]]$ComputerName=$env:COMPUTERNAME,

		[ValidateSet('*','tcp','udp')]
		[System.String]$Protocol='*',

		[ValidateSet('*','Closed','Close_Wait','Closing','Delete_Tcb','DeleteTcb','Established','Fin_Wait_1','Fin_Wait_2','Last_Ack','Listening','Syn_Received','Syn_Sent','Time_Wait','Unknown')]
		[System.String]$State='*',

        [switch]$ShowHostnames,
        
        [switch]$ShowProcessNames = $true,	

        [System.String]$TempFile = "C:\netstat.txt",

        [validateset('*','IPv4','IPv6')]
        [string]$AddressFamily = '*'
	)
    
	begin{
        #Define properties
            $properties = 'ComputerName','Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','State','ProcessName','PID'

        #store hostnames in array for quick lookup
            $dnsCache = @{}
            
	}
	
	process{

        foreach($Computer in $ComputerName) {

            #Collect processes
            if($ShowProcessNames){
                Try {
                    $processes = Get-Process -ComputerName $Computer -ErrorAction stop | select name, id
                }
                Catch {
                    Write-warning "Could not run Get-Process -computername $Computer.  Verify permissions and connectivity.  Defaulting to no ShowProcessNames"
                    $ShowProcessNames = $false
                }
            }
	    
            #Handle remote systems
                if($Computer -ne $env:COMPUTERNAME){

                    #define command
                        [string]$cmd = "cmd /c c:\windows\system32\netstat.exe -ano >> $tempFile"
            
                    #define remote file path - computername, drive, folder path
                        $remoteTempFile = "\\{0}\{1}`${2}" -f "$Computer", (split-path $tempFile -qualifier).TrimEnd(":"), (Split-Path $tempFile -noqualifier)

                    #delete previous results
                        Try{
                            $null = Invoke-WmiMethod -class Win32_process -name Create -ArgumentList "cmd /c del $tempFile" -ComputerName $Computer -ErrorAction stop
                        }
                        Catch{
                            Write-Warning "Could not invoke create win32_process on $Computer to delete $tempfile"
                        }

                    #run command
                        Try{
                            $processID = (Invoke-WmiMethod -class Win32_process -name Create -ArgumentList $cmd -ComputerName $Computer -ErrorAction stop).processid
                        }
                        Catch{
                            #If we didn't run netstat, break everything off
                            Throw $_
                            Break
                        }

                    #wait for process to complete
                        while (
                            #This while should return true until the process completes
                                $(
                                    try{
                                        get-process -id $processid -computername $Computer -ErrorAction Stop
                                    }
                                    catch{
                                        $FALSE
                                    }
                                )
                        ) {
                            start-sleep -seconds 2 
                        }
            
                    #gather results
                        if(test-path $remoteTempFile){
                    
                            Try {
                                $results = Get-Content $remoteTempFile | Select-String -Pattern '\s+(TCP|UDP)'
                            }
                            Catch {
                                Throw "Could not get content from $remoteTempFile for results"
                                Break
                            }

                            Remove-Item $remoteTempFile -force

                        }
                        else{
                            Throw "'$tempFile' on $Computer converted to '$remoteTempFile'.  This path is not accessible from your system."
                            Break
                        }
                }
                else{
                    #gather results on local PC
                        $results = netstat -ano | Select-String -Pattern '\s+(TCP|UDP)'
                }

            #initialize counter for progress
                $totalCount = $results.count
                $count = 0
    
            #Loop through each line of results    
	            foreach($result in $results) {
            
    	            $item = $result.line.split(' ',[System.StringSplitOptions]::RemoveEmptyEntries)
    
    	            if($item[1] -notmatch '^\[::'){
                    
                        #parse the netstat line for local address and port
    	                    if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $localAddress = $la.IPAddressToString
    	                        $localPort = $item[1].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $localAddress = $item[1].split(':')[0]
    	                        $localPort = $item[1].split(':')[-1]
    	                    }
                    
                        #parse the netstat line for remote address and port
    	                    if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6'){
    	                        $remoteAddress = $ra.IPAddressToString
    	                        $remotePort = $item[2].split('\]:')[-1]
    	                    }
    	                    else {
    	                        $remoteAddress = $item[2].split(':')[0]
    	                        $remotePort = $item[2].split(':')[-1]
    	                    }

                        #Filter IPv4/IPv6 if specified
                            if($AddressFamily -ne "*")
                            {
                                if($AddressFamily -eq 'IPv4' -and $localAddress -match ':' -and $remoteAddress -match ':|\*' )
                                {
                                    #Both are IPv6, or ipv6 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                                elseif($AddressFamily -eq 'IPv6' -and $localAddress -notmatch ':' -and ( $remoteAddress -notmatch ':' -or $remoteAddress -match '*' ) )
                                {
                                    #Both are IPv4, or ipv4 and listening, skip
                                    Write-Verbose "Filtered by AddressFamily:`n$result"
                                    continue
                                }
                            }
    	    		
                        #parse the netstat line for other properties
    	    		        $procId = $item[-1]
    	    		        $proto = $item[0]
    	    		        $status = if($item[0] -eq 'tcp') {$item[3]} else {$null}	

                        #Filter the object
		    		        if($remotePort -notlike $Port -and $localPort -notlike $Port){
                                write-verbose "remote $Remoteport local $localport port $port"
                                Write-Verbose "Filtered by Port:`n$result"
                                continue
		    		        }

		    		        if($remoteAddress -notlike $Address -and $localAddress -notlike $Address){
                                Write-Verbose "Filtered by Address:`n$result"
                                continue
		    		        }
    	    			     
    	    			    if($status -notlike $State){
                                Write-Verbose "Filtered by State:`n$result"
                                continue
		    		        }

    	    			    if($proto -notlike $Protocol){
                                Write-Verbose "Filtered by Protocol:`n$result"
                                continue
		    		        }
                   
                        #Display progress bar prior to getting process name or host name
                            Write-Progress  -Activity "Resolving host and process names"`
                                -Status "Resolving process ID $procId with remote address $remoteAddress and local address $localAddress"`
                                -PercentComplete (( $count / $totalCount ) * 100)
    	    		
                        #If we are running showprocessnames, get the matching name
                            if($ShowProcessNames -or $PSBoundParameters.ContainsKey -eq 'ProcessName'){
                        
                                #handle case where process spun up in the time between running get-process and running netstat
                                if($procName = $processes | Where {$_.id -eq $procId} | select -ExpandProperty name ){ }
                                else {$procName = "Unknown"}

                            }
                            else{$procName = "NA"}

		    		        if($procName -notlike $ProcessName){
                                Write-Verbose "Filtered by ProcessName:`n$result"
                                continue
		    		        }
    	    						
                        #if the showhostnames switch is specified, try to map IP to hostname
                            if($showHostnames){
                                $tmpAddress = $null
                                try{
                                    if($remoteAddress -eq "127.0.0.1" -or $remoteAddress -eq "0.0.0.0"){
                                        $remoteAddress = $Computer
                                    }
                                    elseif($remoteAddress -match "\w"){
                                        
                                        #check with dns cache first
                                            if ($dnsCache.containskey( $remoteAddress)) {
                                                $remoteAddress = $dnsCache[$remoteAddress]
                                                write-verbose "using cached REMOTE '$remoteAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $remoteAddress
                                                    $remoteAddress = [System.Net.DNS]::GetHostByAddress("$remoteAddress").hostname
                                                    $dnsCache.add($tmpAddress, $remoteAddress)
                                                    write-verbose "using non cached REMOTE '$remoteAddress`t$tmpAddress"
                                            }
                                    }
                                }
                                catch{ }

                                try{

                                    if($localAddress -eq "127.0.0.1" -or $localAddress -eq "0.0.0.0"){
                                        $localAddress = $Computer
                                    }
                                    elseif($localAddress -match "\w"){
                                        #check with dns cache first
                                            if($dnsCache.containskey($localAddress)){
                                                $localAddress = $dnsCache[$localAddress]
                                                write-verbose "using cached LOCAL '$localAddress'"
                                            }
                                            else{
                                                #if address isn't in the cache, resolve it and add it
                                                    $tmpAddress = $localAddress
                                                    $localAddress = [System.Net.DNS]::GetHostByAddress("$localAddress").hostname
                                                    $dnsCache.add($localAddress, $tmpAddress)
                                                    write-verbose "using non cached LOCAL '$localAddress'`t'$tmpAddress'"
                                            }
                                    }
                                }
                                catch{ }
                            }
    
    	    		    #Write the object	
    	    		        New-Object -TypeName PSObject -Property @{
		    		            ComputerName = $Computer
                                PID = $procId
		    		            ProcessName = $procName
		    		            Protocol = $proto
		    		            LocalAddress = $localAddress
		    		            LocalPort = $localPort
		    		            RemoteAddress =$remoteAddress
		    		            RemotePort = $remotePort
		    		            State = $status
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
        [Parameter(Mandatory=$false, 
                        Position=0, 
                        ValueFromPipeline=$true, 
                        ValueFromPipelineByPropertyName=$true)] 
        [Alias("Name")] 
        [string[]]$ComputerName=$env:COMPUTERNAME, 
        $Credential = [System.Management.Automation.PSCredential]::Empty 
        ) 
 
    begin{} 
 
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
    end{} 
}

<#
    Simple screen writer with timestamp 
#>
function Write-TS {
    param(
        [string]$Message,
        [string]$Color 
    )

    $ts = (Get-Date -Format 's')
    if ($Color) {
        Write-Host "[$ts]: $Message" -ForegroundColor $Color
    }
    else {
        Write-Host "[$ts]: $Message"
    }
}

function Write-Log {
    param([string]$msg)

    if (-not $LogPath) {
        # no logpath defined → just print to console
        Write-Host $msg
        return
    }

    try {
        # ensure folder exists
        $dir = Split-Path $LogPath -Parent
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        # ensure file exists
        if (-not (Test-Path $LogPath)) {
            New-Item -ItemType File -Path $LogPath -Force | Out-Null
        }

        # write line with timestamp
        "[{0}] {1}" -f (Get-Date -Format s), $msg | Add-Content -Path $LogPath -Encoding utf8
    }
    catch {
        Write-Warning "Write-Log failed: $($_.Exception.Message)"
        Write-Host $msg
    }
}

# SIG # Begin signature block
# MIIb1AYJKoZIhvcNAQcCoIIbxTCCG8ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSoZPQpjZEJuEUdyKBlNHtb8K
# vtagghZEMIIDBjCCAe6gAwIBAgIQEBhQPUc10ahAl/Rc6gVKqzANBgkqhkiG9w0B
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
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTvdugUhAJxtEq9GeG2c0EqTT+YsDANBgkq
# hkiG9w0BAQEFAASCAQBsqm3iS7Y2HeDUkTZkoCQioYknmrxby+XIjO72gAGAF08j
# g/qBeESItJHbMpJDcNcOvlg+NymxEfHBSFJE91PjYDR5wN4eW/2ozn0k3eckyPVy
# hU2BUnHCAtMCyVNGBosJ0knmqWVptvvQ09Hgw3HKGbNXNJr0t9ZPR3vo6575jeWV
# AV2wyZZAfy0XIRYPRxNqepnzW6ZYLwkL28q0IaeO37YKH2GTIAqhTSwq77abxKXo
# vufO5ezrsZerRjaaba1RaSG7z7Dvh4fXJrXy828sxyId90foy/43/q9dLqB99PBT
# UaGPrk2y4lG/TdbwTupR6gnCxLqqmvaAWZpJlqHyoYIDJjCCAyIGCSqGSIb3DQEJ
# BjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglg
# hkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcN
# AQkFMQ8XDTI2MDIwMzE0NDgyMFowLwYJKoZIhvcNAQkEMSIEIJ8j2h6VqN630L4Z
# 6JQ8PTVFOz7mZ5d8ZGDPAyD6m6ZTMA0GCSqGSIb3DQEBAQUABIICAKiybxoJFriW
# dBclKs7thLGOPE94kKUCvsKpb4+q4E43Quxzkm7ls+Ia6je2JZRXYJQ7Knvgwyhg
# uRFLk9jYBZ+z5xho9C4HbEzSnIW/UZQm78FhZxOIsqxPEqRPfvHxNEpc4/Wltdar
# mCJBl4URjVJyST6pO5dcX7Sp8HNM53+RZ7ev26EKNsG2fPidv5LpIFyUsrqyeEij
# ZqWCmp8NOlNf68BU8QLBOJQE1cm6ckkzlrtYH0yMC//ixnl+qFtLjrTOuPPnRi4C
# Y6E+9wbylaUG39S/Fg9G/fQr7anbK9dV9EdKEUZiV8I2LQRTXko6GayQMGKHdhcm
# c9bxphlYMryu/j7VYdBEcxUAWwn/azPjsvnUcGhHcZ6N9+eG4luY0CHQIhZxQ6M1
# kQKoA4jECY8nGHi9vY1iSNEAFtGhUlLe3EkoyrrEFN+WZX2d+/iAZMoctXbfuKHa
# +2LYw/TkFaF360jwkyxP17mB7BmfU8hGx7XTqUrQARlkO6kDGWu9D/nTyRkZ2yzv
# rQX4Y5MhtfXr+RKcz+IyqvAOTTmvQUGPWDT6sTeQa4WLFMB41POwdwkfFvWihCgp
# e8dUAfexhoI1kEJndZyRRRBWYLh1IGLsWwpX3DKN7DkZM9LQni/eC1MMp/rOQLK+
# 6ZnMnMwTMdA3x+84qZ0petbPruTqF/bo
# SIG # End signature block
