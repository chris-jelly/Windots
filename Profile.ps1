<#
    Author: Christopher Jelly
    Decription: Powershell profile containing customizations, aliases, functions, etc.
#>



#region moduleImports
Import-Module PSFramework
Import-Module Logging
Import-Module posh-git
#endregion moduleImports

#region Alias
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Set-Alias -Name su -Value Start-AdminSession
Set-Alias -Name up -Value Update-Profile
Set-Alias -Name ff -Value Find-File
Set-Alias -Name grep -Value Find-String
Set-Alias -Name touch -Value New-Item
Set-Alias -Name df -Value Get-Volume
Set-Alias -Name sed -Value Set-String
Set-Alias -Name which -Value Show-Command
Set-Alias -Name ll -Value Get-ChildItem
Set-Alias -Name la -Value Get-ChildItem
Set-Alias -Name l -Value Get-ChildItem
#endregion Alias

#region Functions
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

function Find-WindotsRepository {
    <#
    .SYNOPSIS
        Finds the local Windots repository.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$ProfilePath
    )

    Write-Verbose 'Resolving the symbolic link for the profile'
    $profileSymbolicLink = Get-ChildItem $ProfilePath | Where-Object FullName -EQ $PROFILE.CurrentUserAllHosts
    return Split-Path $profileSymbolicLink.Target
}

function Get-LatestProfile {
    <#
    .SYNOPSIS
        Checks the Github repository for the latest commit date and compares to the local version.
        If the profile is out of date, instructions are displayed on how to update it.
    #>

    Write-Verbose 'Checking for updates to the profile'
    $currentWorkingDirectory = $PWD
    Set-Location $ENV:WindotsLocalRepo
    $gitStatus = git status

    if ($gitStatus -like '*Your branch is up to date with*') {
        Write-Verbose 'Profile is up to date'
        Set-Location $currentWorkingDirectory
        return
    } else {
        Write-Verbose 'Profile is out of date'
        Write-Host 'Your PowerShell profile is out of date with the latest commit. To update it, run Update-Profile.' -ForegroundColor Yellow
        Set-Location $currentWorkingDirectory
    }
}

function Start-AdminSession {
    <#
    .SYNOPSIS
        Starts a new PowerShell session with elevated rights. Alias: su
    #>
    Start-Process wt -Verb runAs
}

function Update-Profile {
    <#
    .SYNOPSIS
        Downloads the latest version of the PowerShell profile from Github and updates the PowerShell profile with the latest version. Alternative to completely restarting the action session.
        Note that functions won't be updated, this requires a full restart. Alias: up
    #>
    Write-Verbose 'Storing current working directory in memory'
    $currentWorkingDirectory = $PWD
    Write-Verbose 'Updating local profile from Github repository'
    Set-Location $ENV:WindotsLocalRepo
    git pull | Out-Null
    Write-Verbose 'Reverting to previous working directory'
    Set-Location $currentWorkingDirectory
    Write-Verbose "Re-running profile script from $($PROFILE.CurrentUserAllHosts)"
    .$PROFILE.CurrentUserAllHosts
}

function Find-File {
    <#
    .SYNOPSIS
        Finds a file in the current directory and all subdirectories. Alias: ff
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline, Mandatory = $true, Position = 0)]
        [string]$SearchTerm
    )

    Write-Verbose "Searching for '$SearchTerm' in current directory and subdirectories"
    $result = Get-ChildItem -Recurse -Filter "*$SearchTerm*" -ErrorAction SilentlyContinue

    Write-Verbose 'Outputting results to table'
    $result | Format-Table -AutoSize
}

function Find-String {
    <#
    .SYNOPSIS
        Searches for a string in a file or directory. Alias: grep
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$SearchTerm,
        [Parameter(ValueFromPipeline, Mandatory = $false, Position = 1)]
        [string]$Directory,
        [Parameter(Mandatory = $false)]
        [switch]$Recurse
    )

    Write-Verbose "Searching for '$SearchTerm' in '$Directory'"
    if ($Directory) {
        if ($Recurse) {
            Write-Verbose "Searching for '$SearchTerm' in '$Directory' and subdirectories"
            Get-ChildItem -Recurse $Directory | Select-String $SearchTerm
            return
        }

        Write-Verbose "Searching for '$SearchTerm' in '$Directory'"
        Get-ChildItem $Directory | Select-String $SearchTerm
        return
    }

    if ($Recurse) {
        Write-Verbose "Searching for '$SearchTerm' in current directory and subdirectories"
        Get-ChildItem -Recurse | Select-String $SearchTerm
        return
    }

    Write-Verbose "Searching for '$SearchTerm' in current directory"
    Get-ChildItem | Select-String $SearchTerm
}

function Set-String {
    <#
    .SYNOPSIS
        Replaces a string in a file. Alias: sed
    .EXAMPLE
        Set-String -File "C:\Users\Scott\Documents\test.txt" -Find "Hello" -Replace "Goodbye"
    .EXAMPLE
        sed test.txt Hello Goodbye
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$File,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$Find,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$Replace
    )
    Write-Verbose "Replacing '$Find' with '$Replace' in '$File'"
    (Get-Content $File).replace("$Find", $Replace) | Set-Content $File
}

function Get-PublicIP {
    Invoke-WebRequest -Uri 'https://api.ipify.org'
}

function Show-Command {
    <#
    .SYNOPSIS
        Displays the definition of a command. Alias: which
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Name
    )
    Write-Verbose "Showing definition of '$Name'"
    Get-Command $Name | Select-Object -ExpandProperty Definition
}

function grep {
    $input | Out-String -Stream | Select-String $args
}

function Get-MailDomainInfo {
    param(
        [parameter(Mandatory = $true)][string]$DomainName,
        [parameter(Mandatory = $false)][string]$DNSserver
    )

    #Use DNS server 1.1.1.1 when parameter DNSserver is not used
    if (-not ($DNSserver)) {
        $DNSserver = '1.1.1.1'
    }

    #Retrieve all mail DNS records
    $autodiscoverA = (Resolve-DnsName -Name "autodiscover.$($domainname)" -Type A -Server $DNSserver -ErrorAction SilentlyContinue).IPAddress
    $autodiscoverCNAME = (Resolve-DnsName -Name "autodiscover.$($domainname)" -Type CNAME -Server $DNSserver -ErrorAction SilentlyContinue).NameHost
    $dkim1 = Resolve-DnsName -Name "selector1._domainkey.$($domainname)" -Type CNAME -Server $DNSserver -ErrorAction SilentlyContinue
    $dkim2 = Resolve-DnsName -Name "selector2._domainkey.$($domainname)" -Type CNAME -Server $DNSserver -ErrorAction SilentlyContinue
    $domain = Resolve-DnsName -Name $DomainName -Server $DNSserver -ErrorAction SilentlyContinue
    $dmarc = (Resolve-DnsName -Name "_dmarc.$($DomainName)" -Type TXT -Server $DNSserver -ErrorAction SilentlyContinue | Where-Object Strings -Match 'DMARC').Strings
    $mx = (Resolve-DnsName -Name $DomainName -Type MX -Server $DNSserver -ErrorAction SilentlyContinue).NameExchange
    $spf = (Resolve-DnsName -Name $DomainName -Type TXT -Server $DNSserver -ErrorAction SilentlyContinue | Where-Object Strings -Match 'v=spf').Strings

    #Set variables to Not enabled or found if they can't be retrieved
    #and stop script if domainname is not valid
    $errorfinding = 'Not enabled'
    if ($null -eq $domain) {
        Write-Warning ('{0} not found' -f $DomainName)
        return
    }

    if ($null -eq $dkim1 -and $null -eq $dkim2) {
        $dkim = $errorfinding
    } else {
        $dkim = "$($dkim1.Name) , $($dkim2.Name)"
    }

    if ($null -eq $dmarc) {
        $dmarc = $errorfinding
    }

    if ($null -eq $mx) {
        $mx = $errorfinding
    }

    if ($null -eq $spf) {
        $spf = $errorfinding
    }

    if (($autodiscoverA).count -gt 1) {
        $autodiscoverA = $errorfinding
    }

    if ($null -eq $autodiscoverCNAME) {
        $autodiscoverCNAME = $errorfinding
    }

    $info = [PSCustomObject]@{
        'Domain Name'             = $DomainName
        'Autodiscover IP-Address' = $autodiscoverA
        'Autodiscover CNAME '     = $autodiscoverCNAME
        'DKIM Record'             = $dkim
        'DMARC Record'            = "$($dmarc)"
        'MX Record(s)'            = $mx -join ', '
        'SPF Record'              = "$($spf)"
    }

    return $info

}

Function Set-PathVariable {
    param (
        [string]$AddPath,
        [string]$RemovePath
    )
    $regexPaths = @()
    if ($PSBoundParameters.Keys -contains 'AddPath') {
        $regexPaths += [regex]::Escape($AddPath)
    }

    if ($PSBoundParameters.Keys -contains 'RemovePath') {
        $regexPaths += [regex]::Escape($RemovePath)
    }

    $arrPath = $env:Path -split ';'
    foreach ($path in $regexPaths) {
        $arrPath = $arrPath | Where-Object { $_ -notMatch "^$path\\?" }
    }
    $env:Path = ($arrPath + $addPath) -join ';'
}

#endregion Functions

Set-PSReadLineOption -HistoryNoDuplicates:$true

# Include (don't RUN) the script by prefixing it with `.`
. C:\git\quick_scripts\Powershell\F7History.ps1

#region AWS
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Set-DefaultAWSRegion 'us-east-2'
# Retrieve Bitwarden jelly_desktop CLI token from AWS SSM
$env:BWS_ACCESS_TOKEN = Get-SSMParameter -Name /app/bitwarden -WithDecryption:$true | Select-Object -ExpandProperty Value
# Retrieve openAI token
$env:OpenAIKey = Get-SSMParameter -Name /app/open_ai_beta -WithDecryption:$true | Select-Object -ExpandProperty Value

#endregion AWS

# Add Bitwarden CLI Program to path
Set-PathVariable -AddPath 'C:\Program Files\bitwarden-cli'

# Custom Environment Variables
$ENV:IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ENV:WindotsLocalRepo = Find-WindotsRepository -ProfilePath $PSScriptRoot


#region PromptSetup
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

#Remove python venv environment variable
$env:VIRTUAL_ENV_DISABLE_PROMPT = 1

oh-my-posh init pwsh --config 'C:\git\quick_scripts\chris_custom_atomicBit.omp.json' | Invoke-Expression

# Check for updates
Get-LatestProfile