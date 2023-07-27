# Elevated privileges required for creating symbolic links
#Requires -RunAsAdministrator


Set-Location $PSScriptRoot

# Make sure Oh My Posh is installed
$ompPath = (Get-Command oh-my-posh).Source
if (!(Test-Path $ompPath)) {
    winget install -e -h --id=JanDeDobbeleer.oh-my-posh
}

# Create Symbolic link to Profile.ps1 in PowerShell profile directory
New-Item -ItemType SymbolicLink -Path $PROFILE.CurrentUserAllHosts -Target (Resolve-Path .\Profile.ps1) -Force

# Install Terminal-Icons module
Install-Module -Name Terminal-Icons -Repository PSGallery

# Get all installed font families
[void] [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
$fontFamilies = (New-Object System.Drawing.Text.InstalledFontCollection).Families

# Check if MesloLGS is installed
if ($fontFamilies -notcontains 'CaskaydiaCove NF') {
    # Download and install CaskaydiaCove NF
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile('https://github.com/ryanoasis/nerd-fonts/releases/download/v3.0.2/CascadiaCode.zip', '.\CascadiaCode.zip')

    Expand-Archive -Path '.\CascadiaCode.zip' -DestinationPath '.\CascadiaCode' -Force
    $destination = (New-Object -ComObject Shell.Application).Namespace(0x14)
    Get-ChildItem -Path '.\CascadiaCode' -Recurse -Filter '*.ttf' | ForEach-Object {
        If (-not(Test-Path "C:\Windows\Fonts\$($_.Name)")) {
            # Install font
            $destination.CopyHere($_.FullName, 0x10)
        }
    }

    Remove-Item -Path '.\CascadiaCode' -Recurse -Force
    Remove-Item -Path '.\CascadiaCode.zip' -Force
}

$terminalSettings = Get-Content -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json" | ConvertFrom-Json -Depth 20


if ($terminalSettings.profiles.defaults.font.face -ne 'CaskaydiaCove Nerd Font Mono') {
    $font = @{
        'face' = 'CaskaydiaCove Nerd Font Mono'
    }
    Add-Member -InputObject $terminalSettings.profiles.defaults -MemberType NoteProperty -Name 'font' -Value $font -Force

    $terminalSettings | ConvertTo-Json -Depth 20 | Set-Content -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json" -Force
}
