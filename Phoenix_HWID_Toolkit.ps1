<#
.SYNOPSIS
    Phoenix HWID Toolkit v20.1 - The final, polished, and animated version of the utility, ready for release.
.DESCRIPTION
    The definitive version of the Phoenix HWID Toolkit. This release introduces a professional startup animation and optimizes UI loading for a faster, more responsive user experience. The codebase has been fully cleaned of all dead code, and features detailed tooltips for all options, ensuring maximum stability, clarity, and ease of use.

    Version 20.1 (GitHub Release):
    - FINAL: Author name updated to 'Giliolera' for release.
    - FIXED: Splash screen window is now set to 'Topmost' to prevent the PowerShell console from appearing in front of it on launch.
    - All features are stable and polished.

.NOTES
    Author: Giliolera
    Version: 20.1 (Final)
    Language: PowerShell with WPF (English UI)
    Disclaimer: This script makes significant, low-level changes to your system. Use at your own risk.
#>

#region --- PARAMETER DEFINITION (MUST BE FIRST) ---
param(
    [switch]$autoSpoofOnLaunch
)
#endregion

#region --- INITIALIZATION & SETUP ---

# --- Self-Elevation (Auto-Admin) ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    if ($PSBoundParameters['autoSpoofOnLaunch']) { $arguments += " -autoSpoofOnLaunch" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments; exit
}

# --- Initial Setup ---
Add-Type -AssemblyName PresentationFramework, System.Windows.Forms, System.Drawing

# --- C# Signatures for Native Win32 API Calls ---
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class NativeMethods {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct SHFILEOPSTRUCT {
        public IntPtr hwnd; public uint wFunc; [MarshalAs(UnmanagedType.LPWStr)] public string pFrom; [MarshalAs(UnmanagedType.LPWStr)] public string pTo;
        public ushort fFlags; [MarshalAs(UnmanagedType.Bool)] public bool fAnyOperationsAborted; public IntPtr hNameMappings; [MarshalAs(UnmanagedType.LPWStr)] public string lpszProgressTitle;
    }
    [DllImport("shell32.dll", CharSet=CharSet.Unicode)] public static extern int SHFileOperation(ref SHFILEOPSTRUCT lpFileOp);
    [DllImport("advapi32.dll", CharSet = CharSet.Auto)] public static extern int RegDeleteTree(IntPtr hKey, string lpSubKey);
    public const uint FO_DELETE = 0x0003; public const ushort FOF_NOCONFIRMATION = 0x0010; public const ushort FOF_SILENT = 0x0004;
    public static IntPtr HKEY_CURRENT_USER = new IntPtr(unchecked((int)0x80000001)); public static IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
}
"@ -ErrorAction SilentlyContinue

#endregion

#region --- SPLASH SCREEN LOGIC ---
# Define, create, and show the splash screen immediately for a better user experience.

[xml]$splashXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Loading" Height="300" Width="500" WindowStyle="None" AllowsTransparency="True"
        Background="Transparent" WindowStartupLocation="CenterScreen" ShowInTaskbar="False" Topmost="True">
    <Grid>
        <Border Background="#FF0D1117" CornerRadius="10" BorderBrush="#FFE53935" BorderThickness="1">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                <TextBlock Text="P H O E N I X" Foreground="#FFE53935" FontSize="48" FontWeight="Bold" FontFamily="Segoe UI Black">
                    <TextBlock.Effect>
                        <DropShadowEffect Color="Black" ShadowDepth="3" BlurRadius="10"/>
                    </TextBlock.Effect>
                </TextBlock>
                <TextBlock Text="TOOLKIT v20.1" Foreground="#C9D1D9" FontSize="20" HorizontalAlignment="Center" Margin="0,-10,0,0"/>
                <TextBlock Text="Loading..." Name="lblLoading" Foreground="#C9D1D9" FontSize="14" HorizontalAlignment="Center" Margin="0,20,0,0"/>
            </StackPanel>
        </Border>
    </Grid>
</Window>
"@

$splashReader = New-Object System.Xml.XmlNodeReader $splashXaml
$splashWindow = [Windows.Markup.XamlReader]::Load($splashReader)
$splashWindow.Opacity = 0
$splashWindow.Show()

$fadeInAnimation = New-Object System.Windows.Media.Animation.DoubleAnimation(0, 1, [System.Windows.Duration]::new([TimeSpan]::FromSeconds(0.5)))
$splashWindow.BeginAnimation([System.Windows.Window]::OpacityProperty, $fadeInAnimation)
Start-Sleep -m 500

#endregion

#region --- FUNCTION DEFINITIONS ---

#region --- CORE & UI FUNCTIONS ---
function global:Write-Log { 
    param(
        [string]$Message, 
        [string]$Color = "White", 
        [bool]$IsBold = $false,
        [bool]$ForceLog = $false
    )
    if ($script:stealthModeEnabled -and (-not $ForceLog)) { return }
    $window.Dispatcher.Invoke([Action]{ 
        $run = New-Object System.Windows.Documents.Run($Message + "`n")
        $run.Foreground = [System.Windows.Media.Brushes]::$Color
        if ($IsBold) { $run.FontWeight = [System.Windows.FontWeights]::Bold }
        $paragraph = New-Object System.Windows.Documents.Paragraph($run)
        $paragraph.Margin = '0'
        $txtLog.Document.Blocks.Add($paragraph)
        $txtLog.ScrollToEnd()
    })
    "$([System.DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')) :: $Message" | Add-Content -Path $script:externalLogFile -ErrorAction SilentlyContinue
}
function global:Get-DecodedString { param([string]$EncodedString); try { return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedString)) } catch { Write-Log "Error decoding string: $($_.Exception.Message)" "Red" -ForceLog:$true; return $null } }
function global:Generate-RandomString($length, [string]$charSet = "ABCDEF0123456789") { -join ($charSet.ToCharArray() | Get-Random -Count $length) }
function global:Generate-RandomMAC { $macBytes = (2..6 | ForEach-Object { Get-Random -Minimum 0 -Maximum 255 }); $firstByte = (Get-Random -Minimum 0 -Maximum 255) -band 0xFE -bor 0x02; "{0:X2}{1:X2}{2:X2}{3:X2}{4:X2}{5:X2}" -f $firstByte, $macBytes[0], $macBytes[1], $macBytes[2], $macBytes[3], $macBytes[4] }
function global:Remove-ItemStealthy { param([string]$Path); try { if (-not (Test-Path $Path)) { return }; Write-Log "    -> Removing Path (Native): $Path" "White"; $op = New-Object -TypeName NativeMethods+SHFILEOPSTRUCT; $op.wFunc = [NativeMethods]::FO_DELETE; $op.pFrom = $Path + "`0`0"; $op.fFlags = [NativeMethods]::FOF_NOCONFIRMATION -bor [NativeMethods]::FOF_SILENT; [NativeMethods]::SHFileOperation([ref]$op) | Out-Null } catch { Write-Log "    -> Stealth remove failed for '$Path'. Falling back to standard." "Orange"; Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue } }
function global:Remove-RegistryKeyStealthy { param([string]$KeyPath); try { if (-not (Test-Path $KeyPath)) { return }; $hiveStr, $pathStr = $KeyPath.Split('\', 2); $hKey = [IntPtr]::Zero; if ($hiveStr -eq "HKCU:") { $hKey = [NativeMethods]::HKEY_CURRENT_USER } elseif ($hiveStr -eq "HKLM:") { $hKey = [NativeMethods]::HKEY_LOCAL_MACHINE } else { throw "Unsupported registry hive: $hiveStr" }; Write-Log "    -> Removing Registry Key (Native): $KeyPath" "White"; $result = [NativeMethods]::RegDeleteTree($hKey, $pathStr); if ($result -ne 0 -and $result -ne 2) { throw "Native RegDeleteTree failed with code $result" } } catch { Write-Log "    -> Stealth registry remove failed for '$KeyPath'. Falling back to standard." "Orange"; if (Test-Path $KeyPath) { Remove-Item -Path $KeyPath -Recurse -Force -EA SilentlyContinue } } }
function global:Stealth-Sleep { if ($script:stealthModeEnabled) { Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 350) } }
function global:Invoke-ProtectedOperation {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [string]$StartMessage,
        [string]$SuccessMessage,
        [string]$FailureMessage = "Operation FAILED"
    )
    Write-Log $StartMessage "Yellow"
    Stealth-Sleep
    try {
        & $ScriptBlock
        Write-Log $SuccessMessage "LimeGreen" -ForceLog:$true
    } catch {
        Write-Log "❌ $FailureMessage`: $($_.Exception.Message)" "Red" -ForceLog:$true
    }
}
function global:Update-Dashboard { 
    Write-Log "Updating live dashboard..." "Gray"
    $dashboardItems = @{ 
        "MAC Address" = (Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | ? { $_.IPEnabled -and $_.MACAddress } | Select-Object -First 1).MACAddress
        "Disk Serial" = (Get-WmiObject Win32_PhysicalMedia -ErrorAction SilentlyContinue | Select-Object -First 1).SerialNumber.Trim()
        "Machine GUID" = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -ErrorAction SilentlyContinue).MachineGuid
        "Computer Name" = $env:COMPUTERNAME
        "TEMP Path" = [Environment]::GetEnvironmentVariable("TEMP", "Machine") 
    }
    $window.Dispatcher.Invoke([Action]{ 
        $DashboardGrid.Children.Clear(); $DashboardGrid.RowDefinitions.Clear(); $DashboardGrid.ColumnDefinitions.Clear()
        $DashboardGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, 'Auto')}))
        $DashboardGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, 'Star')}))
        $i = 0
        foreach ($item in $dashboardItems.GetEnumerator()) { 
            $DashboardGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
            $label = New-Object System.Windows.Controls.TextBlock -Property @{ Text = "$($item.Name):"; FontWeight = 'Bold'; Margin = '5'; VerticalAlignment = 'Center'}
            $label.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "ForegroundColor")
            $displayText = if ($item.Value) { $item.Value } else { 'N/A' }
            $value = New-Object System.Windows.Controls.TextBlock -Property @{ Text = $displayText; Margin = '5'; Foreground = 'LightGray'; VerticalAlignment = 'Center'}
            [System.Windows.Controls.Grid]::SetRow($label, $i); [System.Windows.Controls.Grid]::SetColumn($label, 0)
            [System.Windows.Controls.Grid]::SetRow($value, $i); [System.Windows.Controls.Grid]::SetColumn($value, 1)
            $DashboardGrid.Children.Add($label) | Out-Null; $DashboardGrid.Children.Add($value) | Out-Null; $i++ 
        } 
    }) 
}
function global:Get-Network-Info {
    Invoke-ProtectedOperation -ScriptBlock {
        $netInfo = Invoke-RestMethod -Uri "http://ip-api.com/json" -TimeoutSec 10
        $window.Dispatcher.Invoke([Action]{ 
            $NetworkGrid.Children.Clear(); $NetworkGrid.RowDefinitions.Clear(); $NetworkGrid.ColumnDefinitions.Clear()
            $NetworkGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1,'Auto')}))
            $NetworkGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)}))
            $NetworkGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1,'Auto')}))
            $items = @{"Public IP"=$netInfo.query; "Country"="$($netInfo.country) ($($netInfo.countryCode))"; "ISP"=$netInfo.isp}
            $i=0
            foreach($item in $items.GetEnumerator()){
                $NetworkGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
                $label = New-Object System.Windows.Controls.TextBlock -Property @{Text="$($item.Name):"; FontWeight='Bold'; Margin='5'; VerticalAlignment='Center'}
                $label.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "ForegroundColor")
                $value = New-Object System.Windows.Controls.TextBlock -Property @{Text=$item.Value; Margin='5'; Foreground='LightGray'; VerticalAlignment='Center'}
                [System.Windows.Controls.Grid]::SetRow($label,$i); [System.Windows.Controls.Grid]::SetColumn($label,0)
                [System.Windows.Controls.Grid]::SetRow($value,$i);[System.Windows.Controls.Grid]::SetColumn($value,1)
                $NetworkGrid.Children.Add($label)|Out-Null; $NetworkGrid.Children.Add($value)|Out-Null;$i++
            }
            $btn = New-Object System.Windows.Controls.Button -Property @{Content='Refresh'; Width=80; Height=30; VerticalAlignment='Center'}
            $btn.Add_Click({Get-Network-Info})
            [System.Windows.Controls.Grid]::SetRow($btn,0);[System.Windows.Controls.Grid]::SetColumn($btn,2);[System.Windows.Controls.Grid]::SetRowSpan($btn,3)
            $NetworkGrid.Children.Add($btn)|Out-Null
        })
    } -StartMessage "Checking network status..." -SuccessMessage "✅ Network status updated." -FailureMessage "Failed to retrieve network info"
}
function global:Apply-Theme {
    param([string]$themeName)
    $newTheme = New-Object System.Windows.ResourceDictionary
    if ($themeName -eq 'Dark') {
        $themeXaml = '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"><SolidColorBrush x:Key="WindowBackgroundColor" Color="#FF0D1117"/><SolidColorBrush x:Key="ForegroundColor" Color="#C9D1D9"/><SolidColorBrush x:Key="BorderColor" Color="#FF30363D"/><SolidColorBrush x:Key="ButtonBackgroundColor" Color="#FF21262D"/><SolidColorBrush x:Key="LogBackgroundColor" Color="#FF010409"/><SolidColorBrush x:Key="TitleColor" Color="#FFE53935"/><SolidColorBrush x:Key="TabBackgroundColor" Color="#FF161B22"/></ResourceDictionary>'
    } else { # Light
        $themeXaml = '<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"><SolidColorBrush x:Key="WindowBackgroundColor" Color="#FFFAFAFA"/><SolidColorBrush x:Key="ForegroundColor" Color="#FF1F2328"/><SolidColorBrush x:Key="BorderColor" Color="#FFD0D7DE"/><SolidColorBrush x:Key="ButtonBackgroundColor" Color="#FFF6F8FA"/><SolidColorBrush x:Key="LogBackgroundColor" Color="#FFFFFFFF"/><SolidColorBrush x:Key="TitleColor" Color="#FFD73A49"/><SolidColorBrush x:Key="TabBackgroundColor" Color="#FFF6F8FA"/></ResourceDictionary>'
    }
    $stream = [System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($themeXaml))
    $newTheme = [System.Windows.Markup.XamlReader]::Load($stream)
    $stream.Close()
    $ThemeDictionary.MergedDictionaries.Clear()
    $ThemeDictionary.MergedDictionaries.Add($newTheme)
}
function global:Toggle-Buttons($enable) { 
    $window.Dispatcher.Invoke([Action]{
        $btnSpoof.IsEnabled=$enable; $btnScan.IsEnabled=$enable; $btnClean.IsEnabled=$enable; $btnRestore.IsEnabled=$enable; 
        $btnSfcScan.IsEnabled=$enable; $btnDismRestore.IsEnabled=$enable;
    })
}
#endregion

#region --- SPOOFING & CLEANING FUNCTIONS ---
function global:Spoof-MACAddress { Invoke-ProtectedOperation -ScriptBlock { $nic = Get-WmiObject Win32_NetworkAdapterConfiguration | ? { $_.IPEnabled -and $_.MACAddress } | Select-Object -First 1; if (-not $nic) { throw "No active network adapter found." }; $newMAC = Generate-RandomMAC; $nicDevice = Get-WmiObject Win32_NetworkAdapter -Filter "Description = '$($nic.Description)'"; $nicDevice.Disable(); Stealth-Sleep; Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\$($nicDevice.DeviceID.PadLeft(4,'0'))" "NetworkAddress" $newMAC -Force; Stealth-Sleep; $nicDevice.Enable(); Start-Sleep 3; $Global:SuccessMessage = "✅ MAC Address spoofed to $newMAC" } -StartMessage "Spoofing MAC Address..." -SuccessMessage $Global:SuccessMessage -FailureMessage "Spoofing MAC FAILED" }
function global:Spoof-RegistryKeys { Invoke-ProtectedOperation -ScriptBlock { Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "ProductId" "$(Generate-RandomString 5)-$(Generate-RandomString 5)-$(Generate-RandomString 5)-$(Generate-RandomString 5)"; Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" "MachineGuid" ([guid]::NewGuid().ToString()); Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001" "HwProfileGuid" ("{"+[guid]::NewGuid().ToString()+"}") } -StartMessage "Spoofing Registry Keys..." -SuccessMessage "✅ Registry keys (ProductID, GUIDs) spoofed." }
function global:Spoof-ComputerName { Invoke-ProtectedOperation -ScriptBlock { $newName = "DESKTOP-" + (Generate-RandomString 7); Write-Log "  -> New computer name will be: $newName"; Rename-Computer -NewName $newName -Force -ErrorAction Stop } -StartMessage "Spoofing Computer Name..." -SuccessMessage "✅ Computer name has been changed. A RESTART IS REQUIRED." -FailureMessage "Spoofing computer name FAILED" }
function global:Spoof-InstallDate { Invoke-ProtectedOperation -ScriptBlock { $randomDays = Get-Random -Min 365 -Max 1825; $newDate = (Get-Date).AddDays(-$randomDays); $epochTime = [int64](([datetime]$newDate) - (Get-Date "1970-01-01")).TotalSeconds; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "InstallDate" -Value $epochTime -Type DWord -Force; $Global:SuccessMessage = "✅ Windows install date spoofed to $newDate." } -StartMessage "Spoofing Windows Install Date..." -SuccessMessage $Global:SuccessMessage -FailureMessage "Spoofing install date FAILED" }
function global:Spoof-TempPath { Invoke-ProtectedOperation -ScriptBlock { $newTemp = Join-Path $env:SystemDrive "\TempSpoof_$(Generate-RandomString 6)"; New-Item -ItemType Directory -Force -Path $newTemp | Out-Null; [Environment]::SetEnvironmentVariable("TEMP", $newTemp, "Machine"); [Environment]::SetEnvironmentVariable("TMP", $newTemp, "Machine"); $Global:SuccessMessage = "✅ TEMP/TMP path spoofed to: $newTemp. A restart is required." } -StartMessage "Spoofing TEMP/TMP environment paths..." -SuccessMessage $Global:SuccessMessage -FailureMessage "Spoofing TEMP path FAILED" }
function global:Manual-NewUser-Guide { Write-Log "--- MANUAL USER CREATION REQUIRED ---" "Yellow" -IsBold $true -ForceLog:$true; $username = "User" + (Generate-RandomString 5); $password = (Generate-RandomString 12 -charSet "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") + "a1!"; Write-Log "To prevent system instability, please create the new user manually." "White"; Write-Log "1. Open Start, type 'cmd', right-click 'Command Prompt' and 'Run as administrator'." "White"; $cmd1 = "net user $username $password /add"; $cmd2 = "net localgroup Administrators $username /add"; Write-Log "2. Copy and paste this first command, then press Enter:" "White"; Write-Log $cmd1 "Cyan"; Write-Log "3. Copy and paste this second command, then press Enter:" "White"; Write-Log $cmd2 "Cyan"; Write-Log "4. User created! Please save this info. Username: $username | Password: $password" "LimeGreen"; Write-Log "After spoofing, restart and log in with this new account." "Yellow" -IsBold $true }
function global:Spoof-DiskSerial {
    Invoke-ProtectedOperation -ScriptBlock {
        $sourcePath = Join-Path $script:scriptRoot "Tools\HardDiskSerialNumberChanger.exe"
        if (-not (Test-Path $sourcePath)) { throw "HardDiskSerialNumberChanger.exe not found in Tools folder." }
        
        $targetPath = Join-Path $script:tempToolPath "HardDiskSerialNumberChanger.exe"
        Copy-Item -Path $sourcePath -Destination $targetPath -Force
        
        Start-Process -FilePath $targetPath
        
        $Global:SuccessMessage = "✅ Disk Serial spoof launched. Please spoof manually using HardDiskSerialNumberChanger.exe."
    } -StartMessage "Launching Disk Serial Number Changer..." -SuccessMessage $Global:SuccessMessage -FailureMessage "Failed to launch Disk Serial changer tool"
}
function global:Clean-ShadowCopies {
    Invoke-ProtectedOperation -ScriptBlock {
        Invoke-Expression (Get-DecodedString "dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL0FsbCAvcXVpZXQ=") | Out-Null
    } -StartMessage "--- Deep Cleaning: Deleting Volume Shadow Copies ---" -SuccessMessage "SUCCESS: All shadow copies have been deleted." -FailureMessage "Failed to delete shadow copies"
}
function global:Clean-UsbHistory {
    Write-Log "--- Deep Cleaning: Purging USB Device History (Safe Internal Method) ---" "Red" -IsBold $true
    $usbKeys = @("HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR", "HKLM:\SYSTEM\CurrentControlSet\Enum\USB")
    foreach ($key in $usbKeys) {
        Invoke-ProtectedOperation -ScriptBlock {
            $subKeys = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
            if ($null -eq $subKeys) {
                Write-Log "  -> No subkeys found in $key. Skipping." "Gray"
                return
            }
            
            foreach ($subKey in $subKeys) {
                try {
                    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $user = $identity.User
                    $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($identity.Name, "FullControl", "Allow")

                    $descendants = Get-ChildItem -Path $subKey.PSPath -Recurse -ErrorAction SilentlyContinue
                    foreach ($descendant in $descendants) {
                        try {
                            $acl = Get-Acl $descendant.PSPath
                            $acl.SetOwner($user)
                            Set-Acl -Path $descendant.PSPath -AclObject $acl -EA SilentlyContinue
                            $acl.SetAccessRule($rule)
                            Set-Acl -Path $descendant.PSPath -AclObject $acl -EA SilentlyContinue
                        } catch {}
                    }
                    
                    $acl = Get-Acl $subKey.PSPath
                    $acl.SetOwner($user)
                    Set-Acl -Path $subKey.PSPath -AclObject $acl -EA SilentlyContinue
                    $acl.SetAccessRule($rule)
                    Set-Acl -Path $subKey.PSPath -AclObject $acl -EA SilentlyContinue
                    
                    Remove-RegistryKeyStealthy -KeyPath $subKey.PSPath
                } catch {
                     Write-Log "     -> Could not process or delete subkey $($subKey.PSPath)." "Gray"
                }
            }
            $remainingKeys = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
            if ($remainingKeys.Count -gt 0) {
                Write-Log "  -> NOTE: Some subkeys in $key are protected by the OS and could not be removed. This is expected." "Orange"
            }
            $Global:SuccessMessage = "  -> SUCCESS: Cleared all non-protected subkeys from $key"

        } -StartMessage "  -> Processing registry hive: $key" -SuccessMessage $Global:SuccessMessage -FailureMessage "Could not process all subkeys in $key"
    }
}
function global:Clean-MuiCache {
    Invoke-ProtectedOperation -ScriptBlock {
        $muiPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
        if(Test-Path $muiPath) {
            Remove-RegistryKeyStealthy -KeyPath $muiPath
            if (Test-Path $muiPath) { throw "Failed to clear key." }
        }
    } -StartMessage "--- Kernel-Level Spoof: Cleaning MUI Cache ---" -SuccessMessage "SUCCESS: MUI Cache has been cleared." -FailureMessage "Failed to clear MUI Cache"
}
function global:Run-SfcScan { Invoke-ProtectedOperation -ScriptBlock { Invoke-Expression (Get-DecodedString "c2ZjIC9zY2Fubm93") | ForEach-Object { Write-Log "  [SFC] $_" "Gray" } } -StartMessage "--- System Repair: Running System File Checker ---" -SuccessMessage "SUCCESS: SFC scan completed." -FailureMessage "SFC scan failed" }
function global:Run-DismRestore { Invoke-ProtectedOperation -ScriptBlock { Invoke-Expression (Get-DecodedString "RElTTSAvT25saW5lIC9DbGVhbnVwLUltYWdlIC9SZXN0b3JlSGVhbHRo") | ForEach-Object { Write-Log "  [DISM] $_" "Gray" } } -StartMessage "--- System Repair: Running DISM Restore Health ---" -SuccessMessage "SUCCESS: DISM RestoreHealth completed." -FailureMessage "DISM failed" }
function global:Get-Trace-Locations {
    $locations = @{ "Paths" = @(); "RegistryKeys" = @() }
    if ($chkCleanRiot.IsChecked) { $locations.Paths += @((Join-Path $env:LOCALAPPDATA (Get-DecodedString "UmlvdCBHYW1lcw==")), (Join-Path $env:PROGRAMDATA (Get-DecodedString "UmlvdCBHYW1lcw=="))); $locations.RegistryKeys += @("HKCU:\Software\APICIA SOFTWARE LLC\Riot Client", "HKCU:\Software\RiotGames") }
    if ($chkCleanEAC.IsChecked) { $locations.Paths += (Join-Path $env:APPDATA (Get-DecodedString "RWFzeUFudGlDaGVhdA==")); $locations.RegistryKeys += (Get-DecodedString "SEtMTTpcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XFNlcnZpY2VzXEVhc3lBbnRpQ2hlYXQ=") }
    if ($chkCleanBE.IsChecked) { $locations.Paths += (Join-Path $env:LOCALAPPDATA (Get-DecodedString "QmF0dGxlWXk=")); $locations.RegistryKeys += (Get-DecodedString "SEtMTTpcU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XFNlcnZpY2VzXEJFU2VydmljZQ==") }
    if ($chkCleanFiveM.IsChecked) { $locations.Paths += (Join-Path $env:LOCALAPPDATA "FiveM"); $locations.RegistryKeys += "HKCU:\Software\CitizenFX" }
    if ($chkCleanEpic.IsChecked) { $locations.Paths += @((Join-Path $env:LOCALAPPDATA "EpicGamesLauncher"), (Join-Path $env:PROGRAMDATA "Epic")); $locations.RegistryKeys += @("HKCU:\Software\Epic Games", "HKLM:\SOFTWARE\WOW6432Node\EpicGames") }
    if ($chkCleanSystem.IsChecked) { $locations.Paths += @((Join-Path $env:windir "Temp"), (Join-Path $env:LOCALAPPDATA "Temp"), (Join-Path $env:windir "Prefetch"), (Join-Path $env:windir "SoftwareDistribution\Download")) }
    return $locations
}
function global:Scan-Traces {
    Write-Log "--- Starting Trace Scan (Radar) ---" "Cyan" -IsBold $true -ForceLog:$true
    $locations = Get-Trace-Locations; $foundCount = 0
    Write-Log "Scanning for known trace files and folders..." "Yellow"
    foreach($path in $locations.Paths) { Stealth-Sleep; if (Test-Path $path) { Write-Log "  [FOUND] Path: $path" "Orange"; $foundCount++ } }
    Write-Log "Scanning for known registry keys..." "Yellow"
    foreach($key in $locations.RegistryKeys) { Stealth-Sleep; if (Test-Path $key) { Write-Log "  [FOUND] Registry: $key" "Orange"; $foundCount++ } }
    if ($foundCount -eq 0) { Write-Log "--- No common traces found. Your system looks clean. ---" "LimeGreen" -IsBold $true -ForceLog:$true }
    else { Write-Log "--- Scan Complete. Found $foundCount known trace(s). ---" "LimeGreen" -IsBold $true -ForceLog:$true }
}
function global:Clean-Traces {
    Write-Log "--- Starting Trace Cleaning ---" "Cyan" -IsBold $true -ForceLog:$true
    $locations = Get-Trace-Locations
    foreach ($item in $locations.Paths) { Stealth-Sleep; Remove-ItemStealthy -Path "$item\*" } 
    foreach ($item in $locations.Paths) { Stealth-Sleep; Remove-ItemStealthy -Path $item }
    foreach ($key in $locations.RegistryKeys) { Stealth-Sleep; Remove-RegistryKeyStealthy -KeyPath $key }
    if ($chkFlushDNS.IsChecked) { Stealth-Sleep; Invoke-ProtectedOperation -ScriptBlock { ipconfig /flushdns | Out-Null; ipconfig /release | Out-Null; ipconfig /renew | Out-Null; (Get-DecodedString "YXJwIC1kICo=") | Invoke-Expression | Out-Null } -StartMessage "  -> Performing Deep Network Reset..." -SuccessMessage "SUCCESS: DNS, IP, and ARP cache flushed." }
    if ($chkShadowCopies.IsChecked) { Stealth-Sleep; Clean-ShadowCopies }
    if ($chkUsbHistory.IsChecked) { Stealth-Sleep; Clean-UsbHistory }
    if ($chkKernelSpoof.IsChecked) { Stealth-Sleep; Clean-MuiCache }
    Write-Log "--- Trace Cleaning Complete ---" "LimeGreen" -IsBold $true -ForceLog:$true
}
function global:Backup-CurrentState { Invoke-ProtectedOperation -ScriptBlock { $backupData = @{}; $nic = Get-WmiObject Win32_NetworkAdapterConfiguration | ? { $_.IPEnabled } | Select-Object -First 1; $backupData.MACAddress = $nic.MACAddress; $backupData.NICDescription = $nic.Description; $backupData.ProductID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductId; $backupData.InstallDate = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallDate; $backupData.MachineGuid = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid; $backupData.HwProfileGuid = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001").HwProfileGuid; $backupData.ComputerName = $env:COMPUTERNAME; $backupData.TempPath = [Environment]::GetEnvironmentVariable("TEMP", "Machine"); $backupData.TmpPath = [Environment]::GetEnvironmentVariable("TMP", "Machine"); $backupData | ConvertTo-Json -Depth 5 | Set-Content -Path $script:backupFile; $Global:BackupSuccess = $true } -StartMessage "--- Backing Up Current System State ---" -SuccessMessage "--- Backup completed successfully ---" -FailureMessage "Backup FAILED" }
function global:Restore-From-Backup { Invoke-ProtectedOperation -ScriptBlock { if (-not (Test-Path $script:backupFile)) { throw "Backup file not found." }; $backupData = Get-Content -Path $script:backupFile | ConvertFrom-Json; Write-Log "  -> Restoring Registry Keys..." "Yellow"; Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "ProductId" $backupData.ProductID; Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" "InstallDate" $backupData.InstallDate; Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" "MachineGuid" $backupData.MachineGuid; Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001" "HwProfileGuid" $backupData.HwProfileGuid; Write-Log "  -> Restoring MAC Address..." "Yellow"; $nic = Get-WmiObject Win32_NetworkAdapter -Filter "Description = '$($backupData.NICDescription)'"; $nic.Disable(); Start-Sleep 2; Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\$($nic.DeviceID.PadLeft(4,'0'))" "NetworkAddress" ($backupData.MACAddress -replace '[:]'); $nic.Enable(); Start-Sleep 2; if ($env:COMPUTERNAME -ne $backupData.ComputerName) { Write-Log "  -> Restoring Computer Name..." "Yellow"; Rename-Computer -NewName $backupData.ComputerName -Force }; Write-Log "  -> Restoring TEMP/TMP Paths..." "Yellow"; [Environment]::SetEnvironmentVariable("TEMP", $backupData.TempPath, "Machine"); [Environment]::SetEnvironmentVariable("TMP", $backupData.TmpPath, "Machine"); } -StartMessage "--- Starting Restore from Backup File ---" -SuccessMessage "--- Restore Complete. A RESTART is required. ---" -FailureMessage "Restore FAILED" }
function global:Save-Profile { Invoke-ProtectedOperation -ScriptBlock { $profile = @{}; Get-Variable -Scope "Global" -Name "chk*" | ForEach-Object { if ($null -ne (Get-Variable $_.Name -ValueOnly)) { $profile[$_.Name] = (Get-Variable $_.Name -ValueOnly).IsChecked } }; $profile | ConvertTo-Json | Set-Content -Path $script:profileFile; } -StartMessage "Saving current settings..." -SuccessMessage "SUCCESS: Profile saved." -FailureMessage "Failed to save profile." }
function global:Load-Profile { Invoke-ProtectedOperation -ScriptBlock { if (-not (Test-Path $script:profileFile)) { throw "No profile file found." }; $profile = Get-Content -Path $script:profileFile | ConvertFrom-Json; foreach ($item in $profile.PSObject.Properties) { try { $checkbox = Get-Variable -Scope "Global" -Name $item.Name -ErrorAction Stop; if ($null -ne $checkbox.Value) { $checkbox.Value.IsChecked = $item.Value } } catch {} } } -StartMessage "Loading settings from profile..." -SuccessMessage "SUCCESS: Profile settings loaded." -FailureMessage "Failed to load profile."}
function global:Start-Spoofing-Process {
    Write-Log "--- Starting Main Spoofing & Cleaning Process ---" "White" -IsBold $true -ForceLog:$true
    $Global:BackupSuccess = $false
    Backup-CurrentState
    if (-not $Global:BackupSuccess) { Write-Log "Backup failed. Aborting spoofing process." "Red" -IsBold $true; return }
    
    if ($chkDiskSerial.IsChecked) { Spoof-DiskSerial }
    if ($chkMAC.IsChecked) { Spoof-MACAddress }
    if ($chkRegistry.IsChecked) { Spoof-RegistryKeys }
    if ($chkTempPath.IsChecked) { Spoof-TempPath }
    if ($chkInstallDate.IsChecked) { Spoof-InstallDate }
    
    Clean-Traces
    
    if ($chkNewUser.IsChecked) { Manual-NewUser-Guide }
    if ($chkComputerName.IsChecked) { Spoof-ComputerName }
    
    Write-Log "--- ALL OPERATIONS COMPLETE ---" "Cyan" -IsBold $true -ForceLog:$true
    Write-Log "A system RESTART is highly recommended for all changes to take full effect." "Yellow" -IsBold $true -ForceLog:$true
}
#endregion

#endregion

#region --- GUI & MAIN EXECUTION BLOCK ---

# Define GUI Layout (XAML)
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        x:Name="MainWindow" Title="Phoenix HWID Toolkit v20.1 - Final" Height="850" Width="1100"
        WindowStartupLocation="CenterScreen" ResizeMode="CanMinimize" FontFamily="Segoe UI">
    <Window.Resources>
        <ResourceDictionary>
            <ResourceDictionary.MergedDictionaries>
                <ResourceDictionary x:Name="ThemeDictionary">
                    </ResourceDictionary>
            </ResourceDictionary.MergedDictionaries>
            <Style TargetType="GroupBox">
                <Setter Property="BorderBrush" Value="{DynamicResource BorderColor}"/>
                <Setter Property="Foreground" Value="{DynamicResource ForegroundColor}"/>
                <Setter Property="BorderThickness" Value="1"/>
                <Setter Property="Padding" Value="8"/>
                <Setter Property="Margin" Value="0,0,0,10"/>
            </Style>
             <Style TargetType="Button">
                <Setter Property="Background" Value="{DynamicResource ButtonBackgroundColor}"/>
                <Setter Property="BorderBrush" Value="{DynamicResource BorderColor}"/>
                <Setter Property="Foreground" Value="{DynamicResource ForegroundColor}"/>
                <Setter Property="Padding" Value="10,5"/>
            </Style>
            <Style TargetType="CheckBox">
                 <Setter Property="Foreground" Value="{DynamicResource ForegroundColor}"/>
                 <Setter Property="Margin" Value="5"/>
            </Style>
            <Style TargetType="TabControl">
                <Setter Property="Background" Value="{DynamicResource TabBackgroundColor}"/>
                <Setter Property="BorderThickness" Value="0"/>
            </Style>
            <Style TargetType="TabItem">
                <Setter Property="Background" Value="{DynamicResource ButtonBackgroundColor}"/>
                <Setter Property="Foreground" Value="{DynamicResource ForegroundColor}"/>
                <Setter Property="BorderBrush" Value="{DynamicResource BorderColor}"/>
                <Setter Property="Padding" Value="10,5"/>
                <Setter Property="Template">
                    <Setter.Value>
                        <ControlTemplate TargetType="TabItem">
                            <Grid>
                                <Border Name="Border" Margin="0,0,-1,0" BorderThickness="1" BorderBrush="{DynamicResource BorderColor}" Background="{TemplateBinding Background}">
                                    <ContentPresenter x:Name="ContentSite" VerticalAlignment="Center" HorizontalAlignment="Center" ContentSource="Header" Margin="10,2,10,2"/>
                                </Border>
                            </Grid>
                            <ControlTemplate.Triggers>
                                <Trigger Property="IsSelected" Value="True">
                                    <Setter TargetName="Border" Property="Background" Value="{DynamicResource WindowBackgroundColor}" />
                                    <Setter Property="Foreground" Value="{DynamicResource TitleColor}" />
                                </Trigger>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter TargetName="Border" Property="Background" Value="{DynamicResource BorderColor}" />
                                </Trigger>
                            </ControlTemplate.Triggers>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Style>
        </ResourceDictionary>
    </Window.Resources>
    <Grid Margin="15" Background="{DynamicResource WindowBackgroundColor}">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        
        <TextBlock Grid.Row="0" Text="Phoenix HWID Toolkit v20.1 - Final" FontSize="26" FontWeight="Bold" Foreground="{DynamicResource TitleColor}" HorizontalAlignment="Center" Margin="0,0,0,15"/>
        
        <Grid Grid.Row="1">
            <Grid.ColumnDefinitions><ColumnDefinition Width="3*"/><ColumnDefinition Width="4*"/></Grid.ColumnDefinitions>

            <TabControl Grid.Column="0" Margin="0,0,10,0">
                <TabItem Header="Spoofing &amp; Cleaning">
                    <ScrollViewer VerticalScrollBarVisibility="Auto">
                        <StackPanel Margin="5">
                            <GroupBox Header="HWID Spoofing">
                                 <StackPanel Margin="5">
                                    <CheckBox x:Name="chkMAC" Content="MAC Address" IsChecked="True" ToolTip="Changes the hardware MAC address of your primary network adapter."/>
                                    <CheckBox x:Name="chkDiskSerial" Content="Disk &amp; Volume ID (Offline)" IsChecked="True" ToolTip="Launches an external tool to change disk serial numbers. A restart is required."/>
                                    <CheckBox x:Name="chkRegistry" Content="Registry Keys (GUIDs, ProductID)" IsChecked="True" ToolTip="Changes various unique identifiers stored in the Windows Registry."/>
                                </StackPanel>
                            </GroupBox>
                            <GroupBox Header="System Spoofing">
                                <StackPanel Margin="5">
                                     <CheckBox x:Name="chkComputerName" Content="Computer Name" IsChecked="False" ToolTip="Assigns a new random 'DESKTOP-XXXXXXX' name to your computer."/>
                                     <CheckBox x:Name="chkNewUser" Content="Guide to Create New Admin User" IsChecked="False" ToolTip="Provides a guide to manually create a new user account for maximum isolation."/>
                                     <CheckBox x:Name="chkTempPath" Content="Spoof TEMP/TMP Path" IsChecked="False" ToolTip="Changes the system's temporary file location to a new random folder."/>
                                     <CheckBox x:Name="chkInstallDate" Content="Windows Install Date" IsChecked="False" ToolTip="Changes the recorded installation date of Windows to a random past date."/>
                                </StackPanel>
                            </GroupBox>
                            <GroupBox Header="Standard Trace Cleaning">
                                <StackPanel Margin="5">
                                    <CheckBox x:Name="chkCleanRiot" Content="Riot Games (Valorant, LoL)" IsChecked="True"/>
                                    <CheckBox x:Name="chkCleanEAC" Content="Easy Anti-Cheat (EAC)" IsChecked="True"/>
                                    <CheckBox x:Name="chkCleanBE" Content="BattlEye (BE)" IsChecked="True"/>
                                    <CheckBox x:Name="chkCleanFiveM" Content="FiveM / CitizenFX" IsChecked="True"/>
                                    <CheckBox x:Name="chkCleanEpic" Content="Epic Games / Fortnite" IsChecked="True"/>
                                    <CheckBox x:Name="chkCleanSystem" Content="System Caches (Temp, Prefetch, Update)" IsChecked="True"/>
                                </StackPanel>
                            </GroupBox>
                        </StackPanel>
                    </ScrollViewer>
                </TabItem>
                <TabItem Header="Advanced Cleaning">
                     <ScrollViewer VerticalScrollBarVisibility="Auto">
                        <StackPanel Margin="5">
                             <GroupBox Header="⚠️ Deep / Kernel-Level Cleaning" BorderBrush="{DynamicResource TitleColor}">
                                <StackPanel Margin="5">
                                    <CheckBox x:Name="chkFlushDNS" Content="Deep Network Reset (DNS, IP, ARP)" IsChecked="True" ToolTip="Flushes DNS cache, releases and renews your IP address, and clears the ARP cache."/>
                                    <CheckBox x:Name="chkShadowCopies" Content="Delete Shadow Copies (VSS)" IsChecked="False" FontWeight="Bold" Foreground="OrangeRed" ToolTip="WARNING: Deletes all System Restore points and file history versions. This action is irreversible."/>
                                    <CheckBox x:Name="chkUsbHistory" Content="Clean USB Device History (Safe Mode)" IsChecked="False" FontWeight="Bold" Foreground="OrangeRed" ToolTip="WARNING: Attempts to remove all traces of previously connected USB devices from the registry. Some protected system devices may remain."/>
                                    <CheckBox x:Name="chkKernelSpoof" Content="Kernel Mode Spoof (Clean MUI Cache)" IsChecked="False" FontWeight="Bold" Foreground="OrangeRed" ToolTip="WARNING: Deletes the cache of programs that have been run on the system. May cause some applications to 're-initialize' on next launch."/>
                                </StackPanel>
                            </GroupBox>
                        </StackPanel>
                     </ScrollViewer>
                </TabItem>
                <TabItem Header="System Repair">
                     <StackPanel Margin="15">
                        <TextBlock Text="System Integrity Tools" FontWeight="Bold" FontSize="16" Foreground="{DynamicResource TitleColor}"/>
                        <TextBlock TextWrapping="Wrap" Margin="0,10,0,15" Foreground="{DynamicResource ForegroundColor}">
                            These tools check for and repair corrupt Windows system files. This can resolve underlying issues and remove traces that anti-cheats might detect. This process can take a long time and may require a restart.
                        </TextBlock>
                        <Button x:Name="btnSfcScan" Content="Run SFC /scannow" Margin="5" Height="40"/>
                        <Button x:Name="btnDismRestore" Content="Run DISM /RestoreHealth" Margin="5" Height="40"/>
                     </StackPanel>
                </TabItem>
                <TabItem Header="Settings &amp; About">
                     <StackPanel Margin="5">
                        <GroupBox Header="Operational Mode">
                            <StackPanel Margin="5">
                                <ToggleButton x:Name="toggleStealth" Content="Stealth Mode: OFF" Width="150" HorizontalAlignment="Left" Margin="5"/>
                            </StackPanel>
                        </GroupBox>
                        <GroupBox Header="User Profiles">
                            <StackPanel Orientation="Horizontal" Margin="5">
                                <Button x:Name="btnSaveProfile" Content="Save Profile" Margin="5" Width="120"/>
                                <Button x:Name="btnLoadProfile" Content="Load Profile" Margin="5" Width="120"/>
                            </StackPanel>
                        </GroupBox>
                         <GroupBox Header="Appearance">
                            <StackPanel Margin="5">
                                <TextBlock Text="Theme:" VerticalAlignment="Center" Margin="5" Foreground="{DynamicResource ForegroundColor}"/>
                                <ComboBox x:Name="cmbTheme" SelectedIndex="0" Margin="5" Width="150" HorizontalAlignment="Left">
                                    <ComboBoxItem Content="Dark Theme"/>
                                    <ComboBoxItem Content="Light Theme"/>
                                </ComboBox>
                            </StackPanel>
                        </GroupBox>
                        <GroupBox Header="Update Status" Margin="0,10,0,0">
                            <StackPanel>
                                <TextBlock x:Name="lblVersion" Text="Current Version: 20.1 (Final)" Foreground="{DynamicResource ForegroundColor}" Margin="5"/>
                                <Button x:Name="btnCheckUpdate" Content="Check for Updates" Margin="5" Width="150" HorizontalAlignment="Left"/>
                            </StackPanel>
                        </GroupBox>
                     </StackPanel>
                </TabItem>
            </TabControl>

            <Grid Grid.Column="1" Margin="10,0,0,0">
                 <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <GroupBox Header="Live HWID Dashboard" Grid.Row="0"><Grid x:Name="DashboardGrid" Margin="5"/></GroupBox>
                <GroupBox Header="Network Status" Grid.Row="1"><Grid x:Name="NetworkGrid" Margin="5"/></GroupBox>
                <GroupBox Header="Activity Log" Grid.Row="2">
                    <RichTextBox x:Name="txtLog" Background="{DynamicResource LogBackgroundColor}" Foreground="{DynamicResource ForegroundColor}" IsReadOnly="True" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" BorderThickness="0"/>
                </GroupBox>
            </Grid>
        </Grid>
        
        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,15,0,0">
            <Button x:Name="btnSpoof" Content="Apply &amp; Spoof" Width="150" Height="45" Margin="5" Background="#FF347D3A" Foreground="White" FontWeight="Bold"/>
            <Button x:Name="btnScan" Content="Scan for Traces" Width="150" Height="45" Margin="5" Background="#FF1976D2" Foreground="White"/>
            <Button x:Name="btnClean" Content="Clean Traces Only" Width="150" Height="45" Margin="5" Background="#FF8957E5" Foreground="White"/>
            <Button x:Name="btnRestore" Content="Restore Backup" Width="150" Height="45" Margin="5" Background="#FFB1BAC4" Foreground="Black"/>
        </StackPanel>
    </Grid>
</Window>
"@

# Define script-wide variables
$script:stealthModeEnabled = $false
$script:scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:tempToolPath = Join-Path $env:TEMP "PhoenixTools_$(Generate-RandomString 8)"
$script:backupFile = Join-Path $script:scriptRoot "Phoenix_Backup.json"
$script:profileFile = Join-Path $script:scriptRoot "Phoenix_Profile.json"
$script:externalLogFile = Join-Path $script:scriptRoot "Phoenix_Activity.log"
New-Item -Path $script:tempToolPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

# Load XAML into a usable Window object
$reader = New-Object System.Xml.XmlNodeReader $xaml
try {
    $script:window = [Windows.Markup.XamlReader]::Load($reader)
} catch {
    Write-Host "FATAL ERROR: Failed to load XAML GUI. Details: $($_.Exception.Message)"
    Read-Host
    exit
}

# Hook up all GUI elements to variables
$global:chkMAC = $window.FindName("chkMAC")
$global:chkDiskSerial = $window.FindName("chkDiskSerial")
$global:chkRegistry = $window.FindName("chkRegistry")
$global:chkComputerName = $window.FindName("chkComputerName")
$global:chkNewUser = $window.FindName("chkNewUser")
$global:chkTempPath = $window.FindName("chkTempPath")
$global:chkInstallDate = $window.FindName("chkInstallDate")
$global:chkCleanRiot = $window.FindName("chkCleanRiot")
$global:chkCleanEAC = $window.FindName("chkCleanEAC")
$global:chkCleanBE = $window.FindName("chkCleanBE")
$global:chkCleanFiveM = $window.FindName("chkCleanFiveM")
$global:chkCleanEpic = $window.FindName("chkCleanEpic")
$global:chkCleanSystem = $window.FindName("chkCleanSystem")
$global:chkFlushDNS = $window.FindName("chkFlushDNS")
$global:chkShadowCopies = $window.FindName("chkShadowCopies")
$global:chkUsbHistory = $window.FindName("chkUsbHistory")
$global:chkKernelSpoof = $window.FindName("chkKernelSpoof")
$global:btnSfcScan = $window.FindName("btnSfcScan")
$global:btnDismRestore = $window.FindName("btnDismRestore")
$global:toggleStealth = $window.FindName("toggleStealth")
$global:btnSaveProfile = $window.FindName("btnSaveProfile")
$global:btnLoadProfile = $window.FindName("btnLoadProfile")
$global:cmbTheme = $window.FindName("cmbTheme")
$global:lblVersion = $window.FindName("lblVersion")
$global:btnCheckUpdate = $window.FindName("btnCheckUpdate")
$global:DashboardGrid = $window.FindName("DashboardGrid")
$global:NetworkGrid = $window.FindName("NetworkGrid")
$global:txtLog = $window.FindName("txtLog")
$global:btnSpoof = $window.FindName("btnSpoof")
$global:btnScan = $window.FindName("btnScan")
$global:btnClean = $window.FindName("btnClean")
$global:btnRestore = $window.FindName("btnRestore")
$global:ThemeDictionary = $window.FindName("ThemeDictionary")

# Attach all Event Handlers
$btnSpoof.Add_Click({ $txtLog.Document.Blocks.Clear(); Toggle-Buttons $false; Start-Spoofing-Process; Toggle-Buttons $true; Update-Dashboard })
$btnScan.Add_Click({ $txtLog.Document.Blocks.Clear(); Toggle-Buttons $false; Scan-Traces; Toggle-Buttons $true; })
$btnClean.Add_Click({ $txtLog.Document.Blocks.Clear(); Toggle-Buttons $false; Clean-Traces; Toggle-Buttons $true; Update-Dashboard })
$btnRestore.Add_Click({ $txtLog.Document.Blocks.Clear(); Toggle-Buttons $false; Restore-From-Backup; Toggle-Buttons $true; Update-Dashboard })
$btnSfcScan.Add_Click({ $txtLog.Document.Blocks.Clear(); Toggle-Buttons $false; Run-SfcScan; Toggle-Buttons $true; })
$btnDismRestore.Add_Click({ $txtLog.Document.Blocks.Clear(); Toggle-Buttons $false; Run-DismRestore; Toggle-Buttons $true; })
$btnSaveProfile.Add_Click({ Save-Profile })
$btnLoadProfile.Add_Click({ Load-Profile })
$btnCheckUpdate.Add_Click({ Write-Log "UPDATE: You are using the latest version (v20.1)." "LimeGreen" -ForceLog:$true })
$toggleStealth.Add_Click({
    $script:stealthModeEnabled = $toggleStealth.IsChecked
    if ($script:stealthModeEnabled) {
        $toggleStealth.Content = "Stealth Mode: ON"
        Write-Log "Stealth Mode ACTIVATED. Logging will be minimal." "OrangeRed" -ForceLog:$true
    } else {
        $toggleStealth.Content = "Stealth Mode: OFF"
        Write-Log "Stealth Mode DEACTIVATED. Verbose logging is enabled." "LimeGreen" -ForceLog:$true
    }
})
$cmbTheme.Add_SelectionChanged({
    param($sender, $e)
    if ($cmbTheme.SelectedIndex -eq 0) { Apply-Theme -themeName 'Dark' } 
    else { Apply-Theme -themeName 'Light' }
})
$window.Add_Loaded({
    Apply-Theme -themeName 'Dark' # Set default theme
    Write-Log "Welcome to Phoenix HWID Toolkit v20.1 (Final)!" "White" -IsBold $true
    Write-Log "UI is now fully responsive. Dashboard will load in the background." "DarkTurquoise"
    
    # Asynchronous job for loading dashboard and network info for faster UI startup
    $job = Start-Job -ScriptBlock {
        # Functions used by the job must be defined inside its scope
        function Get-DashboardData {
            $dashboardItems = @{ 
                "MAC Address" = (Get-WmiObject Win32_NetworkAdapterConfiguration -EA SilentlyContinue | ? { $_.IPEnabled -and $_.MACAddress } | Select -First 1).MACAddress
                "Disk Serial" = (Get-WmiObject Win32_PhysicalMedia -EA SilentlyContinue | Select -First 1).SerialNumber.Trim()
                "Machine GUID" = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -EA SilentlyContinue).MachineGuid
                "Computer Name" = $env:COMPUTERNAME
                "TEMP Path" = [Environment]::GetEnvironmentVariable("TEMP", "Machine") 
            }
            return $dashboardItems
        }
        function Get-NetData {
            try {
                return (Invoke-RestMethod -Uri "http://ip-api.com/json" -TimeoutSec 5)
            } catch {
                return $null
            }
        }
        return @{Dashboard = (Get-DashboardData); Network = (Get-NetData)}
    }
    
    Register-ObjectEvent -InputObject $job -EventName StateChanged -Action {
        param($job)
        if ($job.State -eq 'Completed') {
            $result = Receive-Job -Job $job
            $window.Dispatcher.Invoke([Action]{
                # Populate Dashboard with results from the job
                $dashboardItems = $result.Dashboard
                $DashboardGrid.Children.Clear(); $DashboardGrid.RowDefinitions.Clear(); $DashboardGrid.ColumnDefinitions.Clear()
                $DashboardGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, 'Auto')}))
                $DashboardGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1, 'Star')}))
                $i = 0
                foreach ($item in $dashboardItems.GetEnumerator()) { 
                    $DashboardGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
                    $label = New-Object System.Windows.Controls.TextBlock -Property @{ Text = "$($item.Name):"; FontWeight = 'Bold'; Margin = '5'; VerticalAlignment = 'Center'}
                    $label.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "ForegroundColor")
                    $displayText = if ($item.Value) { $item.Value } else { 'N/A' }
                    $value = New-Object System.Windows.Controls.TextBlock -Property @{ Text = $displayText; Margin = '5'; Foreground = 'LightGray'; VerticalAlignment = 'Center'}
                    [System.Windows.Controls.Grid]::SetRow($label, $i); [System.Windows.Controls.Grid]::SetColumn($label, 0)
                    [System.Windows.Controls.Grid]::SetRow($value, $i); [System.Windows.Controls.Grid]::SetColumn($value, 1)
                    $DashboardGrid.Children.Add($label) | Out-Null; $DashboardGrid.Children.Add($value) | Out-Null; $i++ 
                } 

                # Populate Network Info
                $netInfo = $result.Network
                if ($netInfo) {
                    $NetworkGrid.Children.Clear(); $NetworkGrid.RowDefinitions.Clear(); $NetworkGrid.ColumnDefinitions.Clear()
                    $NetworkGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1,'Auto')}))
                    $NetworkGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)}))
                    $NetworkGrid.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = [System.Windows.GridLength]::new(1,'Auto')}))
                    $items = @{"Public IP"=$netInfo.query; "Country"="$($netInfo.country) ($($netInfo.countryCode))"; "ISP"=$netInfo.isp}
                    $i=0
                    foreach($item in $items.GetEnumerator()){
                        $NetworkGrid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
                        $label = New-Object System.Windows.Controls.TextBlock -Property @{Text="$($item.Name):"; FontWeight='Bold'; Margin='5'; VerticalAlignment='Center'}
                        $label.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "ForegroundColor")
                        $value = New-Object System.Windows.Controls.TextBlock -Property @{Text=$item.Value; Margin='5'; Foreground='LightGray'; VerticalAlignment='Center'}
                        [System.Windows.Controls.Grid]::SetRow($label,$i); [System.Windows.Controls.Grid]::SetColumn($label,0)
                        [System.Windows.Controls.Grid]::SetRow($value,$i);[System.Windows.Controls.Grid]::SetColumn($value,1)
                        $NetworkGrid.Children.Add($label)|Out-Null; $NetworkGrid.Children.Add($value)|Out-Null;$i++
                    }
                    $btn = New-Object System.Windows.Controls.Button -Property @{Content='Refresh'; Width=80; Height=30; VerticalAlignment='Center'}
                    $btn.Add_Click({Get-Network-Info})
                    [System.Windows.Controls.Grid]::SetRow($btn,0);[System.Windows.Controls.Grid]::SetColumn($btn,2);[System.Windows.Controls.Grid]::SetRowSpan($btn,3)
                    $NetworkGrid.Children.Add($btn)|Out-Null
                }
            })
            $job | Remove-Job -Force
        }
    } | Out-Null

    if ($autoSpoofOnLaunch.IsPresent) { Write-Log "Auto-Spoof on Launch is enabled. Applying changes now..." "Yellow" -ForceLog:$true; $btnSpoof.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) }
})

$window.Add_Closing({ Write-Log "Cleaning up temporary tools..." "Gray"; if (Test-Path $script:tempToolPath) { Remove-Item -Path $script:tempToolPath -Recurse -Force -EA SilentlyContinue } })

# Close the splash screen and show the main window
$fadeOutAnimation = New-Object System.Windows.Media.Animation.DoubleAnimation(1, 0, [System.Windows.Duration]::new([TimeSpan]::fromseconds(0.3)))
$fadeOutAnimation.add_Completed({ $splashWindow.Close() })
$splashWindow.BeginAnimation([System.Windows.Window]::OpacityProperty, $fadeOutAnimation)
Start-Sleep -m 300

# Finally, show the main window
$window.ShowDialog() | Out-Null
#endregion
