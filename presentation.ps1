<#Old Install Method
    #Silent Install PowerShell Core
    Start-Process msiexec.exe -Wait -ArgumentList '/I C:\temp\PowerShell-6.2.0-rc.1-win-x64.msi /q'
    #Add Env Path for PSCore   
    $env:Path="$env:Path;C:\Program Files\PowerShell\6-preview\"
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $env:Path

    #Run Command from Powershell and pwsh
    $PScount = (Get-Command -CommandType Cmdlet | Measure).count
    $PSCorecount = pwsh -Command "(Get-Command -CommandType Cmdlet | Measure).count"

    Write-Host "Powershell has $PScount commands!" -ForegroundColor Green
    Write-host "PowerShell Core has $PSCorecount commands!" -ForegroundColor Green
    Write-Host "Powershell has $($PScount - $PSCorecount) more commands!" -ForegroundColor Green

    #Install OpenSSH
    & 'C:\Program Files\OpenSSH-Win64\install-sshd.ps1'

    #Add Env Path for OpenSSH
    $env:Path="$env:Path;C:\Program Files\OpenSSH-Win64"
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $env:Path

    #Open Firewall for OpenSSH
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    #Set OpenSSH to Auto Start

    Set-Service -Name sshd -StartupType Automatic
    #Starts OpenSSH to generate default config
    Start-Service -Name sshd
    #Stops OpenSSH so we can edit config
    Stop-Service -Name sshd
#>

#Windows ModulePSReleaseTools module (https://github.com/jdhitsolutions/PSReleaseTools)
#On Linux install package yum/apt-get
#On MAC Brew
#Oneliners:
    #Windows- iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Preview"
    #Linux- wget https://aka.ms/install-powershell.sh; sudo bash install-powershell.sh -preview; rm install-powershell.sh
#Download MSI/RPM/PKG
    
#Install Powershell on Windows
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Preview"

#Install SSH on Windows

#Check OpenSSH

Get-WindowsCapability -Online | Where Name -like 'OpenSSH*'  

# Install the OpenSSH Client and Server

Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
 
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
 
# Initial Configuration of SSH Server
 
Start-Service sshd
 
Set-Service -Name sshd -StartupType 'Automatic'
 
# Confirm the Firewall rule is configured. It should be created automatically by setup.
 
Get-NetFirewallRule -Name *ssh*
 
# There should be a firewall rule named "OpenSSH-Server-In-TCP", which should be enabled

& cmd /c mklink /d 'c:\pwsh' 'C:\Program Files\PowerShell\6'

#Removes commenting from user auth line in config
(Get-Content -Path $env:ProgramData\ssh\sshd_config -Raw) -replace '#PasswordAuthentication yes', 'PasswordAuthentication yes'| Set-Content $env:ProgramData\ssh\sshd_config
#Add PSCore to Subsystem in config
(Get-Content $env:ProgramData\ssh\sshd_config) -replace "# override default of no subsystems", "$&`nSubsystem`tpowershell`tC:/Program Files/PowerShell/6-preview/pwsh.exe -sshs -NoLogo -NoProfile" | Set-Content $env:ProgramData\ssh\sshd_config


#Install SSH on Linux if not already
#Update /etc/ssh/sshd_config
#Add line "Subsystem       powershell   /usr/bin/pwsh --sshs -NoLogo -NoProfile"
#Remove commenting on "#PasswordAuthentication yes"
scp C:\Users\klaux\.ssh\id_rsa.pub klaux@laux.net:C:\Users\klaux\.ssh\authorized_keys

#What Sessions are available
Invoke-Command -ComputerName pswindows -ScriptBlock {Get-PSSessionConfiguration | Select Name}
Invoke-Command -Session  -ScriptBlock {Get-PSSessionConfiguration | Select Name} -username klaux@laux.net

$Linux = '192.168.20.32'
$Mac = '192.168.20.33'
$Windows = '192.168.20.31'

#test
#Connect to Linux (Delay in openssh response)
Enter-PSSession -hostname $Linux
#
$PSversiontable
#
if($PSversiontable.OS | Select-String Linux){Write-Host "I am Linux" -ForegroundColor Red}
#
if($PSversiontable.OS | Select-String Windows){Write-Host "I am Windows"}
# Do not get hung up on CASE SENSITIVITY 'Grep' <> 'grep'
if($PSversiontable.OS | grep Linux){Write-Host "I am Linux"}
Get-alias grep
# Easier Method
$IsLinux
#
$IsWindows
#
$IsMacOS
#
if($IsLinux){Write-Host "I am Linux" -ForegroundColor Red}
#How many Cmdlets do we have?
$(Get-Command -CommandType Cmdlet | Measure-Object).count
#Close Session
Exit-PSSession

#Connect with WSMan
Enter-PSSession $Windows
$PSversiontable
#Close Session
Exit-PSSession

#Connect with OpenSSH
Enter-PSSession -hostname $Windows
$PSversiontable
#Close Session
Exit-PSSession

#MultiSession
$sessions = @()
$sessions += New-PSSession -hostname $Linux -UserName atomadmin
$sessions += New-PSSession $Windows
$sessions += New-PSSession -hostname $Windows yes

#Lets see what our sessions look like
$sessions

#Now that I have created the sessions lets send them all a command
Invoke-Command -Session $sessions -scriptblock {$PSVersionTable}
Invoke-Command -Session $sessions -scriptblock {$PSVersionTable.PSVersion}
Invoke-Command -Session $sessions -scriptblock {$PSVersionTable.PSVersion | Format-Table}

#What else could I do? lets try looping through the sessions and returning some information
$Info = @()
$Info = Foreach($session in $sessions){
    Invoke-Command $session -ScriptBlock{
        $OS = 'Did not process'
        switch ( $true )
        {
            $IsLinux{ $OS = 'Linux'}
            $IsWindows{ $OS = 'Windows'}
            $IsMacOS{ $OS = 'Mac'}
            default{ $OS = 'Windows PS'}
        }
        $myObject = [PSCustomObject]@{
            OS          = $OS
            Commands    = Get-Command -CommandType Cmdlet
            Count       = (Get-Command -CommandType Cmdlet | Measure-Object).count
        }
        Return $myObject
    }
}
#Whats in $info?
$Info

#Lets Split that into Local Variables
$PS5Commands = $($Info | Where-Object OS -eq 'Windows PS').Commands.Name
$PS6Commands = $($Info | Where-Object OS -eq 'Windows').Commands.Name
$PSLinuxCommands = $($Info | Where-Object OS -eq 'Linux').Commands.Name

#Whats the difference?
Write-Host "Windows PS 5 has: $($PS5Commands.count) Commands" -ForegroundColor Green
Write-Host "Windows PSCore on Windows has: $($PS6Commands.count) Commands" -ForegroundColor Green
Write-Host "Windows PSCore on Linux has: $($PSLinuxCommands.count) Commands" -ForegroundColor Green

#Which Commands are where?
Compare-Object $PS5Commands $PS6Commands
#
Compare-Object $PS6Commands $PSLinuxCommands
#
Compare-Object $PS5Commands $PSLinuxCommands

#How can we make this a bit more understandable?
$allcommands = $PS5Commands
$allcommands += $PS6Commands
$allcommands += $PSLinuxCommands
$allcommands = $allcommands | Select-Object -Unique
$allcommands.count

$Table = @()
foreach($command in $allcommands){

    $myObject = [PSCustomObject]@{
        Cmdlet                  = $command
        'PowerShell 5'          = $PS5Commands.Contains($command)
        'PowerShell Core'       = $PS6Commands.Contains($command)
        'PowerShell Core Linux' = $PSLinuxCommands.Contains($command)
    }
    $table += $myObject
}
#What does it look like
$Table
#Lets save it to a CSV
$Table | Export-Csv 'c:\atom\output.CSV'

