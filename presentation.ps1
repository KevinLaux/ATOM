#Windows ModulePSReleaseTools module (https://github.com/jdhitsolutions/PSReleaseTools)
#On Linux install package yum/apt-get
#On MAC Brew
#Oneliners:
#Windows- iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI -Preview"
#Linux- wget https://aka.ms/install-powershell.sh; sudo bash install-powershell.sh -preview; rm install-powershell.sh
#Download MSI/RPM/PKG
#Update /etc/ssh/sshd_config
#Add line "Subsystem       powershell   /usr/bin/pwsh --sshs -NoLogo -NoProfile"
#Remove commenting on "#PasswordAuthentication yes"




#What Sessions are available
Invoke-Command -ComputerName pswindows -ScriptBlock {Get-PSSessionConfiguration | Select Name}


$Linux = 'uscku1metu03c0l'
$LinuxAdmin = 'atomadmin'
$Windows = 'uscku1metu03c3'

#test
#Connect to Linux (Delay in openssh response)
Enter-PSSession -hostname $Linux -UserName $LinuxAdmin
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
$sessions += New-PSSession -hostname $Windows

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

