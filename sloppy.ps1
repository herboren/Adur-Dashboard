# Import module for Windows 7
Import-Module ActiveDirectory ;

# For alert dialogs, used when a user needs 
# to be notified by a message dialog
Add-Type -AssemblyName PresentationFramework

# Get local user (not runas admin) Then write
# to log, track user progress within script
$LOCAL_USERNAME = ((Get-WMIObject -class Win32_ComputerSystem | select -ExpandProperty username)-split "\\" )[1] ;
$LogFile = "c:\Users\$($LOCAL_USERNAME)\Desktop\ADPassLock.txt" ;

# Servers with ADFS Management Services
$DomainControllers = @("","")

# For clearing log
$null = Out-File -FilePath $LogFile -append
  
$profile    =  [PSCustomObject] @{
    Badge   =  ' '
    Name    =  ' '
    Email   =  ' '
    Phone   =  ' '
    Title   =  ' '
    Dept    =  ' '
    Manager =  ' '
    Dist    =  ' '
    Active  =  ' '
    Locked  =  ' '
    DOB     =  ' '
    SSN     =  ' '
    COB     =  ' '
    SID     =  ' '
    HOME    =  ' '
    OU      =  ' '    
}

Function InitializationLockoutCheck() {
    # If Account Locked
    if($profile.Locked -eq $true) {        
        Unlock-ADAccount -Identity $($profile.Dist);        
        $null = [System.Windows.MessageBox]::Show("It appears that the account was locked out`nThe account has now been Unlocked.") 
		Clear-Host
		for($i = 7; $i -ge 1; $i--)
		{
			write-host -n -f Green ("{0,64}" -f "Please wait $($i) seconds while review is being populated`r");
			Start-Sleep -s 1
		}		
        InitializeEnvironment -badge $profile.Badge       
    }  
}


# This function displays the information gathered from the initialization function.
Function ProfileReviewDescriptions() {
    Clear-Host
    Write-Host ("{0,30}" -f "`n")    
    #Title Info
    Write-Host ("{0,20}" -f "Info") -ForegroundColor Cyan;
    #
    Write-Host -n ("{0,25}" -f "Badge: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "$($profile.Badge)") -ForegroundColor Yellow;
    Write-Host -n ("{0,25}" -f "Name: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "$($profile.Name)") -ForegroundColor Yellow;    
    Write-Host -n ("{0,25}" -f "Email: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "$($profile.Email)") -ForegroundColor Yellow;
    Write-Host -n ("{0,25}" -f "Phone: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "$($profile.Phone)") -ForegroundColor Yellow;
    Write-Host -n ("{0,25}" -f "Title: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "$($profile.Title)") -ForegroundColor Yellow;
    Write-Host -n ("{0,25}" -f "Dept: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "$($profile.Dept)") -ForegroundColor Yellow;
    Write-Host -n ("{0,25}" -f "Manager: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "$($profile.Manager[2]) $($profile.Manager[1])") -ForegroundColor Yellow;
    CheckType    
    #    
    #Title Security
    Write-Host ("{0,20}" -f "Security") -ForegroundColor Cyan;
    #
    Write-Host -n ("{0,25}" -f "DOB: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "$($profile.DOB )") -ForegroundColor Cyan;
    Write-Host -n ("{0,25}" -f "4SSN: ") -ForegroundColor Gray; Write-Host ("{0,4}" -f "$($profile.SSN)") -ForegroundColor Cyan;    
    #Title Status
    Write-Host    ("{0,20}" -f "Status") -ForegroundColor Cyan
    #    
    CheckEnabled    
    Write-Host ("`n{0,33}" -f "LockedOut`t`tServer")
    GetUserLockout
    ProfileReviewMenu
}

Function CheckEnabled() {
    
    # If Account Enabled/Disabled
    if($profile.Active -eq $false) {
        Write-Host -n ("{0,25}" -f "Enabled: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "Disabled") -ForegroundColor Red;
    }                                                                                                              
    else { 
        Write-Host -n ("{0,25}" -f "Enabled: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "Enabled") -ForegroundColor Green;
    }

    # If Account Un/Locked
    if($profile.Locked -eq $false) {
        Write-Host -n ("{0,25}" -f "State: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "Unlocked") -ForegroundColor Green;
    }                          
    else {
        Write-Host -n ("{0,25}" -f "State: ") -ForegroundColor Gray; Write-Host ("{0,5}" -f "Locked") -ForegroundColor Red;
    }    
}

Function CheckType() {
    If($($profile.Dist) -match 'OU=Employees') {
        Write-Host -n ("{0,25}" -f "Type: ") -ForegroundColor Gray; Write-Host ("{0,4}" -f "<redacted> Employee") -ForegroundColor Green;
    }
    if ($($profile.Dist) -match 'OU=Disabled') {
        Write-Host -n ("{0,25}" -f "Type: ") -ForegroundColor Gray; Write-Host ("{0,4}" -f "Disabled") -ForegroundColor Red;
    }
    If ($($profile.Dist) -match 'OU=Non-Employees') {
        Write-Host -n ("{0,25}" -f "Type: ") -ForegroundColor Gray; Write-Host ("{0,4}" -f "Non-Employee") -ForegroundColor Cyan;
    }    
}

Function ProfileReviewMenu() {        
    write-host ("" -f "");
    write-host -n ("{0,30}" -f "Reset Password");                                  write-host ("{0,36}" -f "Permissions");
    write-host -n ("{0,39}" -f "├─ 1. Default Password") -ForegroundColor Green;   write-host ("{0,35}" -f "├─ 4. Current User") -ForegroundColor Yellow;
    write-host -n ("{0,33}" -f "├─ 2. Unlock All") -ForegroundColor Green;     write-host ("{0,48}" -f "└─ 5. Compare Permissions");
    write-host -n ("{0,40}" -f "└─ 3. Custom Password`n`n");                           
    

    write-host    ("{0,22}" -f "Update");    
    write-host    ("{0,38}" -f "└─ 0. Refresh Screen`n")  -ForegroundColor Yellow; 
    
    $userMenuInput = Read-Host ("{0,40}" -f "Option (s to start over)")
    switch($userMenuInput)
    {
        1 {
            Generate-Password -badge $profile.Badge -name $profile.Name -option 2
            
        }
        2 {
            CheckPasswordLock              
        }
        3 {
            Generate-Password -badge $profile.Badge -name $profile.Name -option 3                    
        }
        4 {
            CheckPermissionsCurrentUser
        }
        5 {
            CompareBadgePermissions
            Read-Host
            InitializeEnvironment -badge $profile.Badge 
        }
               
        0 {
            InitializeEnvironment -badge $profile.Badge  
        }
        's' {
            Introduction
        }
    }    
}

Function CompareBadgePermissions {
       
    # Get Badge From User
    $badge = Read-Host ("`n{0,41}" -f "Input badge to compare to")
    Clear-Host ; 
    Write-Host ("`n`n{0,58}" -f "Gathering results, comparing information one moment") -ForegroundColor Yellow
    # Get OU from badge    
    $UserOU = (Get-ADUser $badge).DistinguishedName;        
	
    #Dump badge Properties to Array
    $UserProperty =  Get-ADUser -Filter * -SearchBase $UserOU -Properties * ;

    # Assign badge AD properties to object properties
    $compare = [PSCustomObject] @{        
        NameA = $profile.Name -split(', ') #
        Dist  = $UserProperty.DistinguishedName        
        NameB = $UserProperty.DisplayName -split(', ')        
    }
    

    $a = Get-ADPrincipalGroupMembership -Identity $($profile.Dist) -Server '<redacted>.<redacted>.org' | sort-object | Select name;
    $b = Get-ADPrincipalGroupMembership -Identity $($compare.Dist) -Server '<redacted>.<redacted>.org' | sort-object | Select name;        

    Compare-Object $a.Name $b.Name -IncludeEqual| Foreach {
        $_.SideIndicator = $_.SideIndicator -replace '=>', "$($compare.NameB[1])"
        $_.SideIndicator = $_.SideIndicator -replace '<=', "$($compare.NameA[1])"        
        $_.SideIndicator = $_.SideIndicator -replace '==', "$($compare.NameA[1]) == $($compare.NameB[1])"
        $_ 
    }
    Write-Host ("{0,48}" -f "Results Obtained, press [ENTER] to review") -ForegroundColor Yellow
    Read-Host    
    Write-Host ("{0,48}" -f "Press [ENTER] to return to review.") -ForegroundColor Green
}

Function GetUserLockout
 {     
     $LockedOutStats = @()

     Foreach($DC in $DomainControllers) {
         Try
         {
             $UserInfo = Get-ADUser -Identity $profile.Badge -Server $DC -Properties LockedOut -ErrorAction Stop
         }
         catch {}
         
         $userInfo | % {"`t`t{0}`t`t`t{1}" -f $_.LockedOut, $DC} | Format-Color @{'True' = 'Red'; 'False' = 'Green' }
     }
     #$LockedOutStats | Format-Table -Property Server,LockedOut }
 }

 Function Format-Color([hashtable] $Colors = @{}, [switch] $SimpleMatch)
 {
     $lines = ($input | Out-String) -replace "`r", "" -split "`n"
     foreach($line in $lines) {
         $color = ''
         foreach($pattern in $Colors.Keys){
             if(!$SimpleMatch -and $line -match $pattern) { $color = $Colors[$pattern] }
             elseif ($SimpleMatch -and $line -like $pattern) { $color = $Colors[$pattern] }
         }
         if($color) {
             Write-Host -n -ForegroundColor $color $line
         } else {
             Write-Host  $line
         }
     }
 }

Function CheckPermissionsCurrentUser() {
    Clear-Host ;
    Write-Host "`n`n`t`t" -n ; Write-Host "Please wait while permissions are retrieved..." -Fore Cyan ;

    # Dump Permissions/Memberships
    #
    $permissions = Get-ADPrincipalGroupMembership -Identity $badge -server '<redacted>.<redacted>.org' | sort-object | select name ;

    Clear-Host ;
    Write-Host "`n`n`n`t`t┌──────────┤ Permissions `n" -Fore Magenta ;
    for ($i=0; $i -le $permissions.count -1; $i++)
    {           
        if ($i -le 8 )
        {            
            Write-Host "`t`t`t" -n; Write-Host "$([int]$i+1).  " -n -Fore Yellow ; Write-Host $permissions[$i].Name -Fore Cyan ;            
        }
        elseif ($i -ge 10 )
        {            
            Write-Host "`t`t`t" -n; Write-Host "$([int]$i+1). " -n -Fore Yellow ; Write-Host $permissions[$i].Name -Fore Cyan ;            
        }  
    }
    "[$(Get-Date)]: Reviewed permissions for user: $($profile.Name) - $($profile.Badge). " | Out-File -FilePath $LogFile -append ;
    Write-Host "`n`t`t`tPress [Enter] to return to review..." -Fore Green ; Read-Host ;
    InitializeEnvironment -badge $profile.Badge    
}

Function CheckPasswordLock {
    if($profile.Active -eq $true) # If Account ENABLED and Account is LOCKED # -and $profile.Locked -eq $true
    {
        Write-Host -ForegroundColor Cyan ("{0,52}" -f "Unlocking on servers, please wait...")
        foreach($dc in $DomainControllers)
        {
            Unlock-ADAccount -Identity $profile.Badge -Server $dc
        }
        
        "[$(Get-Date)]: Unlocked account for user: $($profile.Name) - $($profile.Badge). " | Out-File -FilePath $LogFile -append ;
        
    }
    elseif ($profile.Active -eq $false) # If Account disabled DO NOTHING
    {
        Write-Host "`n`t`t`tAccount $($profile.Badge), is disabled, CANNOT unlock.`n`t`t`tPress [Enter] to return to review..." -Fore White -Back DarkR ; Read-Host ; 
        "[$(Get-Date)]: Account disabled for user: $($profile.Name) - $($profile.Badge). " | Out-File -FilePath $LogFile -append ;
        
    }
    #elseif ($profile.Active -eq $true -and $profile.Locked -eq $false) # If Account enabled and unlocked, unlock anyways (reset attempts).
    #{
      #  Write-Host "`n`t`t`tAccount appears unlocked:" $profile.badge   -Fore Yellow ;
      #  Write-Host "`t`t`tPress [Enter] to unlock anyways..." -n -Fore Green ; Read-Host;

        # Push Unlock
      #  Unlock-ADAccount -Identity $profile.Dist
      #  Write-Host -f Green -n "`t`t`tAccount has been unlocked, press [Enter] to return to review..."; Read-Host ;        
      #  "[$(Get-Date)]: Unlocked account for user: $($profile.Name) - $($profile.Badge). " | Out-File -FilePath $LogFile -append ;
    #}   
    
    InitializeEnvironment -badge $profile.Badge  
}

# Generate Random Password for Non-<redacted>/<redacted> Employees

Function Generate-Password ([string]$badge, [string]$name, [int]$option)
{   
    if ($profile.Active -eq $false)
    {       
        $null = [System.Windows.MessageBox]::Show("Account disabled, cannot reset password for, $($profile.Name) - $($profile.Badge)")
    }
    elseif($profile.Active -eq $true)
    {    
        # Password includes characters [A-Z], [a-z], [0-9] [!@#$^&*()-_=+.,)]
        # Conversion from Hex to Ascii 
        #
        # 21=!,40=@,23=#,24=$,25=%,
        # 5E=^,26=&,2A=*,28=(,29=),
        # 2D=-,5F=_,3D==,2B=+,2E=.,
        # 2C=
            
        If ($option -eq 1)
        {
            # Return randomly generated string given the hex
            # values and alpha-numeric range.                           
            $randomPassword = -join ((0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A)+(0x21,0x40,0x23,0x24,0x25,0x5E,0x26,0x2A,0x28,0x29,
                                                             0x2D,0x5F,0x3D,0x2B,0x2E,0x2C) | Get-Random -Count 8  | % {[char]$_});

            Write-Host "`n`t`t`tPassword Generated: " -n ; Write-Host $randomPassword -Fore Green ;
            Write-Host "`t`t`tHit [Enter] to reset password or [Esc] to cancel..." -Fore Cyan ; 
            MathsBruh -password $randomPassword

        }
        ElseIf($option -eq 2)
        {
            #Substringing makeshift password
            # Prefix splits Display Name into a 2-Element Array
            # prefix = {"lastName"," firstName"}
            $prefix = $name.split(',') ; 
        
            # Root Trim additional whitespace from the last string
            # " firstName" which becomes "firstName"
            # Both strings are cut via SubString, starting point (0)
            # on both elements and includes the first character (1),
            # through Substring(0,1)
            $root = $prefix[1].Trim().substring(0,1) + $prefix[0].substring(0,1).ToLower() ; 
            # Produces "Bp"

            # Root returns both elements as a string and concatenates
            # the Substringed badge and symbols on the tail of the string
            $defaultPassword = $root + $badge.substring(2,4) + '#!' ; 
            # Creating "Fl5292#!"

            Write-Host "`n`t`t`tPassword Generated: " -n ; Write-Host $defaultPassword -Fore Green ;
            Write-Host "`t`t`tHit [Enter] to reset password or [Esc] to cancel..." -Fore Cyan ; 
            MathsBruh -password $defaultPassword
        } 
        ElseIf($option -eq 3)
        {  
            $CustomPassword = Read-Host ("`n{0,39}" -f "Custom Password")
            Write-Host "`t`t`tCustom Password to be applied: " -n ; Write-Host $CustomPassword -Fore Green ;
            Write-Host -n "`t`t`tHit [Enter] to reset password or [Esc] to cancel..." -Fore Cyan ; 
            MathsBruh -password $CustomPassword
        }
    }
}

Function MathsBruh([string]$password) {

    # Read User Key Esc/Enter
    $key = [System.Console]::ReadKey() ;
    if ($key.Key.ToString() -eq 'Escape')
    {
        $null = [System.Windows.MessageBox]::Show('Action Canceled.')
    }
    elseif ($key.Key.ToString() -eq 'Enter')
    {                
        $a = get-random -Maximum 10 ;
        $b = get-random -Maximum 10 ;
        Write-Host "`n`t`t`t" -n ; Write-Host " Captcha: `n" -Fore White -Back Blue ;
        Write-Host "`t`t`t"   -n ;"What is $($a) + $($b)? " ;
        $c = Read-Host "`t`t`tAnswer"; Write-Host ;

        if ($c -eq ($a+$b))
        {      
            Set-ADAccountPassword -Identity $($profile.Dist) -Reset -NewPassword (ConvertTo-SecureString -AsPlainText ($($password)) -Force)
            Unlock-ADAccount -Identity $($profile.Dist);                                              
            $null = [System.Windows.MessageBox]::Show('Password reset successful.')  
            "[$(Get-Date)]: Changed password for user: $($profile.Name) - $($profile.Badge). " | Out-File -FilePath $LogFile -append ;      
        } 
        else
        {
            $null = [System.Windows.MessageBox]::Show('Captcha Incorrect.')                     
        }
    }  
    
    InitializeEnvironment -badge $profile.Badge      
}

Function LogMenu()
{
    Clear-Host
    Write-Host ("{0}" -f ([Environment]::NewLine * 4))
    Write-Host ("{0,40}" -f ('1. Show Password Resets')) -Fore Yellow;
    Write-Host ("{0,40}" -f ('2. Show Account Unlocks')) -Fore Yellow;
    Write-Host ("{0,43}" -f ('3. Show Permission Reviews')) -Fore Yellow;
    Write-Host ("{0,28}" -f ('4. Show All')) -Fore Yellow;
    Write-Host ("{0,29}" -f ('5. Clear Log')) -Fore Yellow;
    Write-Host ("{0,29}" -f ('Q. Main Menu')) -Fore Yellow;
    Write-Host        
    $ui = Read-Host ("{0,30}" -f ('Selection'))
    Write-Host ("`n{0,34}" -f ('Log for last accessed users')) -Fore White -Back Blue "`n" ;
                
                if ($ui.ToLower() -eq "1") {
                    LogFilter("Password")
                }                                
                if ($ui.ToLower() -eq "2") {
                    LogFilter("unlocked")
                }                        
                if ($ui.ToLower() -eq "3") {
                    LogFilter("Permissions")
                }                        
                if ($ui.ToLower() -eq "4") {
                    LogFilter("")
                }  
                if ($ui.ToLower() -eq "5") {
                    $null | Out-File -FilePath $LogFile
                    $null = [System.Windows.MessageBox]::Show('Log has been cleared')
                }     
                if ($ui.ToLower() -eq "q") {                    
                    Clear-Host
                    Introduction
                }                   
                Read-Host ;    
                LogMenu;
}

Function LogFilter ([string]$filter)
{
    foreach ($line in Get-Content $LogFile | where {$_ -ne "" -and $_ -match $filter})
    {
        Write-Host ("  {0,30}" -f $line) -Fore Cyan ;
    }
}

# This will initialize the badge properties to work with
# and will be used globally between functions

Function InitializeEnvironment([string]$badge) {    
    
    Try {
    # Get users ou

    $UserOUA = (Get-ADUser $badge).DistinguishedName;        
    $UserProperty = Get-ADUser -Filter * -SearchBase $UserOUA -Properties * ;    

    # properties that will be used outside of
    # the function.

    $profile.Badge   =  $UserProperty.SamAccountName
    $profile.Name    =  $UserProperty.DisplayName
    $profile.Email   =  $UserProperty.EmailAddress
    $profile.Phone   =  $UserProperty.OfficePhone 
    $profile.Title   =  $UserProperty.Description 
    $profile.Dept    =  $UserProperty.Department
    $profile.Manager =  $UserProperty.Manager -Replace("[=\\,\s–_)]+",",") -split(",").Trim();
    $profile.Dist    =  $UserProperty.DistinguishedName            
    $profile.Active  =  $UserProperty.Enabled
    $profile.Locked  =  $UserProperty.LockedOut    
    $profile.DOB     =  $UserProperty.tGHextattriba.Insert(2,'-').Insert(5,'-')
    $profile.SSN     =  $UserProperty.tGHextattribb
    $profile.COB     =  ' '    
    $profile.SID     =  $UserProperty.SID    
    $profile.OU      =  $UserProperty.PrimaryGroup    
    
    } catch
    {        
        Introduction
    }
    InitializationLockoutCheck
    ProfileReviewDescriptions    
}

Function Introduction() {
    Clear-Host
    While ($userInput -ne 'q')   
    {
        write-host ("`n`n`n`n" -f "");
        #write-host ("{0,30}" -f "1. Badge Lookup");
        write-host ("{0,26}" -f "H. History`n");  
            
        $userInput = Read-Host ("{0,21}"-f"Badge")         

        if($userInput -eq "H" -or $userInput -eq "h")
        {
            LogMenu
            Clear-Host
            Read-Host
            Introduction
        }
        
        # Begin Initialization
        InitializeEnvironment($userInput);
    }
}

Introduction

 Write-Host "`n`n`t`t Log for recently managed users." -Fore White -Back Blue "`n" ;                
            foreach ($line in Get-Content $LogFile)
            {
                Write-Host -Fore Cyan "`t`t" $line ;
            }
