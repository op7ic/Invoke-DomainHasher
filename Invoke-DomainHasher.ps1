<#
VERSION      DATE          AUTHOR
0.3A      18/05/2019       op7ic
0.2A      16/05/2019       op7ic
0.1A      14/05/2019       op7ic
#> # Revision History


<#
  .SYNOPSIS
    This script checks for presence of unknown binaries across windows domain enviroment using known RDS hashset sets from NSRL (https://www.nist.gov/software-quality-group/national-software-reference-library-nsrl)
  .EXAMPLE
    Invoke-DomainHasher.ps1
  .HELP 
    -fast      Fast checks across across the domain (User profile folders only). Results stored in ./fast-output
	-full      Full checks across across the domain (C$ share). Results stored in ./full-output
#>

Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop


function help(){
Write-Host @"
Usage: powershell .\Invoke-DomainHasher.ps1 [options]

Options:
  -fast      (default) Fast checks across across the domain (User profile folders only). Results stored in .\fast-output
  -full      Full checks across across the domain (C$ share). Results stored in .\full-output
  -help      Show this help menu
"@
}

function checkbenignarchive(){
$location = ".\hashset\rds_modernm.zip"
if(!(test-path $location)) {
    $url = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip"
     try{
	 $req = Invoke-WebRequest -Uri $url -OutFile "$location" -ErrorAction:Stop -TimeoutSec 10
	 Write-Host "[+] Tool downloaded and stored in tools folder"
	 return $true
	 }catch{
	 Write-Host "[!] Rds_modernm.zip is missing and unable to download from $url. Please download this file and place it in hashset folder manually"
	 return $false
	 }
}else{
If ((Get-Item $location).length -gt 0kb) {
Write-Output "[+] RDS hashset located in hashset directory. Continue"
}else{
Write-Host "[!] RDS file 0 size"
return $false
}
return $true
}

}

# function taken from https://stackoverflow.com/questions/27768303/how-to-unzip-a-file-in-powershell
function cleanupNSRL(){

$location = ".\hashset\rds_modernm.zip"
$destinationPath = ".\hashset\unpacked_rds_modernm"
$unpacked_sorted_NSRL=".\hashset\dll_exe.NSRL.txt"

#if sorted NSRL doesn't exist then unpack
if (!(Test-Path $unpacked_sorted_NSRL)){
Write-Output "[!] Unpacking and sorting NSRL archive"

$archiveFile = [System.IO.File]::Open($location, [System.IO.FileMode]::Open)
$archive = [System.IO.Compression.ZipArchive]::new($archiveFile)	

 if (Test-Path $destinationPath) {
        foreach ($item in $archive.Entries) {
            $destinationItemPath = [System.IO.Path]::Combine($destinationPath, $item.FullName)

            if ($destinationItemPath -like '*/') {
                New-Item $destinationItemPath -Force -ItemType Directory > $null
            } else {
                New-Item $destinationItemPath -Force -ItemType File > $null

                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($item, $destinationItemPath, $true)
            }
        }
    } else {
        [System.IO.Compression.ZipFileExtensions]::ExtractToDirectory($archive, $destinationPath)
    }
# Finally just get out .exe and .dll. We will use dll_exe.NSRL.txt file for matching
Select-String -Path ".\hashset\unpacked_rds_modernm\NSRLFile.txt" -Pattern ".exe",".dll" | out-file $unpacked_sorted_NSRL

}else{ # otherwise unzip and unpack
Write-Output "[+] Sorted RDS hashet in hashset directory. Continue"
}
}

function compareandsearch($type){
$OutDirectory =".\combined-output"
if ($type){
# All of CSV files
$files= get-childitem ".\fast-output\*" | select fullname
# hashset with dll/exe files
$csvBlock = ".\hashset\dll_exe.NSRL.txt"
# define new Array to store files not seen before
$results = [System.Collections.ArrayList]@()
foreach($file in $files){
 $content = Import-Csv $file.FullName
 $content | foreach-object {
 if(sls $_.Hash $csvBlock -ca){
 # hashes we know about we don't really care about so we don't write them down
 }else{
 # save every line that we don't know about
    $result =  New-object PSObject
    $result | Add-member -type Noteproperty -Name Hash -Value $_.Hash.ToString()
    $result | Add-member -type Noteproperty -Name Path -Value $_.Path.ToString()
    $result | Add-member -type Noteproperty -Name Hostname  -Value $_.Hostname.ToString()
    $result | Add-member -type Noteproperty -Name LastWrite -Value (Get-ItemProperty -Path $_.Path.ToString() -Name LastWriteTime)
	$result | Add-member -type Noteproperty -Name OriginalName -Value ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.Path.ToString()).FileDescription)
    $results.Add($result) | out-null
   }
  }
 }
if (Test-Path $OutDirectory) {
$results | export-csv -notype "output.csv"
}else{
New-Item $OutDirectory -Force -ItemType Directory > $null
$results | export-csv -notype "$OutDirectory\output.csv"
}

}else{
# All of CSV files
$files= get-childitem ".\slow-output\*" | select fullname
# hashset with dll/exe files
$csvBlock = ".\hashset\dll_exe.NSRL.txt"
# define new Array to store files not seen before
$results = [System.Collections.ArrayList]@()
foreach($file in $files){
 $content = Import-Csv $file.FullName
 $content | foreach-object {
 if(sls $_.Hash $csvBlock -ca){
 # hashes we know about we don't really care about so we don't write them down
 }else{
 # save every line that we don't know about
    $result =  New-object PSObject
    $result | Add-member -type Noteproperty -Name Hash -Value $_.Hash.ToString()
    $result | Add-member -type Noteproperty -Name Path -Value $_.Path.ToString()
    $result | Add-member -type Noteproperty -Name Hostname  -Value $_.Hostname.ToString()
    $result | Add-member -type Noteproperty -Name LastWrite -Value (Get-ItemProperty -Path $_.Path.ToString() -Name LastWriteTime)
	$result | Add-member -type Noteproperty -Name OriginalName -Value ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.Path.ToString()).FileDescription)
    $results.Add($result) | out-null
   }
  }
 }

if (Test-Path $OutDirectory) {
$results | export-csv -notype "output.csv"
}else{
New-Item $OutDirectory -Force -ItemType Directory > $null
$results | export-csv -notype "$OutDirectory\output.csv"
}
}
}



function slowChecks($serverListArray){
$directoryOutput=".\full-output"
if (Test-Path $directoryOutput) {
}else{
New-Item $directoryOutput -Force -ItemType Directory > $null
}

	foreach ($remoteServer in $serverListArray){
	# control running jobs, max 4 
	$running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
	if ($running.Count -ge 4) {
	    $running | Wait-Job -Any | Out-Null
    }
	Write-Host "[+] Starting hashing for $remoteServer"
	Start-Job {
		try{
		# Get file path on remote server
		$filePath = Get-ChildItem -Path "FileSystem::\\$using:remoteServer\`C$\" -Include *.exe*,*.dll -Recurse –File | Get-FileHash -Algorithm SHA1 | Select-Object -Property Hash,Path,@{Name='Hostname';Expression={$remoteServer}} | Export-CSV ".\full-output\$using:remoteServer.csv"
		# Return hash/filepath only
        return "$true"
		}catch{
		return $Null
		}
    } | Out-Null
		
}#EOF foreach

# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

# Process the results
foreach($job in Get-Job)
{
    $result = Receive-Job $job
    Write-Host $result
}
Remove-Job -State Completed

}


function fastChecks($serverListArray){
$directoryOutput=".\fast-output"
if (Test-Path $directoryOutput) {
}else{
New-Item $directoryOutput -Force -ItemType Directory > $null
}
	foreach ($remoteServer in $serverListArray){
	# control running jobs, max 4 
	$running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
	if ($running.Count -ge 4) {
	    $running | Wait-Job -Any | Out-Null
    }
	Write-Host "[+] Starting hashing for $remoteServer"
	Start-Job {
	    try{
		# Get file path on remote server
		$filePath = Get-ChildItem -Path "FileSystem::\\$using:remoteServer\`C$\Users" -Include *.exe*,*.dll -Recurse –File | Get-FileHash -Algorithm SHA1 | Select-Object -Property Hash,Path,@{Name='Hostname';Expression={$remoteServer}} | Export-CSV ".\fast-output\$using:remoteServer.csv"
        return "$true"
		}catch{
		return $Null
		}
    } | Out-Null
		
}#EOF foreach

# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

# Process the results
foreach($job in Get-Job)
{
    $result = Receive-Job $job
    Write-Host $result
}
Remove-Job -State Completed
}



function domainHasher($fast){

write-host "-=[ Invoke-DomainHasher 0.3A ]=-"
write-host "      by op7ic        "

#call to check if we got all the files and they are sorted
if (checkbenignarchive){
cleanupNSRL
}else{
Write-Host "[!] Rds_modernm.zip is missing and unable to download from $url. Please download this file and place it in .\hashset folder manually before restarting this script"
exit
}

#if we have our hash file - lets enumerate the domain 
$strFilter = "computer";
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.SearchScope = "Subtree"
$objSearcher.PageSize = 9999999
$objSearcher.Filter = "(objectCategory=$strFilter)";
$colResults = $objSearcher.FindAll()

$serverListArray = [System.Collections.ArrayList]@()
foreach ($i in $colResults)
{
        $objComputer = $i.GetDirectoryEntry()
        $remoteBOX = $objComputer.Name
		#Step 1 - enumerate the domain and save host list to array
		$serverListArray.Add($remoteBOX) | out-null
}

if ($fast -eq $true){
	fastChecks($serverListArray)
	compareandsearch($true)
}else{
	slowChecks($serverListArray)
	compareandsearch($false)
}

}
if($args[0] -eq "-full"){
Write-Output "[!] Option selected: Full Hash" 
domainHasher($false)
}elseif($args[0] -eq "-help"){
help
}else{
Write-Output "[!] Option selected: Fast Hash" 
domainHasher($true)
}

