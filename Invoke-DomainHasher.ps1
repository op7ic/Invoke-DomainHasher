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
	-full      Full checks across the domain (all exe and dll files from C$ share). Results stored in .\full-output.
#>

Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop


function help(){
Write-Host @"
Usage: powershell .\Invoke-DomainHasher.ps1 [options]

Options:
  -fast      (default) Fast checks across the domain (User profile folders only - C:\Users\*). Results stored in .\fast-output
  -full      Full checks across the domain (all exe and dll files from C$ share). Results stored in .\full-output. **Slow**
  -help      Show this help menu
"@
}

function checkbenignarchive(){
$location = Resolve-Path ".\hashset\rds_modernm.zip"
if(!(test-path $location)) {
    $url = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip"
     try{
	 $req = Invoke-WebRequest -Uri $url -OutFile "$location" -ErrorAction:Stop -TimeoutSec 10
	 Write-Host "[+] rds_modernm downloaded and stored in hashset folder"
	 return $true
	 }catch{
	 Write-Host "[!] Rds_modernm.zip is missing and unable to download from $url. Please download this file and place it in hashset folder manually"
	 return $false
	 }
}else{
Write-Output "[+] RDS hashset located in hashset directory. Continue"
return $true
}

}

# based on https://serverfault.com/questions/18872/how-to-zip-unzip-files-in-powershell
function cleanupNSRL(){
#Hardcoded locations
$unpacked_sorted_NSRL= ".\hashset\dll_exe.NSRL.txt"
$unpackedNSRL= ".\hashset\unpacked_rds_modernm\NSRLFile.txt"
$path = (Convert-Path .) + "\hashset\rds_modernm.zip"
$unpackdirectory = (Convert-Path .) + "\hashset\unpacked_rds_modernm"

# Check if output directory exists. Powershell 2.0 unzip version
if(!(Test-Path $unpackdirectory) -and !(Test-Path $unpacked_sorted_NSRL) -and (Test-Path $path)){
	New-Item -ItemType Directory -Path $unpackdirectory | Out-Null 
	$shellApplication = new-object -com shell.application
	$zipPackage = $shellApplication.NameSpace($path)
	$destinationFolder = $shellApplication.NameSpace($unpackdirectory)
	$destinationFolder.CopyHere($zipPackage.Items())
	# Finally just get out .exe and .dll. We will use dll_exe.NSRL.txt file for matching
	Select-String -Path (Resolve-Path $unpackedNSRL) -Pattern ".exe",".dll" | out-file $unpacked_sorted_NSRL
	Write-Output "[+] Sorted RDS hashet in hashset directory. Continue"
	Write-Output "[+] Removing directory unpacked_rds_modernm"
	Delete-Item -ItemType Directory -Path $unpackdirectory
}elseif ((Test-Path $unpacked_sorted_NSRL) -and (Test-Path $path)){
	Write-Output "[+] Sorted RDS hashet already in hashset directory. Continue"
}elseif(!(Test-Path $path)) {
	Write-Output "[-] Missing RDS file. Attempting download & unload"
	if(checkbenignarchive){
		cleanupNSRL
	}else{
	Write-Output "[-] Unable to download RDS file. Download Manually and place in hashset directory from https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip"
	}
}

}


function compareandsearch($type){
Write-Output "[+] Searching Index"
$OutDirectory =".\combined-output"
if ($type){
# All of CSV files
$files= get-childitem ".\fast-output\*" | select fullname
}else{
$files= get-childitem ".\full-output\*" | select fullname
}
# hashset with dll/exe files
$csvBlock = ".\hashset\dll_exe.NSRL.txt"
# define new Array to store files not seen before
$unknownHashes = [System.Collections.ArrayList]@()
# TODO: improve performance here - for full scan this is really slow
$knownHashes = [System.Collections.ArrayList]@()
foreach($file in $files){
 $content = Import-Csv $file.FullName
 $content | foreach-object {
 if(sls $_.Hash $csvBlock -ca){
 # hashes we know about we still want to store in some sort of CSV
    $known =  New-object PSObject
    $known | Add-member -type Noteproperty -Name Hash -Value $_.Hash.ToString()
    $known | Add-member -type Noteproperty -Name Path -Value $_.Path.ToString()
    $known | Add-member -type Noteproperty -Name Hostname  -Value $_.Hostname.ToString()
    $known | Add-member -type Noteproperty -Name LastWrite -Value (Get-Item -Path $_.Path.ToString() | select-object LastWriteTime)
	$known | Add-member -type Noteproperty -Name OriginalName -Value ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.Path.ToString()).FileDescription)
    $known | Add-member -type Noteproperty -Name Signed -Value ((get-AuthenticodeSignature $_.Path.ToString()).SignerCertificate.Status)
    $knownHashes.Add($known) | out-null
 }else{
 # save every line that we don't know about
    $unknown =  New-object PSObject
    $unknown | Add-member -type Noteproperty -Name Hash -Value $_.Hash.ToString()
    $unknown | Add-member -type Noteproperty -Name Path -Value $_.Path.ToString()
    $unknown | Add-member -type Noteproperty -Name Hostname  -Value $_.Hostname.ToString()
    $unknown | Add-member -type Noteproperty -Name LastWrite -Value (Get-Item -Path $_.Path.ToString() | select-object LastWriteTime)
	$unknown | Add-member -type Noteproperty -Name OriginalName -Value ([System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.Path.ToString()).FileDescription)
    $unknown | Add-member -type Noteproperty -Name Signed -Value ((get-AuthenticodeSignature $_.Path.ToString()).SignerCertificate.Status)
    $unknownHashes.Add($unknown) | out-null
   }
  }
 }
if (Test-Path $OutDirectory) {
$unknownHashes | export-csv -notype "$OutDirectory\unknown.csv"
$knownHashes | export-csv -notype "$OutDirectory\known.csv"
$unknownHashes | ConvertTo-Json | out-file "$OutDirectory\unknown.json"
$knownHashes | ConvertTo-Json | out-file "$OutDirectory\known.json"
}else{
New-Item $OutDirectory -Force -ItemType Directory > $null
$unknownHashes | export-csv -notype "$OutDirectory\unknown.csv"
$knownHashes | export-csv -notype "$OutDirectory\known.csv"
$unknownHashes | ConvertTo-Json | out-file "$OutDirectory\unknown.json"
$knownHashes | ConvertTo-Json | out-file "$OutDirectory\known.json"
}

}
function hashDomain($serverListArray, $fast){
#Depending on scan type we use different directories
if ($fast){
$directoryOutput=(Convert-Path .) + "\fast-output"
}else{
$directoryOutput=(Convert-Path .) +"\full-output"
}
# Check if directory exists
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
		param($foldername)
		try{
		# Get file path on remote server
        if($foldername -like "*full-output*"){
		$filePath = Get-ChildItem -Path "FileSystem::\\$using:remoteServer\`C$\" -Include *.exe*,*.dll -Recurse –File | Get-FileHash -Algorithm SHA1 | Select-Object -Property Hash,Path,@{Name='Hostname';Expression={$remoteServer}} | export-csv  "$foldername\$using:remoteServer.csv" -NoType 
        }else{
        $filePath = Get-ChildItem -Path "FileSystem::\\$using:remoteServer\`C$\Users\" -Include *.exe*,*.dll -Recurse –File | Get-FileHash -Algorithm SHA1 | Select-Object -Property Hash,Path,@{Name='Hostname';Expression={$remoteServer}} | export-csv  "$foldername\$using:remoteServer.csv" -NoType 
        }
        # Return hash/filepath only
        return "$true"
		}catch{
		return $Null
		}
    } -Arg $directoryOutput | Out-Null
		
}#EOF foreach

# Wait for all jobs to complete and results ready to be received
Wait-Job * | Out-Null

# Process the results
foreach($job in Get-Job)
{
    $result = Receive-Job $job
}
Remove-Job -State Completed
}

function domainHasher($fast){

write-host "-=[ Invoke-DomainHasher 0.3A ]=-"
write-host "      by op7ic        "

#Check if all files are in place
if (checkbenignarchive){
#cleanup and extract only .exe and .dll hash
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
	hashDomain $serverListArray $true 
	compareandsearch($true)
}else{
	hashDomain $serverListArray $false 
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

