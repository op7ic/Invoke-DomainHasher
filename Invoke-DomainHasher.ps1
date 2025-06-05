#Requires -Version 5.1
<#
.SYNOPSIS
    All-in-One Domain Binary Hasher for Threat Hunting
.DESCRIPTION
    Scans domain computers for unknown binaries using NSRL RDS hashset.
    Includes built-in analysis, GPO script generation, and multiple scan modes.
.PARAMETER Mode
    Scan mode: Fast (user profiles), Full (entire C:), Targeted (common malware locations), 
    Analyze (analyze existing results), GenerateGPO (create GPO deployment script)
.PARAMETER RDSPath
    Path to existing RDS file (ZIP or extracted NSRLFile.txt). If not specified, will offer to download.
.PARAMETER RDSUrl
    URL to download RDS from (default: NIST current RDS modern)
.PARAMETER OutputPath
    Base path for results (default: .\DomainHasherResults)
.PARAMETER NetworkShare
    UNC path for GPO script results (e.g., \\server\share\HashResults)
.PARAMETER MaxThreads
    Maximum concurrent scan threads (default: 4)
.PARAMETER CPUThreshold
    CPU usage threshold for throttling (default: 70%)
.PARAMETER TargetComputers
    Specific computers to scan (comma-separated or file path)
.PARAMETER SkipRDSCheck
    Skip RDS comparison (useful for just collecting hashes)
.PARAMETER ExportSTIX
    Export results in STIX format for threat intelligence platforms
.PARAMETER DaysToAnalyze
    Number of days to include in analysis (default: 30)
.EXAMPLE
    .\Invoke-DomainHasher.ps1 -Mode Fast
.EXAMPLE
    .\Invoke-DomainHasher.ps1 -Mode Full -RDSPath "C:\RDS\NSRLFile.txt" -MaxThreads 8
.EXAMPLE
    .\Invoke-DomainHasher.ps1 -Mode GenerateGPO -NetworkShare "\\DC01\HashResults$"
.EXAMPLE
    .\Invoke-DomainHasher.ps1 -Mode Analyze -DaysToAnalyze 7 -ExportSTIX
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Fast', 'Full', 'Targeted', 'Analyze', 'GenerateGPO', 'Custom')]
    [string]$Mode,
    
    [Parameter()]
    [string]$RDSPath,
    
    [Parameter()]
    [string]$RDSUrl = "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/RDS_modern.zip",
    
    [Parameter()]
    [string]$OutputPath = ".\DomainHasherResults",
    
    [Parameter()]
    [string]$NetworkShare,
    
    [Parameter()]
    [int]$MaxThreads = 4,
    
    [Parameter()]
    [int]$CPUThreshold = 70,
    
    [Parameter()]
    [string]$TargetComputers,
    
    [Parameter()]
    [string[]]$CustomPaths,
    
    [Parameter()]
    [switch]$SkipRDSCheck,
    
    [Parameter()]
    [switch]$ExportSTIX,
    
    [Parameter()]
    [int]$DaysToAnalyze = 30,
    
    [Parameter()]
    [switch]$Quiet
)

#region Global Variables and Functions

$script:Version = "3.0"
$script:Banner = @"
Domain Hasher by op7ic 
"@

# Scan profiles
$script:ScanProfiles = @{
    Fast = @{
        Paths = @("C:\Users", "C:\ProgramData", "C:\Users\*\Downloads")
        Description = "User profiles and ProgramData"
    }
    Full = @{
        Paths = @("C:\")
        Description = "Complete C: drive scan"
    }
    Targeted = @{
        Paths = @(
            "C:\Users\*\AppData\Local\Temp",
            "C:\Users\*\AppData\Roaming",
            "C:\Users\*\Downloads",
            "C:\Windows\Temp",
            "C:\Windows\System32",
            "C:\Windows\SysWOW64",
            "C:\ProgramData",
            "C:\Temp"
        )
        Description = "Common malware locations"
    }
}

function Write-ColorLog {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )
    
    if ($script:Quiet -and $Level -eq 'Debug') { return }
    
    $colors = @{
        'Info'    = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Debug'   = 'Gray'
    }
    
    $prefix = @{
        'Info'    = '[*]'
        'Success' = '[+]'
        'Warning' = '[!]'
        'Error'   = '[-]'
        'Debug'   = '[.]'
    }
    
    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
    
    # Also log to file
    $logFile = Join-Path $OutputPath "DomainHasher_$(Get-Date -Format 'yyyyMMdd').log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Out-File -FilePath $logFile -Append -ErrorAction SilentlyContinue
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CPUUsage {
    try {
        $cpu = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
        if ($cpu) {
            return [math]::Round($cpu.CounterSamples[0].CookedValue, 2)
        }
    }
    catch {}
    return 0
}

function Start-ThrottledJob {
    param(
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [string]$Name
    )
    
    while ($true) {
        $runningJobs = @(Get-Job | Where-Object { $_.State -eq 'Running' })
        $cpuUsage = Get-CPUUsage
        
        if ($runningJobs.Count -lt $MaxThreads -and $cpuUsage -lt $CPUThreshold) {
            Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -Name $Name | Out-Null
            break
        }
        else {
            if ($cpuUsage -ge $CPUThreshold) {
                Write-ColorLog "CPU at $cpuUsage%, throttling..." -Level Debug
            }
            Start-Sleep -Seconds 2
            Get-Job | Where-Object { $_.State -eq 'Completed' -or $_.State -eq 'Failed' } | Remove-Job
        }
    }
}

#endregion

#region RDS Management

function Get-RDSHashTable {
    param([string]$Path)
    
    Write-ColorLog "Preparing RDS hash database..." -Level Info
    
    # Check if we have a cached hashtable
    $cacheFile = Join-Path $OutputPath "rds_cache.clixml"
    $rdsInfo = Join-Path $OutputPath "rds_info.json"
    
    if (Test-Path $cacheFile) {
        try {
            $info = Get-Content $rdsInfo -Raw | ConvertFrom-Json
            $daysSinceCache = ((Get-Date) - [datetime]$info.CacheDate).Days
            
            Write-ColorLog "Found cached RDS database (created $daysSinceCache days ago)" -Level Info
            
            if ($daysSinceCache -lt 30) {
                Write-ColorLog "Loading cached RDS database..." -Level Info
                $hashTable = Import-Clixml $cacheFile
                Write-ColorLog "Loaded $($hashTable.Count) known hashes from cache" -Level Success
                return $hashTable
            }
            else {
                Write-ColorLog "Cache is older than 30 days, rebuilding..." -Level Warning
            }
        }
        catch {
            Write-ColorLog "Failed to load cache: $_" -Level Warning
        }
    }
    
    # Process RDS file
    if (-not $Path) {
        Write-ColorLog "No RDS path specified. Please use one of the following options:" -Level Warning
        Write-Host "`n  1. Download from NIST (WARNING: File is ~3GB compressed, ~15GB extracted)"
        Write-Host "  2. Specify path to existing RDS file with -RDSPath parameter"
        Write-Host "  3. Skip RDS check with -SkipRDSCheck parameter`n"
        
        $choice = Read-Host "Would you like to download RDS now? (y/N)"
        
        if ($choice -eq 'y') {
            $Path = Join-Path $OutputPath "RDS_modern.zip"
            Write-ColorLog "Downloading RDS to $Path (this may take a while...)" -Level Info
            
            try {
                $ProgressPreference = 'SilentlyContinue'
                Invoke-WebRequest -Uri $RDSUrl -OutFile $Path -ErrorAction Stop
                $ProgressPreference = 'Continue'
                Write-ColorLog "Download complete" -Level Success
            }
            catch {
                Write-ColorLog "Download failed: $_" -Level Error
                return $null
            }
        }
        else {
            return $null
        }
    }
    
    # Handle different RDS formats
    $nsrlFile = $null
    
    if ($Path -like "*.zip") {
        Write-ColorLog "Extracting RDS archive..." -Level Info
        $extractPath = Join-Path $OutputPath "RDS_Extract"
        
        try {
            if (Test-Path $extractPath) {
                Remove-Item $extractPath -Recurse -Force
            }
            
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $extractPath)
            
            $nsrlFile = Get-ChildItem -Path $extractPath -Filter "NSRLFile.txt" -Recurse | Select-Object -First 1
            
            if (-not $nsrlFile) {
                throw "NSRLFile.txt not found in archive"
            }
        }
        catch {
            Write-ColorLog "Failed to extract RDS: $_" -Level Error
            return $null
        }
    }
    elseif ($Path -like "*NSRLFile.txt") {
        if (Test-Path $Path) {
            $nsrlFile = Get-Item $Path
        }
        else {
            Write-ColorLog "NSRLFile.txt not found at $Path" -Level Error
            return $null
        }
    }
    else {
        # Try to find NSRLFile.txt in the given directory
        $nsrlFile = Get-ChildItem -Path $Path -Filter "NSRLFile.txt" -Recurse | Select-Object -First 1
        
        if (-not $nsrlFile) {
            Write-ColorLog "Could not find NSRLFile.txt in $Path" -Level Error
            Write-ColorLog "Please specify the full path to NSRLFile.txt or the RDS ZIP file" -Level Info
            return $null
        }
    }
    
    # Build hashtable
    Write-ColorLog "Building hash lookup table from $($nsrlFile.FullName)..." -Level Info
    Write-ColorLog "This may take several minutes for the full RDS database" -Level Warning
    
    $hashTable = @{}
    $reader = [System.IO.StreamReader]::new($nsrlFile.FullName)
    $lineCount = 0
    $hashCount = 0
    
    try {
        # Skip header
        $null = $reader.ReadLine()
        
        while ($null -ne ($line = $reader.ReadLine())) {
            # RDS format: "SHA-1",filename,size,etc...
            if ($line -match '^"([A-F0-9]{40})"') {
                $hash = $matches[1]
                $hashTable[$hash] = $true
                $hashCount++
            }
            
            $lineCount++
            if ($lineCount % 500000 -eq 0) {
                Write-ColorLog "Processed $lineCount lines, found $hashCount hashes..." -Level Debug
            }
        }
    }
    finally {
        $reader.Close()
    }
    
    Write-ColorLog "Built hashtable with $hashCount unique hashes" -Level Success
    
    # Cache the hashtable
    try {
        Write-ColorLog "Caching hashtable for future use..." -Level Info
        $hashTable | Export-Clixml -Path $cacheFile
        
        @{
            CacheDate = Get-Date
            SourceFile = $nsrlFile.FullName
            HashCount = $hashCount
            Version = $script:Version
        } | ConvertTo-Json | Out-File $rdsInfo
        
        Write-ColorLog "Cache saved successfully" -Level Success
    }
    catch {
        Write-ColorLog "Failed to cache hashtable: $_" -Level Warning
    }
    
    # Cleanup
    if ($extractPath -and (Test-Path $extractPath)) {
        Remove-Item $extractPath -Recurse -Force
    }
    
    return $hashTable
}

#endregion

#region Domain Scanning

function Get-DomainComputers {
    if ($TargetComputers) {
        if (Test-Path $TargetComputers) {
            $computers = Get-Content $TargetComputers | Where-Object { $_ -and $_ -notmatch '^\s*#' }
            Write-ColorLog "Loaded $($computers.Count) computers from file" -Level Info
            return $computers
        }
        else {
            $computers = $TargetComputers -split ','
            Write-ColorLog "Using $($computers.Count) specified computers" -Level Info
            return $computers
        }
    }
    
    Write-ColorLog "Enumerating domain computers..." -Level Info
    
    try {
        $computers = @()
        
        # Try AD module first
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
        }
        else {
            # Fallback to ADSI
            $searcher = [adsisearcher]"(objectCategory=computer)"
            $searcher.PageSize = 1000
            $results = $searcher.FindAll()
            
            foreach ($result in $results) {
                $computers += $result.Properties.name[0]
            }
        }
        
        # Filter out DCs and exclude patterns
        $filtered = $computers | Where-Object {
            $_ -and 
            $_ -notmatch '^DC\d+' -and
            $_ -notmatch 'CLUSTER'
        }
        
        Write-ColorLog "Found $($filtered.Count) computers" -Level Success
        return $filtered
    }
    catch {
        Write-ColorLog "Failed to enumerate domain: $_" -Level Error
        return @()
    }
}

function Get-RemoteFileHashes {
    param(
        [string]$ComputerName,
        [string[]]$ScanPaths,
        [string]$ResultPath
    )
    
    $computerResultPath = Join-Path $ResultPath $ComputerName
    if (-not (Test-Path $computerResultPath)) {
        New-Item -ItemType Directory -Path $computerResultPath -Force | Out-Null
    }
    
    $results = @()
    $csvPath = Join-Path $computerResultPath "hashes.csv"
    $errorLog = Join-Path $computerResultPath "errors.log"
    
    try {
        # Quick connectivity test
        if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Computer unreachable" | Out-File $errorLog
            return
        }
        
        $fileCount = 0
        $errorCount = 0
        
        foreach ($scanPath in $ScanPaths) {
            $remotePath = "\\$ComputerName\$($scanPath -replace ':', '$')"
            
            if (Test-Path $remotePath -ErrorAction SilentlyContinue) {
                try {
                    $files = Get-ChildItem -Path $remotePath -Include *.exe, *.dll -Recurse -File -ErrorAction SilentlyContinue
                    
                    foreach ($file in $files) {
                        try {
                            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA1 -ErrorAction Stop
                            
                            # Get file metadata
                            $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
                            $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                            
                            $results += [PSCustomObject]@{
                                ComputerName = $ComputerName
                                Hash = $hash.Hash
                                Path = $file.FullName
                                LocalPath = $file.FullName -replace "^\\\\$ComputerName\\", ""
                                FileName = $file.Name
                                FileSize = $file.Length
                                LastWriteTime = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                                CreationTime = $file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                                FileVersion = $versionInfo.FileVersion
                                ProductName = $versionInfo.ProductName
                                CompanyName = $versionInfo.CompanyName
                                Description = $versionInfo.FileDescription
                                IsSigned = ($signature.Status -eq 'Valid')
                                SignerCertificate = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "" }
                                ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            }
                            
                            $fileCount++
                        }
                        catch {
                            $errorCount++
                            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Failed to hash $($file.FullName): $_" | Out-File $errorLog -Append
                        }
                    }
                }
                catch {
                    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Failed to scan $scanPath: $_" | Out-File $errorLog -Append
                }
            }
        }
        
        # Save results
        if ($results.Count -gt 0) {
            $results | Export-Csv -Path $csvPath -NoTypeInformation
            
            # Create summary
            $summary = @{
                ComputerName = $ComputerName
                ScanDate = Get-Date
                TotalFiles = $fileCount
                Errors = $errorCount
                UniqueHashes = ($results.Hash | Sort-Object -Unique).Count
                SignedFiles = ($results | Where-Object { $_.IsSigned }).Count
                UnsignedFiles = ($results | Where-Object { -not $_.IsSigned }).Count
            }
            
            $summary | ConvertTo-Json | Out-File (Join-Path $computerResultPath "summary.json")
        }
        
        return $fileCount
    }
    catch {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Critical error: $_" | Out-File $errorLog -Append
        return 0
    }
}

#endregion

#region Analysis Functions

function Compare-WithRDS {
    param(
        [hashtable]$RDSHashes,
        [string]$ResultsPath
    )
    
    Write-ColorLog "Comparing collected hashes with RDS database..." -Level Info
    
    $allResults = @()
    $unknownHashes = @()
    $knownHashes = @()
    
    # Load all computer results
    $computerDirs = Get-ChildItem -Path $ResultsPath -Directory
    
    foreach ($dir in $computerDirs) {
        $csvPath = Join-Path $dir.FullName "hashes.csv"
        if (Test-Path $csvPath) {
            $hashes = Import-Csv $csvPath
            $allResults += $hashes
            
            foreach ($hash in $hashes) {
                if ($RDSHashes.ContainsKey($hash.Hash)) {
                    $knownHashes += $hash
                }
                else {
                    $unknownHashes += $hash
                }
            }
        }
    }
    
    # Create analysis results
    $analysisPath = Join-Path $ResultsPath "_Analysis"
    if (-not (Test-Path $analysisPath)) {
        New-Item -ItemType Directory -Path $analysisPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Save unknown hashes
    if ($unknownHashes.Count -gt 0) {
        $unknownPath = Join-Path $analysisPath "unknown_hashes_$timestamp.csv"
        $unknownHashes | Export-Csv -Path $unknownPath -NoTypeInformation
        
        # Group by hash for analysis
        $uniqueUnknown = $unknownHashes | Group-Object -Property Hash
        
        $analysis = foreach ($group in $uniqueUnknown) {
            [PSCustomObject]@{
                Hash = $group.Name
                FileNames = ($group.Group.FileName | Select-Object -Unique) -join '; '
                ComputerCount = ($group.Group.ComputerName | Select-Object -Unique).Count
                Computers = ($group.Group.ComputerName | Select-Object -Unique) -join '; '
                TotalInstances = $group.Count
                IsSigned = ($group.Group.IsSigned | Select-Object -Unique) -join '; '
                CompanyName = ($group.Group.CompanyName | Where-Object { $_ } | Select-Object -Unique) -join '; '
                Paths = ($group.Group.LocalPath | Select-Object -Unique) -join '; '
                RiskScore = $(
                    $score = 0
                    if ($group.Count -gt 5) { $score += 3 }  # Widespread
                    if ('False' -in $group.Group.IsSigned) { $score += 2 }  # Unsigned
                    if ($group.Group.LocalPath -match 'Temp|AppData\\Roaming') { $score += 2 }  # Suspicious location
                    if ($group.Group.CompanyName -notmatch '\S') { $score += 1 }  # No company
                    $score
                )
            }
        } | Sort-Object -Property RiskScore -Descending
        
        $analysisPath2 = Join-Path $analysisPath "unknown_analysis_$timestamp.csv"
        $analysis | Export-Csv -Path $analysisPath2 -NoTypeInformation
        
        # High risk items
        $highRisk = $analysis | Where-Object { $_.RiskScore -ge 5 }
        if ($highRisk) {
            $highRiskPath = Join-Path $analysisPath "HIGH_RISK_$timestamp.csv"
            $highRisk | Export-Csv -Path $highRiskPath -NoTypeInformation
        }
    }
    
    # Generate HTML report
    $htmlReport = Generate-HTMLReport -AllResults $allResults -UnknownHashes $unknownHashes -Analysis $analysis
    $htmlPath = Join-Path $analysisPath "report_$timestamp.html"
    $htmlReport | Out-File -FilePath $htmlPath -Encoding UTF8
    
    # Summary
    Write-ColorLog "`n========== ANALYSIS SUMMARY ==========" -Level Info
    Write-ColorLog "Total files scanned: $($allResults.Count)" -Level Info
    Write-ColorLog "Unique hashes: $(($allResults.Hash | Sort-Object -Unique).Count)" -Level Info
    Write-ColorLog "Known (RDS) hashes: $($knownHashes.Count)" -Level Success
    Write-ColorLog "Unknown hashes: $($unknownHashes.Count)" -Level $(if ($unknownHashes.Count -gt 0) { 'Warning' } else { 'Success' })
    
    if ($highRisk) {
        Write-ColorLog "`nHIGH RISK ITEMS DETECTED: $($highRisk.Count)" -Level Error
        $highRisk | Select-Object -First 5 | ForEach-Object {
            Write-ColorLog "  - $($_.FileNames) (Risk: $($_.RiskScore), Computers: $($_.ComputerCount))" -Level Warning
        }
    }
    
    Write-ColorLog "`nFull report: $htmlPath" -Level Info
    
    return @{
        Total = $allResults.Count
        Unknown = $unknownHashes.Count
        HighRisk = $highRisk.Count
        ReportPath = $htmlPath
    }
}

function Generate-HTMLReport {
    param($AllResults, $UnknownHashes, $Analysis)
    
    $totalComputers = ($AllResults.ComputerName | Select-Object -Unique).Count
    $totalFiles = $AllResults.Count
    $uniqueHashes = ($AllResults.Hash | Select-Object -Unique).Count
    $knownCount = $totalFiles - $UnknownHashes.Count
    $unknownCount = $UnknownHashes.Count
    
    @"
<!DOCTYPE html>
<html>
<head>
    <title>Domain Hash Analysis - $(Get-Date -Format "yyyy-MM-dd HH:mm")</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .card { background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { text-align: center; padding: 20px; border-radius: 8px; background: #f8f9fa; }
        .metric-value { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { color: #6c757d; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .danger { color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; }
        td { padding: 12px; border-bottom: 1px solid #dee2e6; }
        tr:hover { background: #f8f9fa; }
        .risk-score { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .risk-high { background: #dc3545; color: white; }
        .risk-medium { background: #ffc107; color: #212529; }
        .risk-low { background: #28a745; color: white; }
        .tag { display: inline-block; padding: 3px 8px; margin: 2px; border-radius: 3px; font-size: 0.8em; background: #e9ecef; }
        .footer { text-align: center; color: #6c757d; margin-top: 40px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0;">Domain Hash Analysis Report</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
        
        <div class="metric-grid">
            <div class="metric">
                <div class="metric-value">$totalComputers</div>
                <div class="metric-label">Computers Scanned</div>
            </div>
            <div class="metric">
                <div class="metric-value">$totalFiles</div>
                <div class="metric-label">Total Files</div>
            </div>
            <div class="metric">
                <div class="metric-value success">$knownCount</div>
                <div class="metric-label">Known Hashes</div>
            </div>
            <div class="metric">
                <div class="metric-value $(if ($unknownCount -gt 0) { 'warning' } else { 'success' })">$unknownCount</div>
                <div class="metric-label">Unknown Hashes</div>
            </div>
        </div>
        
        $(if ($Analysis | Where-Object { $_.RiskScore -ge 5 }) {
        '<div class="card">
            <h2>⚠️ High Risk Findings</h2>
            <table>
                <tr>
                    <th>Risk</th>
                    <th>File(s)</th>
                    <th>Computers</th>
                    <th>Signed</th>
                    <th>Location(s)</th>
                </tr>'
            foreach ($item in ($Analysis | Where-Object { $_.RiskScore -ge 5 } | Select-Object -First 10)) {
                $riskClass = if ($item.RiskScore -ge 7) { 'risk-high' } elseif ($item.RiskScore -ge 5) { 'risk-medium' } else { 'risk-low' }
                "<tr>
                    <td><span class='risk-score $riskClass'>$($item.RiskScore)</span></td>
                    <td>$($item.FileNames)</td>
                    <td>$($item.ComputerCount) <span class='tag'>$($item.Computers)</span></td>
                    <td>$($item.IsSigned)</td>
                    <td><small>$($item.Paths)</small></td>
                </tr>"
            }
            '</table>
        </div>'
        })
        
        <div class="card">
            <h2>Unknown Hash Summary</h2>
            <p>The following binaries were not found in the NSRL database and may require investigation.</p>
            $(if ($Analysis) {
            '<table>
                <tr>
                    <th>Hash (SHA1)</th>
                    <th>File Name(s)</th>
                    <th>Prevalence</th>
                    <th>Company</th>
                </tr>'
            foreach ($item in ($Analysis | Select-Object -First 50)) {
                "<tr>
                    <td style='font-family: monospace; font-size: 0.9em;'>$($item.Hash)</td>
                    <td>$($item.FileNames)</td>
                    <td>$($item.ComputerCount) computer(s)</td>
                    <td>$($item.CompanyName)</td>
                </tr>"
            }
            '</table>'
            })
        </div>
        
        <div class="footer">
            <p>Domain Hasher AIO v$($script:Version) | National Software Reference Library (NSRL) Database</p>
        </div>
    </div>
</body>
</html>
"@
}

#endregion

#region GPO Script Generation

function New-GPODeploymentScript {
    param([string]$SharePath)
    
    if (-not $SharePath) {
        Write-ColorLog "Network share path is required for GPO deployment" -Level Error
        return
    }
    
    $gpoScript = @'
#Requires -Version 3.0
# Domain Hasher Local Agent - Deploy via GPO
# This script runs locally on each machine and uploads results to network share

param(
    [string]$ResultShare = "NETWORK_SHARE_PATH",
    [string[]]$ScanPaths = @("C:\Users", "C:\ProgramData", "C:\Windows\Temp"),
    [int]$MaxFileSizeMB = 100
)

$ErrorActionPreference = "SilentlyContinue"
$computerName = $env:COMPUTERNAME
$resultPath = Join-Path $ResultShare "$computerName`_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

try {
    # Test share accessibility
    if (-not (Test-Path $ResultShare)) {
        throw "Cannot access result share: $ResultShare"
    }
    
    $results = @()
    $fileCount = 0
    $errorCount = 0
    
    foreach ($path in $ScanPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Include *.exe, *.dll -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.Length -lt ($MaxFileSizeMB * 1MB) }
            
            foreach ($file in $files) {
                try {
                    $hash = Get-FileHash -Path $file.FullName -Algorithm SHA1
                    $sig = Get-AuthenticodeSignature -FilePath $file.FullName
                    
                    $results += [PSCustomObject]@{
                        ComputerName = $computerName
                        Hash = $hash.Hash
                        Path = $file.FullName
                        FileName = $file.Name
                        FileSize = $file.Length
                        LastWriteTime = $file.LastWriteTime
                        IsSigned = ($sig.Status -eq 'Valid')
                        SignerCertificate = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
                        ScanDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    }
                    
                    $fileCount++
                    
                    # Write in batches to avoid memory issues
                    if ($results.Count -ge 1000) {
                        $results | Export-Csv -Path $resultPath -NoTypeInformation -Append
                        $results = @()
                    }
                }
                catch {
                    $errorCount++
                }
            }
        }
    }
    
    # Write remaining results
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $resultPath -NoTypeInformation -Append
    }
    
    # Write summary
    $summary = @{
        ComputerName = $computerName
        ScanDate = Get-Date
        FilesScanned = $fileCount
        Errors = $errorCount
        Success = $true
    }
    
    $summaryPath = Join-Path $ResultShare "$computerName`_summary.json"
    $summary | ConvertTo-Json | Out-File $summaryPath -Force
}
catch {
    # Log error
    $errorLog = @{
        ComputerName = $computerName
        Error = $_.Exception.Message
        Time = Get-Date
    }
    
    $errorPath = Join-Path $ResultShare "$computerName`_error.json"
    $errorLog | ConvertTo-Json | Out-File $errorPath -Force
}
'@

    # Replace placeholder with actual share path
    $gpoScript = $gpoScript -replace 'NETWORK_SHARE_PATH', $SharePath
    
    # Save script
    $scriptPath = Join-Path $OutputPath "DomainHasher_GPO_Agent.ps1"
    $gpoScript | Out-File -FilePath $scriptPath -Encoding UTF8
    
    # Create deployment instructions
    $instructions = @"
=== GPO Deployment Instructions ===

1. Copy the generated script to your domain controller:
   $scriptPath

2. Create a new GPO:
   - Open Group Policy Management
   - Right-click your domain/OU and select "Create a GPO"
   - Name it "Domain Hasher Security Scan"

3. Edit the GPO:
   - Computer Configuration > Policies > Windows Settings > Scripts
   - Double-click "Startup" (or "Shutdown" for end-of-day scanning)
   - Add the PowerShell script

4. Configure the share permissions:
   - Share path: $SharePath
   - Grant "Domain Computers" group:
     * Share Permissions: Change
     * NTFS Permissions: Modify

5. Link the GPO to your target OU(s)

6. Test with: gpupdate /force on a test machine

7. Monitor results in: $SharePath

8. After collection, analyze with:
   .\Invoke-DomainHasher.ps1 -Mode Analyze -OutputPath "$SharePath"

Alternative: Task Scheduler Deployment
- Use Group Policy Preferences to create a scheduled task
- Run daily/weekly during off-hours
- Use SYSTEM account for execution
"@
    
    $instructionsPath = Join-Path $OutputPath "GPO_Deployment_Instructions.txt"
    $instructions | Out-File -FilePath $instructionsPath -Encoding UTF8
    
    Write-ColorLog "`nGPO deployment files created:" -Level Success
    Write-ColorLog "  Script: $scriptPath" -Level Info
    Write-ColorLog "  Instructions: $instructionsPath" -Level Info
    Write-ColorLog "`nFollow the instructions to deploy via Group Policy" -Level Info
}

#endregion

#region STIX Export

function Export-STIX {
    param([string]$AnalysisPath)
    
    Write-ColorLog "Generating STIX 2.1 bundle..." -Level Info
    
    $unknownFiles = Get-ChildItem -Path $AnalysisPath -Filter "unknown_analysis_*.csv" | 
                   Sort-Object LastWriteTime -Descending | 
                   Select-Object -First 1
    
    if (-not $unknownFiles) {
        Write-ColorLog "No analysis files found for STIX export" -Level Warning
        return
    }
    
    $unknowns = Import-Csv $unknownFiles.FullName
    
    $stixBundle = @{
        type = "bundle"
        id = "bundle--$(New-Guid)"
        objects = @()
    }
    
    # Add identity object
    $identity = @{
        type = "identity"
        spec_version = "2.1"
        id = "identity--$(New-Guid)"
        created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        modified = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        name = "Domain Hasher AIO"
        identity_class = "system"
    }
    $stixBundle.objects += $identity
    
    # Create indicators for unknown hashes
    foreach ($unknown in $unknowns | Where-Object { $_.RiskScore -ge 3 }) {
        $indicator = @{
            type = "indicator"
            spec_version = "2.1"
            id = "indicator--$(New-Guid)"
            created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            modified = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            created_by_ref = $identity.id
            name = "Suspicious Binary: $($unknown.FileNames)"
            description = "Unknown binary detected on $($unknown.ComputerCount) computers. Risk Score: $($unknown.RiskScore)"
            pattern = "[file:hashes.SHA1 = '$($unknown.Hash)']"
            pattern_type = "stix"
            valid_from = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            labels = @("malicious-activity")
            confidence = [int](($unknown.RiskScore / 10) * 100)
            external_references = @(
                @{
                    source_name = "Domain Hasher"
                    description = "Internal threat hunting"
                }
            )
        }
        
        $stixBundle.objects += $indicator
        
        # Add observed data if high risk
        if ($unknown.RiskScore -ge 7) {
            $observed = @{
                type = "observed-data"
                spec_version = "2.1"
                id = "observed-data--$(New-Guid)"
                created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                modified = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                created_by_ref = $identity.id
                first_observed = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                last_observed = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                number_observed = [int]$unknown.TotalInstances
                object_refs = @($indicator.id)
            }
            
            $stixBundle.objects += $observed
        }
    }
    
    # Save STIX bundle
    $stixPath = Join-Path $AnalysisPath "threat_intel_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $stixBundle | ConvertTo-Json -Depth 10 | Out-File $stixPath -Encoding UTF8
    
    Write-ColorLog "STIX bundle exported: $stixPath" -Level Success
    Write-ColorLog "Contains $($stixBundle.objects.Count) objects" -Level Info
}

#endregion

#region Main Execution

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Show banner
if (-not $Quiet) {
    Write-Host $script:Banner -ForegroundColor Cyan
}

# Check permissions for non-analysis modes
if ($Mode -ne 'Analyze' -and $Mode -ne 'GenerateGPO' -and -not (Test-Administrator)) {
    Write-ColorLog "This script requires Administrator privileges for domain scanning" -Level Warning
    Write-ColorLog "Run as Administrator or use -Mode GenerateGPO for offline scanning" -Level Info
    exit 1
}

# Mode execution
switch ($Mode) {
    'GenerateGPO' {
        Write-ColorLog "Generating GPO deployment package..." -Level Info
        New-GPODeploymentScript -SharePath $NetworkShare
    }
    
    'Analyze' {
        Write-ColorLog "Starting analysis mode..." -Level Info
        
        # Find latest results or use specified path
        $scanDirs = Get-ChildItem -Path $OutputPath -Directory -Filter "Scan_*" | 
                   Sort-Object LastWriteTime -Descending
        
        if (-not $scanDirs) {
            Write-ColorLog "No scan results found in $OutputPath" -Level Error
            exit 1
        }
        
        $latestScan = $scanDirs | Select-Object -First 1
        Write-ColorLog "Analyzing results from: $($latestScan.FullName)" -Level Info
        
        # Load RDS if not skipping
        if (-not $SkipRDSCheck) {
            $rdsHashes = Get-RDSHashTable -Path $RDSPath
            if ($rdsHashes) {
                $results = Compare-WithRDS -RDSHashes $rdsHashes -ResultsPath $latestScan.FullName
                
                if ($ExportSTIX) {
                    $analysisPath = Join-Path $latestScan.FullName "_Analysis"
                    Export-STIX -AnalysisPath $analysisPath
                }
            }
        }
        else {
            Write-ColorLog "Skipping RDS comparison as requested" -Level Warning
        }
    }
    
    default {
        # Scanning modes
        Write-ColorLog "Starting $Mode scan..." -Level Info
        
        # Get scan paths
        $scanPaths = if ($Mode -eq 'Custom') {
            if (-not $CustomPaths) {
                Write-ColorLog "Custom mode requires -CustomPaths parameter" -Level Error
                exit 1
            }
            $CustomPaths
        }
        else {
            $script:ScanProfiles[$Mode].Paths
        }
        
        Write-ColorLog "Scan paths: $($scanPaths -join ', ')" -Level Info
        
        # Load RDS if not skipping
        $rdsHashes = $null
        if (-not $SkipRDSCheck) {
            $rdsHashes = Get-RDSHashTable -Path $RDSPath
            if (-not $rdsHashes) {
                Write-ColorLog "Continue without RDS comparison? (y/N)" -Level Warning
                $continue = Read-Host
                if ($continue -ne 'y') {
                    exit 1
                }
                $SkipRDSCheck = $true
            }
        }
        
        # Get computers
        $computers = Get-DomainComputers
        if ($computers.Count -eq 0) {
            Write-ColorLog "No computers found to scan" -Level Error
            exit 1
        }
        
        # Create scan directory
        $scanDir = Join-Path $OutputPath "Scan_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -ItemType Directory -Path $scanDir -Force | Out-Null
        
        Write-ColorLog "Scanning $($computers.Count) computers with $MaxThreads threads..." -Level Info
        Write-ColorLog "Results will be saved to: $scanDir" -Level Info
        
        # Scan computers
        $jobScript = {
            param($Computer, $Paths, $Output)
            
            # Re-import functions
            . $using:PSCommandPath
            
            Get-RemoteFileHashes -ComputerName $Computer -ScanPaths $Paths -ResultPath $Output
        }
        
        $completedCount = 0
        $startTime = Get-Date
        
        foreach ($computer in $computers) {
            $progress = [int](($completedCount / $computers.Count) * 100)
            Write-Progress -Activity "Scanning computers" -Status "$computer" -PercentComplete $progress
            
            Start-ThrottledJob -ScriptBlock $jobScript `
                              -ArgumentList @($computer, $scanPaths, $scanDir) `
                              -Name "Scan_$computer"
            
            $completedCount++
        }
        
        # Wait for jobs
        Write-ColorLog "Waiting for scan jobs to complete..." -Level Info
        
        while (Get-Job | Where-Object { $_.State -eq 'Running' }) {
            $running = @(Get-Job | Where-Object { $_.State -eq 'Running' }).Count
            $completed = @(Get-Job | Where-Object { $_.State -eq 'Completed' }).Count
            
            Write-Progress -Activity "Scanning computers" `
                          -Status "$completed completed, $running running" `
                          -PercentComplete (($completed / $computers.Count) * 100)
            
            Get-Job | Where-Object { $_.State -eq 'Completed' } | Remove-Job
            Start-Sleep -Seconds 2
        }
        
        Get-Job | Remove-Job -Force
        Write-Progress -Activity "Scanning computers" -Completed
        
        $duration = (Get-Date) - $startTime
        Write-ColorLog "Scan completed in $([int]$duration.TotalMinutes) minutes" -Level Success
        
        # Analyze results
        if (-not $SkipRDSCheck -and $rdsHashes) {
            $results = Compare-WithRDS -RDSHashes $rdsHashes -ResultsPath $scanDir
            
            if ($ExportSTIX -and $results.Unknown -gt 0) {
                $analysisPath = Join-Path $scanDir "_Analysis"
                Export-STIX -AnalysisPath $analysisPath
            }
        }
        
        # Open results
        if ($results.ReportPath) {
            Start-Process $results.ReportPath
        }
    }
}

Write-ColorLog "`nOperation completed successfully!" -Level Success

#endregion