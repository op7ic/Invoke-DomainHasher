# Domain Hasher Investigation Examples
# These snippets help analyze results after scanning

#region Quick Investigation Commands

# Set your results path
$ResultsPath = ".\DomainHasherResults"

# 1. Find all HIGH RISK items from latest scan
Get-ChildItem "$ResultsPath\Scan_*\_Analysis\HIGH_RISK_*.csv" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 1 | 
    Import-Csv | 
    Format-Table -AutoSize

# 2. Search for specific hash across all computers
$suspiciousHash = "A1B2C3D4E5F6789012345678901234567890ABCD"
Get-ChildItem "$ResultsPath\Scan_*\*\hashes.csv" -Recurse | 
    Select-String $suspiciousHash | 
    ForEach-Object {
        $computer = Split-Path (Split-Path $_.Path -Parent) -Leaf
        "$computer : $($_.Line)"
    }

# 3. Find all unsigned executables in temp folders
Get-ChildItem "$ResultsPath\Scan_*\*\hashes.csv" -Recurse | 
    ForEach-Object { 
        $computer = Split-Path (Split-Path $_.FullName -Parent) -Leaf
        Import-Csv $_ | Where-Object { 
            $_.IsSigned -eq 'False' -and 
            $_.Path -match '\\Temp\\|\\AppData\\Local\\Temp\\'
        } | Add-Member -NotePropertyName Computer -NotePropertyValue $computer -PassThru
    } | 
    Select-Object Computer, FileName, Path, Hash | 
    Sort-Object FileName

# 4. Find files that appear on multiple computers (potential spreading malware)
$allHashes = Get-ChildItem "$ResultsPath\Scan_*\*\hashes.csv" -Recurse | 
    ForEach-Object { Import-Csv $_ }

$spreading = $allHashes | 
    Group-Object Hash | 
    Where-Object { $_.Count -gt 2 } | 
    ForEach-Object {
        $computers = $_.Group.ComputerName | Select-Object -Unique
        [PSCustomObject]@{
            Hash = $_.Name
            FileName = $_.Group[0].FileName
            ComputerCount = $computers.Count
            Computers = $computers -join ', '
            Signed = $_.Group[0].IsSigned
        }
    } | Sort-Object ComputerCount -Descending

$spreading | Format-Table -AutoSize

# 5. Timeline analysis - when did files first appear?
$timeline = Get-ChildItem "$ResultsPath\Scan_*\*\hashes.csv" -Recurse | 
    ForEach-Object { Import-Csv $_ } | 
    Where-Object { $_.IsSigned -eq 'False' } | 
    Select-Object @{N='Date';E={[datetime]$_.CreationTime}}, FileName, ComputerName, Path | 
    Sort-Object Date

# Show recent additions
$timeline | Where-Object { $_.Date -gt (Get-Date).AddDays(-7) }

#endregion

#region Advanced Hunting Queries

# Hunt for files with suspicious characteristics
function Find-SuspiciousFiles {
    param(
        [string]$Path = ".\DomainHasherResults\Scan_*"
    )
    
    $suspicious = @()
    
    Get-ChildItem "$Path\*\hashes.csv" -Recurse | ForEach-Object {
        $computer = Split-Path (Split-Path $_.FullName -Parent) -Leaf
        Import-Csv $_ | ForEach-Object {
            $score = 0
            $reasons = @()
            
            # Unsigned
            if ($_.IsSigned -eq 'False') { 
                $score += 2
                $reasons += "Unsigned"
            }
            
            # Suspicious location
            if ($_.Path -match '\\Temp\\|\\AppData\\Roaming\\|\\Public\\') { 
                $score += 2
                $reasons += "Suspicious Location"
            }
            
            # No company info
            if (-not $_.CompanyName -or $_.CompanyName -eq '') { 
                $score += 1
                $reasons += "No Company"
            }
            
            # Recent file
            if ([datetime]$_.CreationTime -gt (Get-Date).AddDays(-7)) { 
                $score += 1
                $reasons += "Recent"
            }
            
            # Hidden or system
            if ($_.Path -match '\\\.') { 
                $score += 1
                $reasons += "Hidden"
            }
            
            if ($score -ge 3) {
                $suspicious += [PSCustomObject]@{
                    Computer = $computer
                    Score = $score
                    FileName = $_.FileName
                    Path = $_.Path
                    Hash = $_.Hash
                    Reasons = $reasons -join ', '
                    Created = $_.CreationTime
                }
            }
        }
    }
    
    return $suspicious | Sort-Object Score -Descending
}

# Run the hunt
$suspects = Find-SuspiciousFiles
$suspects | Format-Table -AutoSize

# Export for further investigation
$suspects | Export-Csv ".\suspicious_files_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

#endregion

#region Comparison Between Scans

# Compare two scans to find new files
function Compare-Scans {
    param(
        [string]$OldScan,
        [string]$NewScan
    )
    
    Write-Host "Comparing scans..." -ForegroundColor Cyan
    
    # Load all hashes from each scan
    $oldHashes = Get-ChildItem "$OldScan\*\hashes.csv" -Recurse | 
        ForEach-Object { Import-Csv $_ } | 
        Select-Object -ExpandProperty Hash -Unique
    
    $newFiles = Get-ChildItem "$NewScan\*\hashes.csv" -Recurse | 
        ForEach-Object { 
            $computer = Split-Path (Split-Path $_.FullName -Parent) -Leaf
            Import-Csv $_ | Where-Object { $_.Hash -notin $oldHashes } |
            Add-Member -NotePropertyName Computer -NotePropertyValue $computer -PassThru
        }
    
    Write-Host "Found $($newFiles.Count) new files since last scan" -ForegroundColor Yellow
    
    return $newFiles
}

# Example: Compare last two scans
$scans = Get-ChildItem "$ResultsPath\Scan_*" -Directory | Sort-Object Name -Descending | Select-Object -First 2
if ($scans.Count -eq 2) {
    $newFiles = Compare-Scans -OldScan $scans[1].FullName -NewScan $scans[0].FullName
    $newFiles | Select-Object Computer, FileName, Path, IsSigned | Format-Table -AutoSize
}

#endregion

#region IOC Generation

# Generate IOCs from unknown hashes
function Export-IOCs {
    param(
        [string]$AnalysisPath,
        [string]$OutputFile = ".\domain_hasher_iocs.txt"
    )
    
    $iocs = @()
    
    # Get all unknown hashes
    $unknowns = Get-ChildItem "$AnalysisPath\unknown_analysis_*.csv" | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 1 | 
        Import-Csv
    
    # Create IOC list
    $iocs += "# Domain Hasher IOCs - Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $iocs += "# High Risk Unknown Binaries"
    $iocs += ""
    
    $unknowns | Where-Object { $_.RiskScore -ge 5 } | ForEach-Object {
        $iocs += "# Risk Score: $($_.RiskScore) | Seen on: $($_.ComputerCount) computers"
        $iocs += "# Files: $($_.FileNames)"
        $iocs += "$($_.Hash)"
        $iocs += ""
    }
    
    $iocs | Out-File $OutputFile
    Write-Host "IOCs exported to: $OutputFile" -ForegroundColor Green
}

# Generate IOCs from latest scan
$latestScan = Get-ChildItem "$ResultsPath\Scan_*" -Directory | Sort-Object Name -Descending | Select-Object -First 1
if ($latestScan) {
    Export-IOCs -AnalysisPath "$($latestScan.FullName)\_Analysis"
}

#endregion

#region Remediation Helpers

# Generate PowerShell script to remove suspicious files
function New-RemediationScript {
    param(
        [string]$CsvPath,
        [string]$OutputScript = ".\remediate_suspicious_files.ps1"
    )
    
    $targets = Import-Csv $CsvPath
    
    $script = @"
# Remediation Script - Generated $(Get-Date)
# REVIEW CAREFULLY BEFORE RUNNING!

`$files = @(
"@
    
    foreach ($target in $targets) {
        $script += "`n    @{Computer='$($target.Computer)'; Path='$($target.Path)'; Hash='$($target.Hash)'}"
    }
    
    $script += @"
)

foreach (`$file in `$files) {
    Write-Host "Processing `$(`$file.Computer): `$(`$file.Path)" -ForegroundColor Yellow
    
    # Verify hash before deletion
    if (Test-Path "`\\`$(`$file.Computer)\`$(`$file.Path -replace ':', '`$')") {
        `$currentHash = Get-FileHash -Path "`\\`$(`$file.Computer)\`$(`$file.Path -replace ':', '`$')" -Algorithm SHA1
        
        if (`$currentHash.Hash -eq `$file.Hash) {
            # Backup first
            `$backupPath = "`\\`$(`$file.Computer)\C`$\Quarantine\`$(`$file.Hash).bak"
            New-Item -Path (Split-Path `$backupPath -Parent) -ItemType Directory -Force | Out-Null
            Copy-Item -Path "`\\`$(`$file.Computer)\`$(`$file.Path -replace ':', '`$')" -Destination `$backupPath
            
            # Remove file
            Remove-Item -Path "`\\`$(`$file.Computer)\`$(`$file.Path -replace ':', '`$')" -Force
            Write-Host "  Removed and backed up to `$backupPath" -ForegroundColor Green
        }
        else {
            Write-Host "  Hash mismatch - skipping" -ForegroundColor Red
        }
    }
}
"@
    
    $script | Out-File $OutputScript
    Write-Host "Remediation script created: $OutputScript" -ForegroundColor Green
    Write-Host "REVIEW CAREFULLY before running!" -ForegroundColor Yellow
}

#endregion

Write-Host @"

Domain Hasher Investigation Toolkit Loaded!

Available functions:
- Find-SuspiciousFiles     : Hunt for suspicious binaries
- Compare-Scans           : Find new files between scans  
- Export-IOCs             : Generate IOC list
- New-RemediationScript   : Create cleanup script

Example usage:
  `$suspicious = Find-SuspiciousFiles
  `$suspicious | Where-Object { `$_.Score -ge 5 } | Export-Csv "high_risk.csv"

"@ -ForegroundColor Cyan