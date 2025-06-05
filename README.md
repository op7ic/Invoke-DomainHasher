# Domain Hasher v3.0

A powerful PowerShell script for threat hunting using NIST's National Software Reference Library (NSRL).

## Overview

This PowerShell script enumerates executables and DLLs across a Windows domain environment and compares them against the known hash set from [NIST NSRL](https://www.nist.gov/itl/ssd/software-quality-group/nsrl-download). Any binary present in the environment but not listed in the NIST dataset could be a potential source of intelligence for threat hunting. While the resulting list of binaries are not necessarily malicious, they represent unknowns that warrant investigation through external hash checks (e.g., VirusTotal) or manual analysis.

### Why Use Domain Hasher?

- **Identify Unknown Binaries**: Quickly find executables that aren't part of standard software installations
- **Threat Hunting**: Discover potentially malicious files that evade traditional antivirus
- **Compliance**: Maintain visibility of all executables across your domain
- **Incident Response**: Rapidly assess the spread of suspicious files across multiple systems

## Features

- **Single File Solution**: Everything consolidated into one PowerShell script
- **Modern PowerShell**: Optimized for PowerShell 5.1+ with proper threading and performance management
- **Smart RDS Handling**: Automatic download, caching, and flexible path options for NSRL database
- **GPO Deployment**: Generate scripts for firewalled/isolated systems that can't be reached directly
- **Built-in Analysis**: Report and STIX export without external dependencies
- **Better Performance**: CPU throttling, parallel processing, and efficient hash lookups using hashtables
- **Enhanced Output**: Per-computer folders for easy investigation and grep operations

## Quick Start

```powershell
# Run as Domain Administrator
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DomainHasher.ps1 -Mode Fast

# Full system scan with existing RDS file
.\Invoke-DomainHasher.ps1 -Mode Full -RDSPath "C:\Downloads\NSRLFile.txt"

# Generate GPO deployment package for firewalled systems
.\Invoke-DomainHasher.ps1 -Mode GenerateGPO -NetworkShare "\\FileServer\HashResults$"

# Analyze previous results with threat intelligence export
.\Invoke-DomainHasher.ps1 -Mode Analyze -ExportSTIX
```

## Running

Run as domain administrator on a domain-connected system:

```powershell
# Standard execution
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-DomainHasher.ps1 -Mode Fast

# With no profile for minimal interference
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-DomainHasher.ps1 -Mode Fast
```

## Help

```
=== Invoke-DomainHasher ===

SYNOPSIS:
    All-in-One Domain Binary Hasher for Threat Hunting

SYNTAX:
    .\Invoke-DomainHasher.ps1 -Mode <String> [Options]

MODES:
    -Mode Fast       Fast scan (User profiles: C:\Users\*, C:\ProgramData)
    -Mode Full       Full scan (Entire C:\ drive) **Slower**
    -Mode Targeted   Targeted scan (Common malware locations)
    -Mode Custom     Custom scan (Specify paths with -CustomPaths)
    -Mode Analyze    Analyze existing results
    -Mode GenerateGPO Generate GPO deployment scripts

OPTIONS:
    -RDSPath <String>         Path to existing RDS file (ZIP or NSRLFile.txt)
    -OutputPath <String>      Output directory (default: .\DomainHasherResults)
    -MaxThreads <Int>         Maximum concurrent threads (default: 4)
    -CPUThreshold <Int>       CPU usage limit percentage (default: 70)
    -TargetComputers <String> Specific computers (comma-separated or file path)
    -CustomPaths <String[]>   Custom paths for scanning
    -NetworkShare <String>    UNC path for GPO results
    -SkipRDSCheck            Skip NSRL comparison
    -ExportSTIX              Export results in STIX format
    -DaysToAnalyze <Int>     Days to include in analysis (default: 30)
    -Quiet                   Suppress verbose output

EXAMPLES:
    # Quick scan with automatic setup
    .\Invoke-DomainHasher.ps1 -Mode Fast
    
    # Full scan with custom RDS location
    .\Invoke-DomainHasher.ps1 -Mode Full -RDSPath "D:\NSRL\NSRLFile.txt"
    
    # Targeted threat hunt on specific computers
    .\Invoke-DomainHasher.ps1 -Mode Targeted -TargetComputers "WS01,WS02,SERVER01"
    
    # Generate GPO package for offline scanning
    .\Invoke-DomainHasher.ps1 -Mode GenerateGPO -NetworkShare "\\DC01\Shares\HashCollection$"
```

## How It Works

The script performs the following process:

1. **Domain Enumeration**: Uses LDAP/Active Directory to enumerate all computer objects in the domain
2. **Hash Collection**: For each identified system, creates SHA1 hashes of executables and DLLs from:
   - Fast mode: `C:\Users\*` and `C:\ProgramData` (user profiles only)
   - Full mode: Entire `C:\` drive (comprehensive but slower)
   - Targeted mode: Common malware locations (temp folders, AppData, system directories)
3. **Parallel Processing**: Uses configurable threading with CPU throttling to prevent system overload
4. **RDS Comparison**: Compares collected hashes against NIST NSRL database (~3.5 million known good hashes)
5. **Risk Analysis**: Scores unknown binaries based on:
   - Digital signature status
   - File location (suspicious paths get higher scores)
   - Prevalence across multiple computers
   - Missing company/version information
6. **Report Generation**: Creates comprehensive outputs including CSV, JSON, HTML reports, and STIX format

## RDS Database Setup

### ⚠️ Important: RDS File Size Warning
The NIST NSRL Reference Data Set (RDS) is substantial:
- **Download Size**: ~3-4 GB (compressed)
- **Extracted Size**: ~15-20 GB (NSRLFile.txt)
- **Processing Requirements**: ~4-8 GB RAM
- **Cache File**: ~500 MB (speeds up subsequent runs)

### Managing RDS Size

#### Option 1: Use RDS Modern (Recommended)
The "Modern" RDS subset contains only recent software and is much smaller:
```powershell
# Default URL uses RDS Modern
.\Invoke-DomainHasher.ps1 -Mode Fast
```

#### Option 2: Use Custom Minimal RDS
Download only the minimal RDS set from NIST for testing:
```powershell
.\Invoke-DomainHasher.ps1 -Mode Fast -RDSUrl "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/RDS_minimal.zip"
```

#### Option 3: Pre-Download and Extract
Download RDS manually to a fast drive with space:
```powershell
# 1. Download to separate location
Invoke-WebRequest -Uri "https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/RDS_modern.zip" -OutFile "E:\RDS\RDS_modern.zip"

# 2. Extract (use 7-zip for better performance)
7z x "E:\RDS\RDS_modern.zip" -o"E:\RDS\Extract"

# 3. Point script to extracted file
.\Invoke-DomainHasher.ps1 -Mode Fast -RDSPath "E:\RDS\Extract\NSRLFile.txt"
```

#### Option 4: Use Existing Download
If you've already downloaded RDS:
```powershell
# Point to ZIP file
.\Invoke-DomainHasher.ps1 -Mode Fast -RDSPath "C:\Downloads\RDS_modern.zip"

# Point to extracted NSRLFile.txt
.\Invoke-DomainHasher.ps1 -Mode Fast -RDSPath "C:\RDS\NSRLFile.txt"

# Point to folder containing NSRLFile.txt
.\Invoke-DomainHasher.ps1 -Mode Fast -RDSPath "C:\RDS_Extracted\"
```

#### Option 5: Skip RDS Check
For initial hash collection without comparison:
```powershell
# Just collect hashes, analyze later
.\Invoke-DomainHasher.ps1 -Mode Fast -SkipRDSCheck

# Later, analyze with RDS
.\Invoke-DomainHasher.ps1 -Mode Analyze -RDSPath "E:\RDS\NSRLFile.txt"
```

### RDS Caching
After first run, the script creates a cached hashtable (~500MB) for faster subsequent runs:
- Cache location: `.\DomainHasherResults\rds_cache.clixml`
- Valid for 30 days (configurable)
- Dramatically speeds up analysis (seconds vs minutes)

## Scan Modes

### Fast Mode (Default)
- Scans: `C:\Users`, `C:\ProgramData`
- Best for: Quick daily scans
- Time: 5-30 minutes per computer

### Full Mode
- Scans: Entire `C:\` drive
- Best for: Comprehensive analysis
- Time: 1-4 hours per computer

### Targeted Mode
- Scans: Common malware locations
  - User temp folders
  - AppData\Roaming
  - Windows\Temp
  - System directories
- Best for: Focused threat hunting

### Custom Mode
```powershell
.\Invoke-DomainHasher.ps1 -Mode Custom -CustomPaths @("D:\Apps", "E:\Tools")
```

## Deployment Options

### Direct Domain Scan (Requires Admin)
```powershell
# Scan all domain computers
.\Invoke-DomainHasher.ps1 -Mode Fast

# Scan specific computers
.\Invoke-DomainHasher.ps1 -Mode Fast -TargetComputers "Server01,Server02,Workstation01"

# Scan from computer list file
.\Invoke-DomainHasher.ps1 -Mode Fast -TargetComputers ".\computers.txt"
```

### GPO Deployment (For Firewalled Systems)
```powershell
# Generate GPO package
.\Invoke-DomainHasher.ps1 -Mode GenerateGPO -NetworkShare "\\DC01\HashCollection$"

# This creates:
# - DomainHasher_GPO_Agent.ps1 (deploy via GPO)
# - GPO_Deployment_Instructions.txt (setup guide)
```

## Output Structure

Files are organized in a hierarchical structure for easy investigation:

```
DomainHasherResults\                # Main output directory
├── DomainHasher_20241105.log     # Execution log
├── rds_cache.clixml               # Cached RDS hashtable (speeds up subsequent runs)
├── rds_info.json                  # Cache metadata
├── Scan_20241105_143022\          # Timestamped scan session
│   ├── Computer01\                # Per-computer results
│   │   ├── hashes.csv            # All collected hashes with metadata
│   │   ├── summary.json          # Scan statistics for this computer
│   │   └── errors.log            # Any errors encountered
│   ├── Computer02\
│   │   └── ...
│   └── _Analysis\                 # Aggregated analysis results
│       ├── unknown_hashes_*.csv        # All unknown binaries (raw)
│       ├── unknown_analysis_*.csv      # Risk-scored unknown binaries
│       ├── HIGH_RISK_*.csv            # Priority threats (risk score ≥5)
│       ├── known_hashes_*.csv         # Binaries found in NSRL
│       ├── report_*.html              # Visual HTML report
│       └── threat_intel_*.json        # STIX 2.1 format for SIEM integration
```

### Key Output Files

- **hashes.csv**: Contains SHA1, file path, size, timestamps, signature status, version info
- **unknown_analysis_*.csv**: Unknown binaries
- **HIGH_RISK_*.csv**: Immediate attention required - unsigned files in suspicious locations
- **report_*.html**: Report with charts and summaries

## Analysis and Reporting

### View Results
```powershell
# Analyze latest scan
.\Invoke-DomainHasher.ps1 -Mode Analyze

# Export to STIX format for threat intelligence platforms
.\Invoke-DomainHasher.ps1 -Mode Analyze -ExportSTIX
```

### Risk Scoring
Files are scored based on:
- Prevalence (seen on multiple computers)
- Digital signature status
- File location (temp folders, etc.)
- Company information presence

### Using Results

#### Find specific hash across all computers:
```powershell
Get-ChildItem -Path ".\DomainHasherResults\Scan_*\*\hashes.csv" | 
    Select-String "A1B2C3D4E5F6789012345678901234567890ABCD" | 
    ForEach-Object { $_.Path }
```

#### List all unsigned executables in temp folders:
```powershell
Get-ChildItem -Path ".\DomainHasherResults\Scan_*\*\hashes.csv" | 
    ForEach-Object { Import-Csv $_ } | 
    Where-Object { $_.IsSigned -eq 'False' -and $_.Path -match '\\Temp\\' } |
    Select-Object ComputerName, FileName, Path | 
    Format-Table
```

#### Find binaries appearing on multiple computers (potential malware spread):
```powershell
# Load the investigation toolkit
. .\Investigation-Examples.ps1

# Hunt for suspicious files
$suspicious = Find-SuspiciousFiles
$suspicious | Where-Object { $_.Score -ge 5 } | Format-Table -AutoSize
```

## False Positives

Using NSRL comparison will result in some false positives because:
- Not every legitimate binary is present in the NSRL index
- Custom/proprietary software won't be in NSRL
- Newly released software may not yet be indexed
- Some legitimate tools used by IT/developers might be flagged

**Mitigation strategies:**
1. The risk scoring system helps prioritize real threats over false positives
2. Check HIGH_RISK items first - these combine multiple suspicious indicators
3. Verify unknowns using VirusTotal or your threat intelligence platform
4. Build a whitelist of known-good hashes specific to your environment
5. Focus on unsigned binaries in suspicious locations (temp folders, user profiles)

## Real-World Examples

### Daily Security Operations
```powershell
# Morning threat hunt - fast scan of all workstations
.\Invoke-DomainHasher.ps1 -Mode Fast -TargetComputers ".\workstations.txt"

# Weekly deep scan of servers
.\Invoke-DomainHasher.ps1 -Mode Full -TargetComputers "SERVER*" -MaxThreads 2

# Investigate specific incident - custom paths
.\Invoke-DomainHasher.ps1 -Mode Custom -CustomPaths @("C:\Temp", "C:\Users\*\Downloads") -TargetComputers "INFECTED-PC01,INFECTED-PC02"
```

### Incident Response Scenario
```powershell
# 1. Initial compromise assessment
.\Invoke-DomainHasher.ps1 -Mode Targeted -MaxThreads 8

# 2. Analyze results for IOCs
.\Invoke-DomainHasher.ps1 -Mode Analyze -ExportSTIX

# 3. Search for specific malware hash across domain
$malwareHash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
Get-ChildItem ".\DomainHasherResults\Scan_*\*\hashes.csv" -Recurse | 
    Select-String $malwareHash | 
    ForEach-Object { 
        Write-Host "FOUND: $($_.Filename)" -ForegroundColor Red 
    }

# 4. Generate remediation list
Import-Csv ".\DomainHasherResults\Scan_*\_Analysis\HIGH_RISK_*.csv" |
    Where-Object { $_.Hash -eq $malwareHash } |
    Export-Csv ".\computers_to_clean.csv"
```

### Compliance Audit
```powershell
# Scan for unauthorized software
.\Invoke-DomainHasher.ps1 -Mode Fast

# Find all unsigned executables
$results = Get-ChildItem ".\DomainHasherResults\Scan_*\*\hashes.csv" -Recurse |
    ForEach-Object { Import-Csv $_ } |
    Where-Object { $_.IsSigned -eq 'False' }

# Generate compliance report
$results | Group-Object ComputerName | 
    Select-Object Name, Count | 
    Export-Csv ".\unsigned_software_by_computer.csv"
```

### Threat Hunting Campaign
```powershell
# 1. Baseline scan
.\Invoke-DomainHasher.ps1 -Mode Full -OutputPath ".\Baseline"

# 2. Wait a week, scan again
Start-Sleep -Seconds 604800  # Or schedule via Task Scheduler
.\Invoke-DomainHasher.ps1 -Mode Full -OutputPath ".\Week2"

# 3. Compare scans to find new binaries
. .\Investigation-Examples.ps1
$newFiles = Compare-Scans -OldScan ".\Baseline\Scan_*" -NewScan ".\Week2\Scan_*"

# 4. Investigate new unsigned files
$newFiles | Where-Object { $_.IsSigned -eq 'False' } | 
    Select-Object Computer, FileName, Path, Hash |
    Export-Csv ".\new_unsigned_binaries.csv"
```

## Requirements

- **PowerShell**: Version 5.1 or higher
- **Permissions**: Domain Administrator (for direct scanning) or local admin (for GPO agent)
- **Network**: SMB access to target computers (TCP 445) for direct scanning
- **Disk Space**: 
  - ~120GB free for full RDS processing
  - ~20GB for result storage (varies by domain size)
- **Memory**: 4-8GB RAM recommended for RDS processing

## Troubleshooting

### "Access Denied" Errors
- Ensure running as Domain Admin: `whoami /groups`
- Check Windows Firewall allows SMB: `Test-NetConnection COMPUTERNAME -Port 445`
- Use GPO mode for restricted systems
- Verify WinRM is enabled: `Enable-PSRemoting -Force`

### High Memory Usage
- Normal during RDS processing (building hashtable)
- Use cached RDS after first run (automatic)
- Consider splitting large domains into OUs

### Slow Performance
- Reduce MaxThreads parameter
- Use Fast mode instead of Full
- Exclude unnecessary paths with Custom mode
- Check network latency to target systems

### RDS Download Issues
- Manually download from [NIST](https://www.nist.gov/itl/ssd/software-quality-group/nsrl-download/current-rds)
- Use alternative mirror if available
- Ensure sufficient disk space (120GB+)
- Check proxy settings if behind corporate firewall

## Integration Examples

### SIEM Integration
```powershell
# Schedule daily scans with STIX export
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Invoke-DomainHasher.ps1 -Mode Targeted -ExportSTIX"
Register-ScheduledTask -TaskName "DomainHasher" -Trigger $trigger -Action $action -RunLevel Highest
```

### Email Alerts
```powershell
# After scanning, check for high-risk items
$highRisk = Get-Content ".\DomainHasherResults\Scan_*\_Analysis\HIGH_RISK_*.csv" | ConvertFrom-Csv

if ($highRisk) {
    Send-MailMessage -To "security@company.com" `
        -Subject "Domain Hasher Alert: $($highRisk.Count) High Risk Items" `
        -Body ($highRisk | ConvertTo-Html -Fragment | Out-String) `
        -BodyAsHtml -SmtpServer "mail.company.com"
}
```

### Splunk Integration
```powershell
# Convert results to Splunk-friendly format
Get-ChildItem ".\DomainHasherResults\Scan_*\*\hashes.csv" -Recurse |
    ForEach-Object { 
        Import-Csv $_ | ConvertTo-Json -Compress 
    } | Out-File "\\splunk-indexer\intake\domainhasher.json"
```

## Security Considerations

- **Hashes**: Uses SHA1 to match NSRL format (not for security, just comparison)
- **Network Traffic**: Generates SMB traffic to all scanned systems
- **Results Security**: Output contains sensitive path information - secure appropriately
- **Credentials**: Consider using a dedicated service account with limited permissions
- **Data Retention**: Implement retention policy for scan results

## Credits and References

- [NIST NSRL Documentation](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl)
- [STIX 2.1 Specification](https://oasis-open.github.io/cti-documentation/stix/intro.html)

---

**Remember**: This tool identifies unknown binaries, not necessarily malicious ones. Always verify findings through additional analysis before taking action. When in doubt, preserve evidence and consult with a security team.