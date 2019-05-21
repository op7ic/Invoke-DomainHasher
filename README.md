# Overview
This is a PowerShell script which will attempt to enumerate binaries in windows domain enviroment and compare collected list against known hash set from [NIST NSRL](https://www.nist.gov/itl/ssd/software-quality-group/nsrl-download). Any binary which is present in the enviroment and not listed on NIST dataset could be considered as potential source of intelligence for Threat Hunting. Resulting list of binaries are not necessary malicious however external hash check (i.e. VirusTotal) should be performed to verify this.  

# Running

Run ```Invoke-DomainHasher.ps1``` as domain administrator on domain connected system.

From command line it should be run as follows: 
```powershell.exe -nop -exec bypass .\Invoke-DomainHasher.ps1```

# Help

```
-=[ Invoke-DomainHasher v0.3A ]=-
        by op7ic

Usage: powershell .\Invoke-DomainHasher.ps1 [options]

Options:
  -fast      (default) Fast checks across across the domain (User profile folders only - C:\Users\*). Results stored in .\fast-output
  -full      Full checks across across the domain (entire C$ share). Results stored in .\full-output. **Slow**
  -help      Show this help menu
```

# False Positivies

Using this method of checking for binaries can result in a lot of false positivites. Not every legitimate binary is present on NIST NSRL index. Results should be therefore verified using third party tools such as VirusTotal.

# Process
The script will perform following actions:

* Enumerate LDAP structure of the current domain and identify any object matching 'computer' filter. This is done using "System.DirectoryServices.DirectorySearcher" method.
* For each identified system, create hashlist of either (fast mode) C:\Users\* folders or (full mode) C$ share
* For each identified system, store results in either .\fast-output or .\full-output depending on selected option
* For each identified system, compare the lists (CSV) stored in .\fast-output or .\full-output with master set of NIST hashes and single out anything that is not in the NIST hash
* For every hash not in the NIST dataset check for signature, time of appearance and other binary details, write the result to .\combined-output folder. 
* Both known and unknown files are written to .\combined-output folder in CSV and JSON formats

# Sources of Inspiration
https://www.nist.gov/itl/ssd/software-quality-group/nsrl-download

# TODO
- [ ] Improve output method
- [ ] Improve performance of sorting and searching parts
