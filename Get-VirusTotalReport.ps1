# Define API Key
$config = Get-Content .\config.json | ConvertFrom-Json
$apikey = $config.Key

function Get-HashReport{

    $path = Read-Host "Paste file path (Ctrl + Shift + C)"
    $file = Get-FileHash -Path $path.Replace('"', "")
    $hash = $file.hash 

    # URI/API Request

    $uri = "https://virustotal.com/vtapi/v2/file/report?apikey=$apikey&resource=$hash"

    $results = Invoke-RestMethod -Uri $uri
    Write-Host "Raw output has been added to current directory"
    $results | Out-File .\reports\Raw_HashReport_$hash.txt
    Write-Host "`nOutput" -ForegroundColor Red -BackgroundColor Yellow
    $results
}

function Get-DomainReport {
    $domain = Read-Host "Paste domain or ip address"
    Write-Host "`nNsLookup Information:" -ForegroundColor Red -BackgroundColor Yellow
    nslookup $domain
    $uri = "https://virustotal.com/vtapi/v2/url/report?apikey=$apikey&resource=$domain"
    $results = Invoke-RestMethod -Uri $uri
    Write-Host "Raw output has been added to current directory"
    $results | Out-File .\reports\Raw-DomainReport_$domain.txt
    Write-Host "`nOutput" -ForegroundColor Red -BackgroundColor Yellow
    $results
}

Write-Host "`nPowershell VirusTotal Report Tool" -ForegroundColor Blue
Write-Host "Version: 1" -ForegroundColor Blue

Write-Host "`n`nWhat would you like a report on?"
Write-Host "`n1. File Hash"
Write-Host "2. IP Address or Domain"

$choice = Read-Host "Input Number"

if ($choice -eq "1") {
    Get-HashReport
}
Elseif ($choice -eq "2") {
    Get-DomainReport
}
else {
    Write-Host "Input invalid, please try again"
}