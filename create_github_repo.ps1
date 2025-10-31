# Script to create GitHub repository using GitHub API
# Usage: .\create_github_repo.ps1 -Token YOUR_GITHUB_TOKEN

param(
    [Parameter(Mandatory=$true)]
    [string]$Token,
    
    [string]$RepoName = "AI-Powered-Alert-Prioritization-for-Wazuh",
    [string]$Description = "AI-powered security alert prioritization pipeline for Wazuh with LLM analysis and TheHive integration",
    [switch]$Private = $true
)

$headers = @{
    "Authorization" = "token $Token"
    "Accept" = "application/vnd.github.v3+json"
}

$body = @{
    name = $RepoName
    description = $Description
    private = $Private
} | ConvertTo-Json

try {
    Write-Host "Creating repository: $RepoName..." -ForegroundColor Yellow
    $response = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Method Post -Headers $headers -Body $body
    
    Write-Host "Repository created successfully!" -ForegroundColor Green
    Write-Host "Repository URL: $($response.html_url)" -ForegroundColor Cyan
    Write-Host ""
    
    # Automatically add remote
    $cloneUrl = $response.clone_url
    Write-Host "Adding remote origin..." -ForegroundColor Yellow
    try {
        git remote remove origin 2>$null
    } catch { }
    
    git remote add origin $cloneUrl
    Write-Host "Remote added successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Now push your code:" -ForegroundColor Yellow
    Write-Host "  git push -u origin main" -ForegroundColor White
    
    return $cloneUrl
} catch {
    Write-Host "Error creating repository: $_" -ForegroundColor Red
    $_.Exception.Response | Select-Object -ExpandProperty StatusCode
    exit 1
}

