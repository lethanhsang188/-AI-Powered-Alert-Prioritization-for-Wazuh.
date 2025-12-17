param(
    [string]$LogDirectory = "logs",
    [string]$LogPrefix = "pipeline",
    [string]$PythonExecutable = "py",
    [string[]]$PythonArgs = @("-3", "bin\\run_pipeline.py")
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null

$logPath = Join-Path $LogDirectory ("{0}_{1}.txt" -f $LogPrefix, $timestamp)
Write-Host "Writing output to $logPath" -ForegroundColor Cyan

& $PythonExecutable $PythonArgs 2>&1 | Tee-Object -FilePath $logPath


