param(
    [string]$MobSFApiKey = $env:PRS_MOBSF_API_KEY
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

if ($MobSFApiKey) {
    $env:PRS_MOBSF_API_KEY = $MobSFApiKey
}

docker compose -f docker-compose.mobile.yml up --build
