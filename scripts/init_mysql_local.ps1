<#
Initialize a local MySQL container for SecureChat (development only).

Usage (PowerShell):
  .\scripts\init_mysql_local.ps1

This script will:
- ensure Docker is available
- pull and run `mysql:8` as `securechat-db` (if not already present)
- wait until MySQL is accepting connections
- call Python to run `storage.db.init_db()` using values from `.env`

Do NOT run this in a production environment. Passwords here are for
local development only and match `.env` defaults in the repository.
#>

Write-Host "Starting local MySQL container 'securechat-db' (mysql:8)..."

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is not available on PATH. Install Docker Desktop and try again."
    exit 1
}

$exists = docker ps -a --format "{{.Names}}" | Select-String -Pattern "^securechat-db$"
if ($exists) {
    Write-Host "Container 'securechat-db' already exists. Starting it..."
    docker start securechat-db | Out-Null
} else {
    Write-Host "Pulling mysql:8 and running container..."
    docker pull mysql:8 | Out-Null
    docker run -d --name securechat-db `
        -e MYSQL_ROOT_PASSWORD=rootpass `
        -e MYSQL_DATABASE=securechat `
        -e MYSQL_USER=scuser `
        -e MYSQL_PASSWORD=scpass `
        -p 3306:3306 mysql:8 | Out-Null
}

Write-Host "Waiting for MySQL to accept connections (this may take 10-30s)..."
$max = 60
$i = 0
while ($i -lt $max) {
    try {
        docker exec securechat-db mysqladmin ping -uroot -prootpass --silent > $null 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "MySQL is ready."
            break
        }
    } catch {
        # ignore
    }
    Start-Sleep -Seconds 2
    $i++
}

if ($i -ge $max) {
    Write-Error "MySQL did not become ready in time. Check container logs: docker logs securechat-db"
    exit 2
}

Write-Host "Initializing users table via Python (with retries)..."
$maxAttempts = 6
$attempt = 1
$initSuccess = $false
while ($attempt -le $maxAttempts) {
    Write-Host ("Attempt " + $attempt + " of " + $maxAttempts + ": running Python init")
    python -c "from dotenv import load_dotenv; load_dotenv(); import storage.db as db; db.init_db(); print('users table initialized')"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "users table initialized"
        $initSuccess = $true
        break
    }
    Write-Host ("Initialization attempt " + $attempt + " failed (exit code " + $LASTEXITCODE + "). Retrying in 3s...")
    Start-Sleep -Seconds 3
    $attempt++
}

if (-not $initSuccess) {
    Write-Error "Failed to initialize users table after $maxAttempts attempts. Check container logs: docker logs securechat-db"
    exit 3
}

Write-Host "Initialization complete. The MySQL container 'securechat-db' is running and the users table exists."
Write-Host "You can stop it with: docker stop securechat-db && docker rm securechat-db"
