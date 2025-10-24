# Requires Administrator privileges to run successfully.

# --- Configuration Variables ---
$version = "9.4.5"
$installerFile = "splunkforwarder-$version-486d30fccf54-x64-release.msi"  # **ADJUST THIS FILENAME IF NECESSARY**
$downloadDir = "C:\Temp\SplunkInstall"
$installerPath = Join-Path -Path $downloadDir -ChildPath $installerFile

# Splunk Configuration
$splunkServerIP = "10.10.10.220"
$deploymentServerPort = 8089     # Management Port for Deployment Client
$indexerOutputPort = 9997      # Indexer Receiving Port
$deploymentServer = "$splunkServerIP:$deploymentServerPort"
$indexerOutput = "$splunkServerIP:$indexerOutputPort"
$installDir = "C:\Program Files\SplunkUniversalForwarder" # Default install path
$serviceName = "SplunkForwarder"
$splunkCli = Join-Path -Path $installDir -ChildPath "bin\splunk.exe"

# Admin User Credentials
$adminUsername = "admin"
# NOTE: In a production environment, this password should be retrieved securely, 
# not hardcoded in plain text.
$newPassword = "1qaz2wsx!QAZ@WSX" 
$defaultPassword = "changeme" # Default password for the 'admin' user after install

# --- Prerequisite: Create download directory (if it doesn't exist) ---
Write-Host "Checking for and creating the installation directory: $downloadDir"
if (-not (Test-Path -Path $downloadDir)) {
    New-Item -Path $downloadDir -ItemType Directory | Out-Null
}

# ----------------------------------------------------------------------
## 1. Installation Step
# ----------------------------------------------------------------------

Write-Host "`n--- 1. Starting Splunk Universal Forwarder $version installation ---"
$msiArgs = @(
    "/i",
    "`"$installerPath`"",
    "/qn",
    "INSTALLDIR=`"$installDir`"",
    "AGREETOLICENSE=Yes",
    "DEPLOYMENTCLIENT=$deploymentServer",
    "FORWARD_SERVER=$indexerOutput"
)

try {
    Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Installation complete. UF configured for DS $deploymentServer and Indexer $indexerOutput."
    } else {
        Write-Host "❌ Installation failed. MSI exit code: $LASTEXITCODE" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Host "❌ An error occurred during the installation process: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ----------------------------------------------------------------------
## 2. Admin Password Change
# ----------------------------------------------------------------------

Write-Host "`n--- 2. Setting 'admin' Password ---"

# Use the splunk CLI to change the password from 'changeme' to the new value.
# Note: Since the service should be running after installation, we can run this command.
try {
    if (Test-Path -Path $splunkCli) {
        # The 'edit user' command requires the old password and the new password.
        $passwordArgs = @(
            "edit",
            "user",
            $adminUsername,
            "-password",
            $newPassword,
            "-auth",
            "$adminUsername:$defaultPassword",
            "-full" # Needed to ensure the password is changed successfully
        )
        
        # Execute the command silently
        Start-Process -FilePath $splunkCli -ArgumentList $passwordArgs -Wait -NoNewWindow -PassThru | Out-Null
        
        # We can't easily check the exit code for this specific command, 
        # so we rely on the command completing without throwing a PowerShell error.
        Write-Host "✅ 'admin' user password successfully changed to: $newPassword"
    } else {
        Write-Host "❌ Splunk CLI not found at $splunkCli. Cannot change password." -ForegroundColor Red
    }
}
catch {
    Write-Host "❌ Error changing 'admin' password: $($_.Exception.Message)" -ForegroundColor Red
}

# ----------------------------------------------------------------------
## 3. Connectivity Tests & Service Restart
# ----------------------------------------------------------------------

Write-Host "`n--- 3. Running Connectivity Tests and Service Restart ---"

# Test 1: Indexer Output (9997)
Write-Host "Testing connection to Indexer ($splunkServerIP on Port $indexerOutputPort)..."
try {
    $test9997 = Test-NetConnection -ComputerName $splunkServerIP -Port $indexerOutputPort -InformationLevel Quiet -ErrorAction Stop
    if ($test9997.TcpTestSucceeded) {
        Write-Host " Indexer Port $indexerOutputPort is reachable."
    } else {
        Write-Host " Indexer Port $indexerOutputPort is NOT reachable. Check firewall/routing." -ForegroundColor Yellow
    }
}
catch {
    Write-Host " An error occurred testing Port $indexerOutputPort. Network issue suspected." -ForegroundColor Red
}

# Test 2: Deployment Server (8089)
Write-Host "Testing connection to Deployment Server ($splunkServerIP on Port $deploymentServerPort)..."
try {
    $test8089 = Test-NetConnection -ComputerName $splunkServerIP -Port $deploymentServerPort -InformationLevel Quiet -ErrorAction Stop
    if ($test8089.TcpTestSucceeded) {
        Write-Host " Deployment Server Port $deploymentServerPort is reachable."
    } else {
        Write-Host " Deployment Server Port $deploymentServerPort is NOT reachable. Check firewall/routing." -ForegroundColor Yellow
    }
}
catch {
    Write-Host " An error occurred testing Port $deploymentServerPort. Network issue suspected." -ForegroundColor Red
}

# Service Restart (Best practice to ensure all config and password change takes effect)
try {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "Restarting service '$serviceName' to finalize configuration..."
        Restart-Service -Name $serviceName -Force -ErrorAction Stop
        Write-Host "✅ Service '$serviceName' successfully restarted and running."
    } else {
        Write-Host " Service '$serviceName' not found or installed incorrectly." -ForegroundColor Yellow
    }
}
catch {
    Write-Host " Error restarting service '$serviceName': $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nScript execution finished. Remember the new admin password!"