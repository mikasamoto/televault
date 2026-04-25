@echo off
title TeleVault Web Server
echo ---------------------------------------------------
echo 🚀 TeleVault Web Server
echo ---------------------------------------------------
echo.

:: Move to parent directory so we can find index.js and node_modules
cd /d "%~dp0.."

:: Check if node_modules exists
if not exist node_modules (
    echo 📦 First time setup: Installing dependencies...
    echo.
    call npm install
    if %errorlevel% neq 0 (
        echo.
        echo ❌ ERROR: Failed to install dependencies. 
        echo Please make sure Node.js is installed.
        pause
        exit /b
    )
    echo.
    echo ✅ Dependencies installed successfully!
    echo.
)

echo ⚡ Starting server...
node index.js
if %errorlevel% neq 0 (
    echo.
    echo ❌ App crashed. See error above.
    pause
)
pause
