@echo off
echo Aetrna Offline Decryption Tool (Windows)
echo ========================================
echo.

REM
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
  echo Error: Node.js not found! Please install Node.js from https://nodejs.org/
  echo.
  pause
  exit /b 1
)

REM
if not exist "%~dp0decrypt.js" (
  echo Error: decrypt_offline.js not found in the current directory!
  echo.
  pause
  exit /b 1
)

REM
if not exist "%~dp0node_modules" (
  echo Installing dependencies...
  call npm install
  if %ERRORLEVEL% neq 0 (
    echo Error installing dependencies!
    pause
    exit /b 1
  )
  echo Dependencies installed successfully.
  echo.
)

REM
node "%~dp0decrypt.js" %*

REM
if %* == "" pause 