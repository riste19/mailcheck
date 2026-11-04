@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Install Node.js 20 or newer from https://nodejs.org then run this again.
  pause
  exit /b 1
)
echo Open http://127.0.0.1:4317 in your browser. Keep this window open.
node server.mjs
pause
