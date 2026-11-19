@echo off
title Sentinel-ID dev server (Claude test)
cd /d "%~dp0"
set PORT=3001
npm run dev -- -p 3001
pause
