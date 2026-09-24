@echo off

set "DEEP_DIR=%~dp0"

reg add "HKCU\Software\Classes\deep" /ve /d "URL:DEEP Protocol" /f
reg add "HKCU\Software\Classes\deep" /v "URL Protocol" /d "" /f

reg add "HKCU\Software\Classes\deep\shell\open\command" /ve /d "\"%DEEP_DIR%deep_launcher.bat\" \"%%1\"" /f

echo.
echo DEEP Protocol registered successfully.
echo.
pause