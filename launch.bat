@echo off
title Launch Debloater Script...
IF EXIST "%~dp0win11debloat.ps1" (
	color 02
	echo. Launching the script...
	powershell "%~dp0win11debloat.ps1"
) ELSE (
	color 04
	echo. Script wasn't found! Closing in 5 seconds!
	timeout 5 /nobreak > nul
	exit
)
