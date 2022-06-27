@ECHO OFF
TITLE Restore Windows Update
GOTO CHECK_ADMIN_PERMS
SET CURRENTPATH=%~dp0

:START_SCRIPT
	IF EXIST "%~dp0\Module\Restore.ps1" (
		powershell -File "%~dp0\Module\Restore.ps1" -WindowsUpdate
	) ELSE (
		COLOR C
		CLS
		ECHO Failed to find module, press any key to exit.
		PAUSE > NUL
		EXIT
	)
	EXIT
	
:: Source : https://stackoverflow.com/questions/4051883/batch-script-how-to-check-for-admin-rights
:CHECK_ADMIN_PERMS
	net session >nul 2>&1
	IF NOT %errorLevel% == 0 (
		COLOR C
		CLS
		ECHO This script requires you to have admin premission. Please run this script as admin!
		PAUSE > NUL
		EXIT
	)
	GOTO START_SCRIPT
    
PAUSE > NUL