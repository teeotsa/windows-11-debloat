@ECHO OFF
SET CUR_DIR=%~dp0
TITLE Windows 11 Debloater
GOTO CHECK_MAIN_FILE

:CHECK_MAIN_FILE
	IF NOT EXIST "%CUR_DIR%\src\main.ps1" (
		COLOR C
		CLS
		ECHO PowerShell files was not found, please make sure its there and run this script again.
		ECHO Excepted path : "%CUR_DIR%src\main.ps1"
		ECHO Press any key to close this script
		PAUSE > NUL
		EXIT
	)
	GOTO CHECK_ADMIN_PERMS

:CHECK_ADMIN_PERMS
	openfiles >nul 2>&1
	IF NOT %errorLevel% == 0 (
		COLOR C
		CLS
		ECHO Please run this script as Administrator
		PAUSE > NUL
		EXIT
	)
	GOTO START_SCRIPT

:START_SCRIPT
	powershell -NoProfile -ExecutionPolicy Bypass -File "%CUR_DIR%\src\main.ps1"
	EXIT
