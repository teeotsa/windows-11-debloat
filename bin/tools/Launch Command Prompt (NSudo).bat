@ECHO OFF
TITLE Command Prompt ( NSudo )
SET CUR_DIR=%~dp0
IF NOT EXIST %CUR_DIR% ( ECHO Something is wrong, press any key to exit & PAUSE > NUL & EXIT )
GOTO CHECK_ADMIN_PERMS

:CHECK_ADMIN_PERMS
	net session >nul 2>&1
	IF NOT %errorLevel% == 0 (
		COLOR C
		CLS
		ECHO This script requires you to have admin premission. Please run this script
		ECHO as admin!
		PAUSE > NUL
		EXIT
	)
	GOTO START_INSTANCE
	
:START_INSTANCE
	IF NOT EXIST "%CUR_DIR%\nsudo.exe" ( ECHO NSudo executable is missing, press any key to exit & PAUSE > NUL & EXIT )
	"%CUR_DIR%\nsudo.exe" -U:S -P:E -M:S CMD