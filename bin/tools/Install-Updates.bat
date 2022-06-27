@ECHO OFF
COLOR A

:: I'm dumb, you don't need to extract .cab file. Only if you're working with .msu files

SET CUR_DIR=%~dp0
SET UPDATE_FLDR="%CUR_DIR%\updates"
SET TMP_FLDR="%CUR_DIR%\tmp"
SET LOG="%CUR_DIR%\log.txt"
IF NOT EXIST %CUR_DIR% ( ECHO Something went wrong, press any key to close this script. & PAUSE > NUL & EXIT )
IF NOT EXIST %TMP_FLDR% ( MD %TMP_FLDR% )
IF NOT EXIST %UPDATE_FLDR% ( MD %UPDATE_FLDR% )
IF NOT EXIST %LOG% ( ECHO Log file >> %LOG% )
GOTO CHECK_ADMIN_PERMS

:CHECK_ADMIN_PERMS
	net session >nul 2>&1
	IF NOT %errorLevel% == 0 (
		COLOR C & CLS
		ECHO This script requires you to have admin premission. Please run this script & ECHO as admin!
		PAUSE > NUL & EXIT
	)
	GOTO QUESTION
	
:QUESTION
	CLS
	TITLE Bulk Install Windows Updates
	ECHO This script installs Cabinet Files (*.cab) only to online image! Your update packages should be placed in tmp folder
	ECHO Do you want to continue?
	ECHO 1 ) Yes
	ECHO 2 ) No
	
	SET /P SELECTION=""
	IF %SELECTION% == 2 (
		GOTO EXIT_SCRIPT
	) ELSE IF %SELECTION% == 1 (
		GOTO CONTINUE_SCRIPT
	)
	GOTO QUESTION
	
:CONTINUE_SCRIPT
	GOTO MENU

:FORCE_EXIT_SCRIPT
	IF EXIST "%TMP_FLDR%" ( RD %TMP_FLDR% /S /Q )
	ECHO Force exited >> %LOG%
	EXIT

:EXIT_SCRIPT
	CLS
	IF EXIST "%TMP_FLDR%" ( ECHO Cleaning temp folder, wait... & RD %TMP_FLDR% /S /Q )
	CLS
	ECHO Do you want to delete updates from update folder? 
	ECHO 1 ) Yes
	ECHO 2 ) No
	SET /P SELECTION=""
	IF %SELECTION% == 1 ( RD %UPDATE_FLDR% /S /Q )
	CLS
	ECHO Done, press any key to close this script.
	PAUSE > NUL & EXIT
	
:MENU
	CLS
	ECHO 1 ) Install Cabinet Files (Online Image)
	ECHO 2 ) Exit script
	SET /P SELECTION=""
	IF %SELECTION% == 2 ( GOTO EXIT_SCRIPT )
	IF %SELECTION% == 1 ( GOTO START_INSTALLING )
	GOTO MENU

:DONE_INSTALLING
	CLS
	ECHO Installing done, navigating to menu
	TIMEOUT 3 /NOBREAK > NUL
	GOTO MENU

:START_INSTALLING
	IF NOT EXIST %UPDATE_FLDR% ( ECHO Update folder not found >> %LOG% && GOTO FORCE_EXIT_SCRIPT )
	FOR %%F IN ("%UPDATE_FLDR%\*.cab") DO (
		ECHO Installing %%F >> %LOG%
		Dism /Add-Package /PackagePath:"%%F" /IgnoreCheck /PreventPending /Online >> %LOG%
	)
	GOTO INSTALL_MSU
	
:INSTALL_MSU
	FOR %%S IN ("%UPDATE_FLDR%\*.msu") DO (
		FOR %%A in (%%S) DO (
			SET FLDR_NAME=%~n0 
		)
		ECHO %FLDR_NAME%
		IF NOT EXIST "%TMP_FLDR%\%FLDR_NAME%" ( MD "%TMP_FLDR%\%FLDR_NAME%" )
	)
	PAUSE
	GOTO DONE_INSTALLING