::
:: VmPop Script for Windows
:: - Wait for IDLE status -
::
@echo off
setlocal EnableDelayedExpansion

:: '30 percent' is enough to identify if logon processes are completed or not
:: When Windows is trying to execute system processes, CPU load is maintained about 90~100 percent

set IDLE_PERCENT=30
set IDLE_TIME=7
set time_elapsed=0

:wait_until_idle
	call :get_cpu_load
	set cpu_load=%ERRORLEVEL%
	
	call :get_current_time
	echo CPU: %cpu_load%
	
	if %cpu_load% geq %IDLE_PERCENT% (
		set time_elapsed=0
        timeout /t 1 /nobreak > nul
		goto wait_until_idle
	) else (
		set /a time_elapsed=%time_elapsed%+1
	)

	if %time_elapsed% lss %IDLE_TIME% (
		goto wait_until_idle
	)
	
	echo [VmPop] The system is idle
	exit /b
	
:get_cpu_load
	set sum=0
	set num=0
	
    for /f "tokens=2 delims==" %%p in ('wmic cpu get LoadPercentage /value ^|find "="') do (
        set /a sum=!sum!+%%p
        set /a num=!num!+1
    )

    if %num% gtr 0 (
        set /a avg=%sum%/%num%
    ) else (
        set avg=0
    )

	exit /b %avg%
	
:get_current_time  
    for /f "tokens=1-3 delims=:." %%a in ("%TIME%") do (set mytime=%%a:%%b:%%c)
	echo | set /p=(%mytime%)

endlocal
