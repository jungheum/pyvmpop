@echo off
pushd %~dp0
:: get the current local date & time (using date.exe from UnxUitls)
for /f "tokens=1-6 delims=," %%a in ('date_of_unxutils.exe +"%%Y,%%m,%%d,%%H,%%M,%%S"') do (
    set mydate=%%a-%%b-%%c
    set mytime=%%d:%%e:%%f
)
echo %mydate% %mytime%
popd

:: get the current timezone
set timezone_keyname=
set standard_name=

for /f "tokens=1,2*" %%K in ('reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TimeZoneInformation') do (
	if %%K==TimeZoneKeyName set timezone_keyname=%%M
    if %%K==StandardName    set standard_name=%%M
)

if not "%timezone_keyname%" == "" (
	for /f "tokens=1,2*" %%K in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\%timezone_keyname%"') do (
		if %%K==Display  set timezone=%%M
	)
) else (
    :: Windows XP or lower
    set timezone=%standard_name%  
)

echo %timezone:&=^&%
