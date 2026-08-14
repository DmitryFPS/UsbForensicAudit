@echo off
chcp 866 >nul
setlocal
cd /d "%~dp0"

rem Трассировка загрузчика .NET: apphost, hostfxr, hostpolicy и распаковка
rem single-file. Это единственный способ увидеть стадию до запуска
rem управляемого кода - именно там приложение зависало на проблемных ноутбуках.
if not exist "data" mkdir "data"
set COREHOST_TRACE=1
set COREHOST_TRACE_VERBOSITY=4
set COREHOST_TRACEFILE=%~dp0data\host-trace.log

echo ================================================================
echo  Запуск UsbForensicAudit с полной трассировкой
echo ================================================================
echo.
echo  Журнал загрузчика  : %~dp0data\host-trace.log
echo  Журнал приложения  : %~dp0data\app.log
echo.
echo  Не закрывайте это окно, пока программа работает.
echo.

"%~dp0UsbForensicAudit.exe"
set EXITCODE=%ERRORLEVEL%

echo.
echo ================================================================
echo  Программа завершилась. Код выхода: %EXITCODE%
echo ================================================================
echo.
echo  Заархивируйте папку data и передайте разработчику.
echo.
pause
