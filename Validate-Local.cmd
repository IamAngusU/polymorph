@echo off
setlocal
pushd "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" scripts\validate_local.py %*
) else (
  py -3 scripts\validate_local.py %*
)
set "result=%ERRORLEVEL%"
echo.
echo Validation exit code: %result%
echo Reports: .polymorph\validation
popd
pause
exit /b %result%
