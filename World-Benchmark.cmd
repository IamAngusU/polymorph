@echo off
setlocal
cd /d "%~dp0"
set "PYTHON=.venv\Scripts\python.exe"
if not exist "%PYTHON%" set "PYTHON=python"
echo Polymorph local evidence run
echo No upload, commit, push, model download, or GitHub Action will be started.
"%PYTHON%" scripts\evidence_bundle.py --project "%CD%" %*
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if "%EXIT_CODE%"=="0" (
  echo Evidence run passed.
) else (
  echo Evidence run completed with findings. Exit code: %EXIT_CODE%
)
exit /b %EXIT_CODE%
