@echo off
:menu
cls
echo =====================================================================
echo                AVS Assessment Platform Control Panel
echo =====================================================================
echo.
echo  [1] Start Secure Web Console Dashboard (HTTPS Local)
echo  [2] Start Containerized Service (Docker Compose)
echo  [3] Stop Containerized Service (Docker Down)
echo  [4] Execute Headless Scanner CLI (cli.py)
echo  [5] Exit
echo.
echo =====================================================================
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto local_web
if "%choice%"=="2" goto docker_up
if "%choice%"=="3" goto docker_down
if "%choice%"=="4" goto run_cli
if "%choice%"=="5" goto exit_menu
goto menu

:local_web
echo.
echo [*] Verifying and installing requirements...
python -m pip install -r requirements.txt
echo [*] Starting local HTTPS web server on port 8080...
python report_viewer.py
pause
goto menu

:docker_up
echo.
echo [*] Building and launching containerized AVS services...
docker-compose up --build
pause
goto menu

:docker_down
echo.
echo [*] Stopping and removing containerized assets...
docker-compose down
pause
goto menu

:run_cli
echo.
set /p target="Enter target hostname or IP address: "
set /p profile="Enter profile (quick/standard/deep/udp/hyper): "
echo [*] Running headless vulnerability scan against %target%...
python cli.py -t %target% --profile %profile%
pause
goto menu

:exit_menu
echo.
echo Goodbye!
exit
