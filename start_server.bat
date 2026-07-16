@echo off
echo ==========================================
echo  AVS Assessment Console Server Bootloader
echo ==========================================
echo.
echo [1/2] Verifying and installing requirements...
python -m pip install -r requirements.txt
echo.
echo [2/2] Launching AVS Web Server on port 8080...
python report_viewer.py
pause
