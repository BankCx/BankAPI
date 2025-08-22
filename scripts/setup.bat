@echo off
REM Setup script for Bank API (Windows)

echo Setting up Bank API...

REM Create logs directory
if not exist logs mkdir logs

REM Create virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt

REM Generate requirements.txt from requirements.in if pip-tools is available
pip-compile --version >nul 2>&1
if %errorlevel% == 0 (
    echo Compiling requirements...
    pip-compile requirements.in
)

echo Setup complete! Run 'venv\Scripts\activate' to activate the virtual environment.
