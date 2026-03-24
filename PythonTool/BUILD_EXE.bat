@echo off
title CyberSentinel v3 — Build EXE
color 0A

echo.
echo ============================================================
echo   CyberSentinel v3 — Automated EXE Builder
echo ============================================================
echo.

REM ── Step 1: Check Python ────────────────────────────────────
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.8+ from python.org
    pause
    exit /b 1
)
python --version
echo       Python OK
echo.

REM ── Step 2: Install dependencies ────────────────────────────
echo [2/5] Installing required packages...
python -m pip install --upgrade pip --quiet
python -m pip install pyinstaller pillow reportlab --quiet
if errorlevel 1 (
    echo ERROR: Failed to install packages. Check your internet connection.
    pause
    exit /b 1
)
echo       Packages installed OK
echo.

REM ── Step 3: Create icon (skip if already exists) ────────────
echo [3/5] Checking for icon...
if exist cybersentinel.ico (
    echo       Icon found: cybersentinel.ico
) else (
    echo       No icon found — building without icon
    echo       (Place cybersentinel.ico in this folder to add one)
)
echo.

REM ── Step 4: Build EXE ───────────────────────────────────────
echo [4/5] Building EXE with PyInstaller...
echo       This may take 2-5 minutes. Please wait...
echo.

if exist cybersentinel.ico (
    python -m PyInstaller ^
        --onefile ^
        --windowed ^
        --name "CyberSentinel_v3" ^
        --icon=cybersentinel.ico ^
        --add-data "modules;modules" ^
        --hidden-import tkinter ^
        --hidden-import tkinter.ttk ^
        --hidden-import tkinter.filedialog ^
        --hidden-import tkinter.messagebox ^
        --hidden-import PIL ^
        --hidden-import PIL.Image ^
        --hidden-import PIL.ExifTags ^
        --hidden-import reportlab ^
        --hidden-import reportlab.platypus ^
        --hidden-import reportlab.lib.styles ^
        --hidden-import sqlite3 ^
        --hidden-import hashlib ^
        --hidden-import urllib.request ^
        --hidden-import json ^
        --hidden-import shutil ^
        --hidden-import threading ^
        --hidden-import zipfile ^
        --hidden-import xml.etree.ElementTree ^
        --hidden-import struct ^
        --hidden-import csv ^
        --clean ^
        main.py
) else (
    python -m PyInstaller ^
        --onefile ^
        --windowed ^
        --name "CyberSentinel_v3" ^
        --add-data "modules;modules" ^
        --hidden-import tkinter ^
        --hidden-import tkinter.ttk ^
        --hidden-import tkinter.filedialog ^
        --hidden-import tkinter.messagebox ^
        --hidden-import PIL ^
        --hidden-import PIL.Image ^
        --hidden-import PIL.ExifTags ^
        --hidden-import reportlab ^
        --hidden-import reportlab.platypus ^
        --hidden-import reportlab.lib.styles ^
        --hidden-import sqlite3 ^
        --hidden-import hashlib ^
        --hidden-import urllib.request ^
        --hidden-import json ^
        --hidden-import shutil ^
        --hidden-import threading ^
        --hidden-import zipfile ^
        --hidden-import xml.etree.ElementTree ^
        --hidden-import struct ^
        --hidden-import csv ^
        --clean ^
        main.py
)

if errorlevel 1 (
    echo.
    echo ERROR: Build failed. See error messages above.
    pause
    exit /b 1
)

echo.

REM ── Step 5: Done ────────────────────────────────────────────
echo [5/5] Build complete!
echo.
echo ============================================================
echo   SUCCESS! Your EXE is ready:
echo.
echo   dist\CyberSentinel_v3.exe
echo.
echo   File size will be approx 30-60 MB (normal for Python EXE)
echo   Double-click the EXE to run — no Python needed on other PCs
echo ============================================================
echo.

REM Open the dist folder
explorer dist

pause
