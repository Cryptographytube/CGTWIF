@echo off
REM ===========================================================================
REM  CGTWIF  -  one-click build   (cryptographytube engine)
REM  Author: Sisujhon
REM  Builds CGTWIF_Scanner.exe + CGTWIF_Reaper.exe  (GPU, multi-arch fatbin)
REM  Just double-click this file, or run:  build.bat
REM ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

echo(
echo ==========================================================
echo   CGTWIF build - by Sisujhon (cryptographytube)
echo ==========================================================

REM ---- 1. locate Visual Studio (vcvars64) -------------------------------------
set "VS="
for %%V in (
  "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
  "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
) do if not defined VS if exist %%V set "VS=%%~V"

if not defined VS (
  echo ERROR: Visual Studio ^(vcvars64.bat^) not found.
  echo        Install "Desktop development with C++" and re-run.
  pause & exit /b 1
)
echo   VS      : %VS%
call "%VS%" >nul 2>&1

REM ---- 2. check CUDA nvcc ------------------------------------------------------
where nvcc >nul 2>&1
if errorlevel 1 (
  echo ERROR: nvcc ^(CUDA Toolkit^) not on PATH. Install CUDA 12.x and re-run.
  pause & exit /b 1
)
for /f "tokens=*" %%c in ('nvcc --version ^| find "release"') do echo   CUDA    : %%c

REM ---- 3. paths / flags -------------------------------------------------------
set "SRC=cryptographytube"

set "ARCH=-gencode=arch=compute_75,code=sm_75 -gencode=arch=compute_86,code=sm_86 -gencode=arch=compute_89,code=sm_89 -gencode=arch=compute_120,code=sm_120 -gencode=arch=compute_120,code=compute_120"
set "DEFS=-DWIN64 -D_CRT_SECURE_NO_WARNINGS"
set "NVFLAGS=-allow-unsupported-compiler -O3 -m64 -std=c++14 --use_fast_math -Xptxas -O3 %DEFS% -I%SRC% -I."

REM ---- all host support sources are handed straight to nvcc (no .obj step) -----
set "SRCS=%SRC%\lib\Int.cpp %SRC%\lib\IntMod.cpp %SRC%\lib\Point.cpp %SRC%\lib\SECP256K1.cpp %SRC%\lib\util.cpp %SRC%\lib\hash\sha256.cpp %SRC%\lib\hash\ripemd160.cpp %SRC%\lib\base58.c"

echo(
echo === engine 1: CGTWIF_Scanner ===
nvcc %NVFLAGS% %ARCH% -o CGTWIF_Scanner.exe CGTWIF_Scanner.cu %SRCS% || goto :fail

if exist CGTWIF_Reaper.cu (
  echo(
  echo === engine 2: CGTWIF_Reaper ===
  nvcc %NVFLAGS% %ARCH% -o CGTWIF_Reaper.exe CGTWIF_Reaper.cu %SRCS% || goto :fail
)

echo(
echo ==========================================================
echo   BUILD OK
echo ==========================================================
dir /b *.exe
echo(
echo Try:  CGTWIF_Scanner.exe -f btc.txt -mask ^<prefix+?...^> -r
pause
exit /b 0

:fail
echo(
echo *** BUILD FAILED *** (see the error above)
pause
exit /b 1
