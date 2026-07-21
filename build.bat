@echo off
REM Build VMP Tracer Pintool for ia32 using Pin's makefile system
REM Requires: VS2022 BuildTools with C++ workload

set PIN_ROOT=%~dp0pin
set PATH=%PATH%;C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\Hostx86\x86

REM Set up MSVC x86 environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86

cd /d "%~dp0"
nmake /f makefile PIN_ROOT="%PIN_ROOT%" TARGET=ia32
