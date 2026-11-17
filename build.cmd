@echo off
rem build.cmd - builds ntrdpc.exe on Windows NT 3.1, 3.5, 3.51 or 4.0.
rem Run it in this folder, in a prompt where the compiler works.
rem   build          build ntrdpc.exe
rem   build clean    delete what the build made
rem The Win32 SDK of 1993 (NT 3.1) is used when its compiler is on the PATH
rem (cl386, mcl or claxp), else Visual C++ (cl). The CPU comes from
rem PROCESSOR_ARCHITECTURE. Written for the cmd of NT 3.1: one command after
rem "do", no "=" in a "set" value, no "call :label".
setlocal
set N_TOOLS=vc
for %%d in (%PATH%) do if exist %%d\cl386.exe set N_TOOLS=sdk31
for %%d in (%PATH%) do if exist %%d\mcl.exe set N_TOOLS=sdk31
for %%d in (%PATH%) do if exist %%d\claxp.exe set N_TOOLS=sdk31
set N_CPU=%PROCESSOR_ARCHITECTURE%
if "%N_CPU%"=="x86" set N_CPU=i386
if "%N_CPU%"=="" goto nocpu
echo build: TOOLS=%N_TOOLS% CPU=%N_CPU%
nmake -nologo TOOLS=%N_TOOLS% CPU=%N_CPU% %1
goto end
:nocpu
echo build: PROCESSOR_ARCHITECTURE is empty. Type: nmake TOOLS=%N_TOOLS% CPU=i386
echo (or CPU=MIPS, ALPHA or PPC)
:end
endlocal
