@echo off
setlocal
cd /d "%~dp0"
if exist "K95Diagnostic_v0_2_rebuilt.exe" (
    echo The rebuilt file already exists. Move it before building again.
    exit /b 1
)
where g++ >nul 2>nul
if not errorlevel 1 goto mingw
where cl >nul 2>nul
if errorlevel 1 (
    echo Use a 64-bit MinGW-w64 shell or an x64 Native Tools Command Prompt for Visual Studio.
    echo No compiler is needed to run the supplied executable.
    exit /b 1
)
cl /nologo /std:c++17 /O2 /W4 /MT /EHsc /Fe:K95Diagnostic_v0_2_rebuilt.exe source\K95Diagnostic.cpp /link /SUBSYSTEM:WINDOWS setupapi.lib hid.lib comdlg32.lib gdi32.lib advapi32.lib user32.lib
exit /b %errorlevel%

:mingw
g++ -std=c++17 -O2 -Wall -Wextra -Werror -static -static-libgcc -static-libstdc++ -municode -mwindows -Wl,--dynamicbase,--nxcompat,--high-entropy-va -s -o K95Diagnostic_v0_2_rebuilt.exe source\K95Diagnostic.cpp -lsetupapi -lhid -lcomdlg32 -lgdi32 -ladvapi32 -luser32
exit /b %errorlevel%
