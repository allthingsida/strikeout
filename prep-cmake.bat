@echo off

setlocal

:: EA64=YES
if not exist build64 mkdir build64
pushd build64

cmake -A x64 -G "Visual Studio 16 2019" .. -DEA64=YES

if "%2"=="" (set cfg=Release) else (set cfg=%2)
if "%1"=="build64" cmake --build . --config %cfg%
popd


:: EA64=NO
if not exist build mkdir build
pushd build
cmake -A x64 -G "Visual Studio 16 2019" .. -DEA64=NO
if "%2"=="" (set cfg=Release) else (set cfg=%2)
if "%1"=="build" cmake --build . --config %cfg%
popd

echo.
echo All done!
echo.