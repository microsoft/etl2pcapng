@echo off

pushd %~dp0

pushd %~dp0
if exist build_release rmdir /s /q build_release
mkdir build_release
mkdir build_release\x64
mkdir build_release\x86
cd build_release\x64
cmake -A x64 ../..
cmake --build . --config Release
"C:/Program Files (x86)/WiX Toolset v3.11/bin/candle.exe" ..\..\installer.wxs -o Release\etl2pcapng.wixobj
"C:/Program Files (x86)/WiX Toolset v3.11/bin/light.exe" -b Release -o Release\etl2pcapng.msi Release\etl2pcapng.wixobj
cd ..\x86
cmake -A Win32 ../..
cmake --build . --config Release
popd

if exist etl2pcapng rmdir /s /q etl2pcapng
mkdir etl2pcapng
mkdir etl2pcapng\x64
mkdir etl2pcapng\x86
copy build_release\x64\Release\etl2pcapng.exe etl2pcapng\x64
copy build_release\x64\Release\etl2pcapng.pdb etl2pcapng\x64
copy build_release\x64\Release\etl2pcapng.msi etl2pcapng\x64
copy build_release\x86\Release\etl2pcapng.exe etl2pcapng\x86
copy build_release\x86\Release\etl2pcapng.pdb etl2pcapng\x86

if exist etl2pcapng.zip del etl2pcapng.zip
echo Now zip up etl2pcapng directory and upload to github.

popd
