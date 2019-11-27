@echo off
msbuild -t:rebuild -p:configuration=release -p:platform=win32
msbuild -t:rebuild -p:configuration=release -p:platform=x64
rmdir /s /q releases
mkdir releases
mkdir releases\x64
mkdir releases\x86
copy x64\release\etl2pcapng.exe releases\x64
copy x64\release\etl2pcapng.pdb releases\x64
copy release\etl2pcapng.exe releases\x86
copy release\etl2pcapng.pdb releases\x86
echo Now zip up releases directory and upload to github.