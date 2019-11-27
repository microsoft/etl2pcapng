@echo off
msbuild -t:rebuild -p:configuration=release -p:platform=win32
msbuild -t:rebuild -p:configuration=release -p:platform=x64
rmdir /s /q etl2pcapng
del etl2pcapng.zip
mkdir etl2pcapng
mkdir etl2pcapng\x64
mkdir etl2pcapng\x86
copy x64\release\etl2pcapng.exe etl2pcapng\x64
copy x64\release\etl2pcapng.pdb etl2pcapng\x64
copy release\etl2pcapng.exe etl2pcapng\x86
copy release\etl2pcapng.pdb etl2pcapng\x86
echo Now zip up etl2pcapng directory and upload to github.
