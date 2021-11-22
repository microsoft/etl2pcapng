@echo off
pushd %~dp0
rmdir /s /q build_release
mkdir build_release
cd build_release
mkdir x64
mkdir x86
cd x64
cmake -A x64 ../..
cmake --build . --config Release
cd ..
cd x86
cmake -A Win32 ../..
cmake --build . --config Release
popd
rmdir /s /q etl2pcapng
del etl2pcapng.zip
mkdir etl2pcapng
mkdir etl2pcapng\x64
mkdir etl2pcapng\x86
copy build_release\x64\Release\etl2pcapng.exe etl2pcapng\x64
copy build_release\x64\Release\etl2pcapng.pdb etl2pcapng\x64
copy build_release\x86\Release\etl2pcapng.exe etl2pcapng\x86
copy build_release\x86\Release\etl2pcapng.pdb etl2pcapng\x86
echo Now zip up etl2pcapng directory and upload to github.
