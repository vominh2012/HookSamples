@echo off

if not exist build mkdir build

pushd build

REM del *.pdb

set COMMON_FLAGS=/Od /W3 /Z7 /EHsc /wd4996 /nologo /MD /FC
set BUILD_FLAGS=%COMMON_FLAGS%  /link /LIBPATH:../

cl /LD ../WSHook.cpp /FeWSHook.dll %BUILD_FLAGS% 

REM del *.ilk
REM del *.obj

popd
