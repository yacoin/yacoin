@echo off
rem cmd started from MSYS has problems running subsequent commands after bootstrap so all commands are concatenated with "and"
@echo on

bootstrap mingw && ^
b2 -a toolset=gcc cxxflags="-std=gnu++0x -Wno-deprecated-declarations -Wno-unused-variable -Wno-unknown-pragmas" ^
--with-chrono --with-filesystem --with-regex --with-program_options --with-system --with-thread --with-date_time ^
--link=static --runtime-link=static linkflags="-static -static-libgcc -static-libstdc++ -s" threading=multi variant=release --prefix="%YBOO%" install && ^
cd "%YBOO%/include" && ^
move "INCLUDESUBDIR/boost" . && ^
cd "%YBOO%/lib" && ^
for /f "tokens=1,2,3,4,5 delims=-." %%i in ('dir /B "*.a"') DO @echo off && ren "%%i-%%j-%%k-%%l.%%m" "%%i.%%m" && @echo on && echo "Boost build done. Please close window or type exit."

exit
