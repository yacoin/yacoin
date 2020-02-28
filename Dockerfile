FROM mcr.microsoft.com/windows/servercore:ltsc2019
MAINTAINER dev34253

RUN dir
# RUN powershell -command Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/download/v2.8.2.windows.1/PortableGit-2.8.2-32-bit.7z.exe -OutFile portablegit.exe
ADD yenvmake.sh yenvmake.sh
# RUN "c:\program files\git\bin\sh.exe" --help
RUN ]"c:\program files\git\bin\sh.exe" yenvmake.sh

CMD ["pwd"]
