FROM microsoft/windowsservercore
MAINTAINER dev34253

RUN dir
RUN Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/download/v2.8.2.windows.1/PortableGit-2.8.2-32-bit.7z.exe -OutFile portablegit.exe
ADD yenvmake.sh yenvmake.sh
RUN portablegit.exe yenvmake.sh

CMD ["pwd"]
