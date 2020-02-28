FROM mcr.microsoft.com/windows/servercore:ltsc2019
MAINTAINER dev34253

ADD yenvmake.sh yenvmake.sh

WORKDIR c:/windows/temp

# RUN powershell -command sleep 5; Invoke-WebRequest -UserAgent 'DockerCI' -outfile 7zsetup.exe http://www.7-zip.org/a/7z1514-x64.exe
# RUN powershell -command sleep 5; Invoke-WebRequest -Uri https://github.com/git-for-windows/git/releases/download/v2.8.2.windows.1/PortableGit-2.8.2-32-bit.7z.exe -OutFile portablegit.exe
RUN powershell -command sleep 5; Invoke-WebRequest -UserAgent 'DockerCI' -outfile gitsetup.exe https://github.com/git-for-windows/git/releases/download/v%GIT_VERSION%.windows.1/Git-%GIT_VERSION%-64-bit.exe
RUN powershell -command start-process .\gitsetup.exe -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS /DIR=c:\git' -Wait
RUN "c:\program files\git\bin\sh.exe" yenvmake.sh
# RUN "c:\program files\git\bin\sh.exe" yenvmake.sh

CMD ["pwd"]
