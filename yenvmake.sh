mkdir /ydir
cd /ydir
curl -L -k https://github.com/senadj/scripts/archive/tdm32.zip > scripts.zip
unzip -j -o -d scripts scripts.zip
cp scripts/yprofile ~/.bash_profile
source ~/.bash_profile
cp D:/ydownloads/* $YDL/
unzip -o 7za920.zip 7za.exe
mv 7za.exe /bin/
source $YDIR/scripts/instgcc
source $YDIR/scripts/instcdb
buildzlib
buildopenssl
buildboost
buildlibpng
buildqrencode
buildminiupnpc
buildjansson
buildpcre
buildcurl
buildberkeleydb
buildleveldb
buildqt
buildwxwidgets
buildwxfolder
mkdir -p $YDIR/yacoin
