export YACREPO=$(pwd)/..

source ./scripts/yprofile

case $YOS in 
  mingw*) source $YDIR/scripts/getdev; source $YDIR/scripts/instgcc; source $YDIR/scripts/instcdb ;;
esac

#
# build dependencies
#
cd $YDIR
buildzlib
cd $YDIR
buildlibpng
cd $YDIR
buildqrencode
cd $YDIR
buildopenssl
cd $YDIR
buildboost
cd $YDIR
buildminiupnpc
cd $YDIR
buildberkeleydb
cd $YDIR
buildqt

#
# build yacoin
#
cd $YACREPO

case $YOS in
  linux*) export QTPRO=yacoin-qt-linux.pro;;
  mingw*) export QTPRO=yacoin-qt-tdm32.pro;;
esac

qmake "USE_IPV6=0" "USE_QRCODE=1" "USE_UPNP=1" "YBOO=$YBOO" "YOSSL=$YOSSL" "YBDB=$YBDB" "YUPNP=$YUPNP" "YQR=$YQR" $QTPRO
make

date
