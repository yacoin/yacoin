export YACREPO=$(pwd)/..
CURRENTDIR=$(pwd)

#
# setup environment
#
source ./scripts/yprofile
source $YDIR/scripts/instgcc 
source $YDIR/scripts/instcdb

#
# build yacoin qt
#
cd $YACREPO

qmake "USE_IPV6=0" "USE_QRCODE=1" "USE_UPNP=1" "YBOO=$YBOO" "YOSSL=$YOSSL" "YBDB=$YBDB" "YUPNP=$YUPNP" "YQR=$YQR" yacoin-qt-tdm32.pro
make

cd CURRENTDIR
date
