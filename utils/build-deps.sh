export YACREPO=$(pwd)/..
CURRENDIR=$(pwd)

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

cd $(CURRENDIR)
date