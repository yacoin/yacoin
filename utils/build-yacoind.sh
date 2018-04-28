export YACREPO=$(pwd)/..
CURRENTDIR=$(pwd)

source ./scripts/yprofile
source $YDIR/scripts/instgcc
source $YDIR/scripts/instcdb

cd $YACREPO/src

make -f makefile.mingw

cd $CURRENTDIR
date
