if [ $# -ne 4 ] && [ $# -ne 5 ]; then
    echo "Usage: <FRAME_SRC_DIR> <SOURCE_DIR> <CROSS-COMPILE-PREFIX> <SET_ENV> <MAGIC_NUM>"
    echo "type: arm32 arm64"
    exit 1
fi

set_build_env=$(readlink -f $4)
if [ -f $set_build_env ];then
  echo $set_build_env
  source $set_build_env
fi

if [ $# -eq 4 ]; then
  cd $1
  make arm64 KDIR=$2 CROSS_COMPILE=$3
  exit 0
fi

if [ $# -eq 5 ]; then
  cd $1
  make arm64 KDIR=$2 CROSS_COMPILE=$3 vermagic=$5
  exit 0
fi
