#!/bin/bash

RELATE_UTSRELEASE="include/generated/utsrelease.h"
UTSRELEASE=$1/$RELATE_UTSRELEASE

if [ ! -e $UTSRELEASE ]; then
    echo "error! $UTSRELEASE not exist"
    exit 1
fi

str_len=${#2}
padding=""

for (( i=0; i<=$str_len; i++ ))
do
    padding="X"$padding
done

line=`wc -l $UTSRELEASE | awk -F ' ' '{print $1}'`

cp $UTSRELEASE $UTSRELEASE.bak
cat $UTSRELEASE.bak | awk -v pad=$padding -v line=$line -F '"' \
    '{if(NR==line){printf("%s \"%s%s\"", $1, pad, $2)}else{print $0}}' > $UTSRELEASE
