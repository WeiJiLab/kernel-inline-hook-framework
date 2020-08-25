#!/bin/bash

RELATE_UTSRELEASE="include/generated/utsrelease.h"
UTSRELEASE=$1/$RELATE_UTSRELEASE

if [ ! -e $UTSRELEASE ]; then
    echo "error! $UTSRELEASE not exist"
    exit 1
fi

if [ ! -e $3.ko ]; then
    echo "$3.ko not found!"
    exit 1
fi

bbe -b "/vermagic=/:/\x00/" -e "r 0 vermagic=$2\0" $3.ko > $3.ko.bak
mv $3.ko.bak $3.ko
mv $UTSRELEASE.bak $UTSRELEASE
echo "modified $3 vermagic to:$2"