#!/bin/bash
Auth = ${Auth:-""}
while getopts "pass" OPT; do
    case $OPT in
        pass)
            Auth=$OPTARG;;
    esac
done
if [Auth != "" ];then
    touch passwd
    echo $Auth >> passwd
fi
/usr/bin/python sf.py 0.0.0.0:5001