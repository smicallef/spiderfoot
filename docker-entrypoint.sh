#!/bin/sh

export TOP_PID=$$
trap 'exit 1' TERM
exit_script(){
        kill -s TERM $TOP_PID
}
if [ $# -gt 0 ];then 
    while getopts "A:" OPT;do
            case $OPT in
                    A)
                            Auth=$OPTARG
                            ;;
                    \?)
                            :|exit_script
                            ;;
            esac
    done
    echo "$Auth"|grep -q ":"
    if [ $? -eq 0 ];then
            echo "$Auth" >> passwd
    else
            echo "Your input should be in the format of 'username:password'"
            :|exit_script
    fi
    /usr/bin/python sf.py 0.0.0.0:5001
else
    echo "spiderfoot is running without authentication"
    /usr/bin/python sf.py 0.0.0.0:5001
fi