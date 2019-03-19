#!/bin/bash
#Author: Mark Hunt (mark.hunt@us.ibm.com)
#Set IP address for phantom lab
#setip.sh

#find server IP
while read line
do
 hostip=$( echo $line | cut -d "'" -f 2 )
 echo $hostip > consoleip.txt
done <<< "`/opt/qradar/bin/myver -v | grep "IP address"`"