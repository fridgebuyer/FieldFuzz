#!/bin/sh
while true
do
echo 'wrapper: start'
sudo /opt/codesys/bin/codesyscontrol.bin -d /opt/codesys/bin/CODESYSControl.cfg
echo 'wrapper: restarting'
sudo echo "restarted "$(date +%s) >> wrapper.log
sleep 0.2
done
