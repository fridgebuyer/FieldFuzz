#!/bin/bash
while true
do
echo 'wrapper: start'
cd /etc
sudo /opt/codesys/bin/codesyscontrol.bin --debug
# sudo /opt/codesys/bin/codesyscontrol.bin --debug -d /opt/codesys/bin/CODESYSControl.cfg
# /opt/codesys/bin/codesyscontrol.bin /etc/CODESYSControl.cfg
# sudo /opt/codesys/bin/codesyscontrol.bin -d /opt/codesys/bin/CODESYSControl.cfg
echo 'wrapper: restarting'
sudo echo "restarted "$(date +%s) >> wrapper.log
sleep 0.2
done