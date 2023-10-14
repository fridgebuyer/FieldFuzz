#!/bin/bash
source "/home/ubuntu/pycodesys_venv/bin/activate"
cd /home/ubuntu/pycodesys_old/cmp_fuzzer/
while true
do
echo 'wrapper: pycodesys start'
python2.7 fuzz_cmp.py 0.0.0.0 &
sleep 600
echo 'wrapper: pycodesys restarting'
sudo echo "restarted "$(date +%s) >> fuzzer_start_stop.log
pkill -f "python2.7"
sleep 5
done
