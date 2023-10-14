# Multipass
Let's see if we can spin multipass VMs and get fuzzing on them

## Generate ssh keys in PEM format (old OpenSSH format)
```ssh-keygen -t rsa -m PEM -f multipass-ssh-key```
Import the private part into Codesys (Tools -> Options -> Runtime Deploy tools)

## Create instance
- Create instance using cloud-init configuration
```multipass launch 20.04 --name ff-instance-1 --cpus 1 --disk 8G --memory 2G --cloud-init multipass-ff-cloudinit.yaml```
- Reboot instance to disable ASLR
```multipass restart ff-instance-1```
- Open Shell to instance:
```multipass shell ff-instance-1```
- Kill codesys
```
sudo pkill -f "codesyscontrol.bin"
ps aux | grep codesys
sudo kill -9 codesys_PID
```
- Work with screens:
```
screen -S codesys
sudo ./codesys_start_wrapper.sh
[Ctrl+A, d]

[Edit fuzzer script appropriately]: nano pycodesys_old/cmp_fuzzer/fuzz_cmp.py: 295
screen -S fuzzer
./start_pycodesys.sh
[Ctrl+A, d]

screen -S ghost
sudo su
source /home/ubuntu/ghost_venv/bin/activate
cd /home/ubuntu/ghost_multipass/
python3 frida-ghost.py
[Ctrl+A, d]

exit
```

## SSHing into the instance with the fieldfuzz user
```
ssh fieldfuzz@INSTANCE_IP_ADDRESS -i multipass-ssh-key
bash
exit
```

## Notes
### No Application error in pycodesys
Make sure you've copied PlcLogic directory, and SysFile.cfg to /etc/. Then cd to etc and start codesys from there with ```sudo /opt/codesys/bin/codesyscontrol.bin --debug```

### Codesys Gateway
Unlike the VMware VM, the multipass instances don't have Codesys Gateway installed. The IDE hasn't bugged me to install the gateway, but we can deploy it if needed using the same way as codesyscontrol. The deb file is in a codesys folder in the Windows user directory.

### Offset
Having disabled ASLR, and inspecting memory at x/16xb 0x55555DA46E00 with gdb, it seems that the runtime is loaded exactly as in the unpacked IDA database, which means that the memory offset is zero 0. Hence we can just ADD 0x154000 to all the addresses already in the config (which was hardcoded/created for the VMWare VM), and ghost should work properly.

## Manual stuff
The below stuff is to do some things manually. These are NOT needed since they're now automatically done using cloud-init. They're just here for reference purposes.

### Install Codemeter antitampering mechanism
- Source: https://wiki.tuflow.com/index.php?title=Installing_Wibu_CodeMeter_Linux
```
scp -i multipass-ssh-key codemeter_7.51.5429.500_amd64.deb fieldfuzz@172.25.90.190:/home/fieldfuzz
sudo apt update
sudo apt install ./codemeter_7.51.5429.500_amd64.deb
sudo apt --fix-broken install
```

### Disable ASLR
```
sudo su
echo "kernel.randomize_va_space = 0" > /etc/sysctl.d/01-disable-aslr.conf
exit
sudo reboot
```