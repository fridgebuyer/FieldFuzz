'''
Written for FieldFuzz
Author: CedArctic
Inspired by fridacov (https://github.com/DavidCatalan/fridacov).
'''
#!/usr/bin/env python
from __future__ import print_function
from operator import truediv

import os
import signal
import sys
import struct
import subprocess
import re
import time
import json
import frida
import pwn

import config

# Global set for basic blocks. We're using sets to sort out duplicate entries
bbs = set()

# Set for component information retrieved by using Interceptor on the setup calls to ServerRegisterServiceHandler
components_info = []

# Address spaces of all subcomponents
address_spaces = []

# Get process id by process name
def get_pid(name):
    try:
        pid = subprocess.check_output(["pidof", name])
        return int(pid[:-1])
    except:
        return -1

# Filtering function. Checks if the given address offset is in the 
# range of addresses that we're interested in getting coverage for
def address_filter(offset):
    for address in address_spaces:
        if offset >= (address[0] - config.cod_base_addr) and offset <= (address[1]-config.cod_base_addr):
            return True
    return False


# Process component info as received from FRIDA. This info is for logging purposes mostly.
def proc_cmp(component_info):
    print(component_info)
    components_info.append(component_info)


# Process basic blocks
def populate_bbs(data):
    global bbs

    # Entry size in bytes
    block_size = 8

    # Traverse received ArrayBuffer entries
    for i in range(0, len(data), block_size):
        # Get entry
        entry = data[i:i+block_size]
        # Unpack the offset of the basic block from the start of its module (codesyscontrol.bin). 4 Bytes
        offset = struct.unpack('I',entry[:4])[0]
        # Filter basic block based on its offset
        if len(config.subcomponents) != 0 and address_filter(offset) == False:
            continue
        # Unpack basic block size (2 bytes)
        size = struct.unpack('H',entry[4:-2])[0]
        # Module ID. Hardcoded to 0 since we only examine codesyscontrol.bin
        # mod_id = struct.unpack('H',entry[6:])[0]
        mod_id = 0
        # Format the dynamorio line and add it to the set
        # buff = 'module[ '+str(mod_id)+']: '+str(hex(offset))+', '+str(size)+'\n'
        bbs.add((mod_id, hex(offset), size))


# Writes coverage to file
def save_coverage():
    
    # Write body (basic blocks)
    body = b'BB Table: %d bbs\n' % len(bbs) + (''.join(['module[ '+str(mod_id)+']: '+str(offset)+', '+str(size)+'\n' for (mod_id, offset, size) in bbs])).encode('utf-8')
    with open(config.outfile, 'wb') as h:
        h.write(body)

    # Write components info
    with open(config.cmp_outfile, 'w') as i:
        for component_info in components_info:
            i.write(str(component_info))
            i.write("\n")

    # Dump the config subcomponents object
    # Convert sets into lists before writing so they can be JSON serialized
    for subcomponent in config.subcomponents:
        for memory_space in subcomponent['memory_spaces']:
            memory_space['covered_instructions'] = list(memory_space['covered_instructions'])
            
    with open("config.subcomponents.json", "w") as write_file:
        json.dump(config.subcomponents, write_file)

    # Dump the config components object
    with open("config.components.json", "w") as write_file:
        json.dump(config.component_handlers, write_file)



# Calculate coverage
def calculate_coverage():
    
    # Iterate over basic blocks
    for (_, offset, size) in bbs:
        # Basic block start and end addresses
        bb_start_address = config.cod_base_addr + int(offset, 16)
        bb_end_address = bb_start_address + size

        # Iterate over subcomponents and their memory addresses to find where
        # the basic block belongs
        for subcomponent in config.subcomponents:
            for memory_space in subcomponent['memory_spaces']:
                # Skip memory space if basic block doesn't belong in its address range
                if not (bb_start_address >= memory_space['address_range'][0] and bb_end_address <= memory_space['address_range'][1]):
                    continue
                
                # Iterate over instruction offsets in the memory space
                for ins_offset in memory_space['instruction_indices']:
                    ins_address = memory_space['address_range'][0] + int(ins_offset, 16)
                    if ins_address >= bb_start_address and ins_address <= bb_end_address:
                        memory_space['covered_instructions'].add(ins_offset)

    # Calculate per-subcomponent, and component coverage
    for subcomponent in config.subcomponents:
        # Initialize component['coverage'], and related counter variables
        subcomponent['coverage'] = 0
        subcomponent_covered_instructions = 0
        subcomponent_total_instructions = 0
        # Count total number of instructions, and covered instructions in all subcomponent memory spaces
        for memory_space in subcomponent['memory_spaces']:
            # Count instructions on the subcomponent level
            subcomponent_covered_instructions += len(memory_space['covered_instructions'])
            subcomponent_total_instructions += len(memory_space['instruction_indices'])
            # Count instructions on the component level
            config.component_handlers[subcomponent['component_id']]['covered_instructions'] += len(memory_space['covered_instructions'])
            config.component_handlers[subcomponent['component_id']]['total_instructions'] += len(memory_space['instruction_indices'])
        print(f"[D] {subcomponent['name']}. Covered: {subcomponent_covered_instructions}. Total: {subcomponent_total_instructions}")
        # Calculate subcomponent coverage
        if subcomponent_total_instructions != 0:
            subcomponent['coverage'] = subcomponent_covered_instructions / subcomponent_total_instructions
        print(f"[*] {subcomponent['name']} coverage: {subcomponent['coverage'] * 100}%")

    # Calculate component coverage
    for component_id in config.component_handlers.keys():
        if config.component_handlers[component_id]['total_instructions'] != 0:
            config.component_handlers[component_id]['coverage'] = config.component_handlers[component_id]['covered_instructions'] / config.component_handlers[component_id]['total_instructions']
        print(f"[*] {config.component_handlers[component_id]['name']} coverage: {config.component_handlers[component_id]['coverage'] * 100}%")
    


# Run when sigint signal comes in. Calls save_coverage() and calculate_coverage()
def sigint(signo, frame):
    print('[!] SIGINT, calculating Coverage based on address ranges')
    calculate_coverage()
    print('[!] SIGINT, saving %d blocks to \'%s\' and components to \'%s\'' % (len(bbs), config.outfile, config.cmp_outfile))
    save_coverage()
    print('[!] Done')
    os._exit(1)


# Callback called when a message comes from FRIDA
def on_message(message, data):
    # print("======================== GOT MESSAGE ========================")
    if 'bbs' in message['payload']:
        populate_bbs(data)
    elif 'cmp' in message['payload']:
        proc_cmp(message['payload'])


# Entry point
def main():

    # Setup interrupt signal
    signal.signal(signal.SIGINT, sigint)

    # Setup pwntools arch
    pwn.context.arch = 'amd64'


    # If previous runs file exists, load config.subcomponents from there
    if os.path.exists('config.subcomponents.json'):
        with open("config.subcomponents.json", "r") as read_file:
            config.subcomponents = json.load(read_file)
        for component in config.subcomponents:
            for memory_space in component['memory_spaces']:
                memory_space['covered_instructions'] = set(memory_space['covered_instructions'])
    else:
        # Initialize Subcomponents data structures
        for subcomponent in config.subcomponents:

            # Iterate through memory spaces
            for memory_space in subcomponent['memory_spaces']:
                # Load address spaces of subcomponent into address_spaces
                address_spaces.append(memory_space['address_range'])

                # Load hex data of each memory space
                with open(memory_space['input_file']) as f:
                    memory_space_data = f.readlines()[0]

                # Disassemble memory space
                asm_ins = pwn.disasm(pwn.unhex(memory_space_data))

                # Get instruction offsets of disassembled memory space
                for line in asm_ins.splitlines():
                    offset_hex_str = re.search(r"([0-9a-f]+):", line).groups()[0]
                    memory_space['instruction_indices'].append(hex(int(offset_hex_str, 16)))

    # time.sleep(5)
    # print(config.subcomponents)
    # input("Printed loaded config. Go on?")

    # Print debug
    # print(config.subcomponents)
    # print(address_spaces)

    # Load JS scripts
    f_ghost_get_cmp = open("ghost_get_cmp.js", "r")
    ghost_get_cmp_js = f_ghost_get_cmp.read()
    f_ghost_get_cmp.close()

    f_ghost_stalk_cmp = open("ghost_stalk_cmp.js", "r")
    ghost_stalk_cmp_js = f_ghost_stalk_cmp.read()
    f_ghost_stalk_cmp.close()

    # Configure the loaded scripts with addresses from the config file
    ghost_get_cmp_js = ghost_get_cmp_js % config.serv_handler_addr

    # Main loop. Restart the runtime every 2 hours to work around the trial limitation
    while True:

        # Launch Codesys
        print("[*] WARNING!! : Attaching to pre-existing CODESYS, *NOT* launching a new instance")
        # print("==== Starting Codesys ==== \n\n")
        # codesys_process = subprocess.Popen([config.cod_bin_path, "--debug"], cwd=config.cod_cwd)
        codesys_pid = get_pid("codesyscontrol.bin")
        while codesys_pid == -1:
            print("[*] Waiting for Codesys to spawn.")
            time.sleep(10)
            codesys_pid = get_pid("codesyscontrol.bin")

        # Attach Frida to codesyscontrol.bin
        print(f"[*] Attaching FRIDA to PID {codesys_pid}")
        session = frida.attach("codesyscontrol.bin")

        # Add the ghost_get_cmp JS script to get components
        get_cmp_script = session.create_script(ghost_get_cmp_js)

        # Set Message callback for ghost_get_cmp script
        get_cmp_script.on('message', on_message)

        # Load ghost_get_cmp script
        get_cmp_script.load()

        # Wait for the calls to the service handler functions have been complete
        print("Waiting for calls to ServerRegisterServiceHandler")
        # time.sleep(config.unpack_delay)
        # time.sleep(30)

        # At this point we have captured all the calls to ServerRegisterServiceHandler
        # and we can parse them to get the addresses of the components in memory
        # These functions are the service handlers for each component
        # func_address_book = [component_info['arg_2'] for component_info in components_info]
        # VMWare VM Address Book
        # func_address_book = ['0x55555d67f440', '0x55555d6b0940', '0x55555d6b7100', '0x55555d6cfa80', '0x55555d8d4ec0', '0x55555d900f40', '0x55555d90dbc0', '0x55555d91de80', '0x55555d691b00', '0x55555d6cb7c0', '0x55555d8ee700', '0x55555d476400', '0x55555d610100', '0x55555d683840', '0x55555d77b6c0']
        # Multipass Address Book
        func_address_book = ['0x55555da855c0', '0x55555d5aef00', '0x55555d5d0900', '0x55555d5d2dc0', '0x55555d7d3440', '0x55555d804940', '0x55555d80b100', '0x55555d823a80', '0x55555da28ec0', '0x55555da54f40', '0x55555da61bc0', '0x55555da71e80', '0x55555d7e5b00', '0x55555d81f7c0', '0x55555da42700', '0x55555d5ca400', '0x55555d764100', '0x55555d7d7840', '0x55555d8cf6c0']

        
        print("Address book:", func_address_book)

        # Halt for user input
        # input("Continue?")

        # Configure the ghost_stalk_cmp JS script with the addresses of the components
        ghost_stalk_cmp_js = ghost_stalk_cmp_js % func_address_book

        # Add the ghost_stalk_cmp JS script
        print("[*] Creating session")
        stalk_cmp_script = session.create_script(ghost_stalk_cmp_js)

        # Set Message callback for ghost_stalk_cmp script
        stalk_cmp_script.on('message', on_message)

        # Load ghost_stalk_cmp script
        print("[*] Loading scripts")
        stalk_cmp_script.load()

        # Wait for ~2 hours (trial period)
        codesys_pid_new = get_pid("codesyscontrol.bin")
        while codesys_pid == codesys_pid_new:
            print("[*] Ghost is standing by")        
            time.sleep(120)
            codesys_pid_new = get_pid("codesyscontrol.bin")

        # When interrupt signal comes, detach FRIDA and format and save coverage data
        print('[*] Detaching, this might take a second...')
        session.detach()

        time.sleep(30)

        # Kill process
        print("==== Stopping Codesys ==== \n\n")
        # codesys_process.kill()
        # codesys_process.communicate()
        # os.kill(codesys_process.pid, signal.SIGKILL)
        # os.wait()

        # Wait for a few seconds while codesys is killed
        # time.sleep(60)

    
    # NOTE: THE stuff from this point onwards is also taken care of by the sigint function
    
    # Wait for SIGINT
    # sys.stdin.read()

    # When interrupt signal comes, detach FRIDA and format and save coverage data
    print('[*] Detaching, this might take a second...')
    session.detach()

    print('[+] Detached. Got %d basic blocks.' % len(bbs))
    print('[*] Formatting coverage and saving...')

    save_coverage()

    print('[!] Done')

    sys.exit(0)


if __name__ == '__main__':
    main()