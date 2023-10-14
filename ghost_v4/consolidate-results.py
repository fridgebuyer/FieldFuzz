import json
import pwn
import os
import re
import config

# Configuration parameters
INSTANCES = 11


# Calculate coverage
def calculate_coverage(components):
    # Calculate per-component coverage
    for component in components:
        # Initialize component['coverage']
        component['coverage'] = 0
        for memory_space in component['memory_spaces']:
            component['coverage'] += len(memory_space['covered_instructions']) / len(
                memory_space['instruction_indices'])
        component['coverage'] = component['coverage'] / len(component['memory_spaces'])
        print(f"[*] {component['name']} coverage: {component['coverage'] * 100}%")


# Writes coverage to file
def save_coverage(components):
    # Dump the config component object
    # Convert sets into lists before writing so they can be JSON serialized
    for component in components:
        for memory_space in component['memory_spaces']:
            memory_space['covered_instructions'] = list(memory_space['covered_instructions'])

    with open("config.components_consolidated.json", "w") as write_file:
        json.dump(components, write_file)


# Initialize Components data structures
# def init_components(components):
#     for component in components:

#         # Iterate through memory spaces
#         for memory_space in component['memory_spaces']:

#             # Load hex data of each memory space
#             with open(memory_space['input_file']) as f:
#                 memory_space_data = f.readlines()[0]

#             # Disassemble memory space
#             asm_ins = pwn.disasm(pwn.unhex(memory_space_data))

#             # Get instruction offsets of disassembled memory space
#             for line in asm_ins.splitlines():
#                 offset_hex_str = re.search(r"([0-9a-f]+):", line).groups()[0]
#                 memory_space['instruction_indices'].append(hex(int(offset_hex_str, 16)))


def main():
    # Make a copy of components
    # local_components = config.components.copy()

    # Initialize local components with hex data
    # init_components(local_components)

    with open(f'config.components_1.json', "r") as read_file:
        local_components = json.load(read_file)

    for component in local_components:
            for memory_space in component['memory_spaces']:
                memory_space['covered_instructions'] = set(memory_space['covered_instructions'])

    # Iterate over instances
    for instance in range(2, INSTANCES + 1):
        # Load instance coverage data
        if os.path.exists(f'config.components_{instance}.json'):
            with open(f'config.components_{instance}.json', "r") as read_file:
                temp_components = json.load(read_file)
            # Iterate over components in parallel
            for local_component, temp_component in zip(local_components, temp_components):
                # Iterate over memory spaces in parallel
                for local_memory_space, temp_memory_space in zip(local_component['memory_spaces'],
                                                                 temp_component['memory_spaces']):
                    # print(f"Adding instructions to {local_component['name']}:{len(local_memory_space['covered_instructions'])}" + 
                    # f"from {temp_component['name']}:{len(temp_memory_space['covered_instructions'])}")
                    for item in temp_memory_space['covered_instructions']:
                        local_memory_space['covered_instructions'].add(item)
        else:
            print(f'File does not exist: config.components_{instance}.json')

    # Calculate coverage
    calculate_coverage(local_components)

    # Save coverage
    save_coverage(local_components)


if __name__ == '__main__':
    main()