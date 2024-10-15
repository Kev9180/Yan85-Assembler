#      Author: Kevin Johnston
# Description: This is a simple assembler for Yan85, the customer architecture used in several pwn.college challenges.
#              Given custom-written Yan85 shellcode, this assembler can reorder the instructions, break them down into
#              their equivalent bytecode values, and send that bytecode into the challenge.

# ****** DISCLAIMER ******
# To pwn.college students: Be aware that pwn.college staff monitors all code that is used on their infrastructure.
# Usage of this code *will* result in an academic integrity violation. A major hurdle of reverse engineering Yan85
# is making your own assembler/disassembler/emulator; it's part of the fun. Good luck!

from pwn import *

context.arch = 'amd64'

# ****** MEMORY ******
# Memory starts at 765 and ends at 1023
# When trying to store a value in memory, use IMM to add the offset from 765 and then use STM to store it
# Ex: IMM A 0    - store the immediate value 0 in register A
#     IMM B 0x2f - store the immediate value 0x2f ('/') in register B
#     STM A B    - *(reg A) = reg B

# ****** REGISTER MEMORY LOCATIONS ******
# A = 1024
# B = 1025
# C = 1026
# D = 1027
# S = 1028
# I = 1029
# F = 1030

# ****** DICTIONARIES ******
# The following dictionaries contain the key-value pairs for the opcodes, registers, and syscalls used by Yan85 
# Each value in the following dictionary key-value pairs (other than INSTRUCTION_ORDERS) will need to be updated with each level
# These values will need to be determined by looking at the disassembled code in the interpret_instruction, interpret_sys, and register functions

# ****** OPCODES ******
opcodes_map = {
    "IMM": 0x1,     # Assign value to register: IMM <register> <integer>
    "ADD": 0x10,    # Add two registers: ADD <reg1> <reg2>
    "STK": 0x8,     # Push: STK 0 <register>    Pop: STK <register> 0
    "STM": 0x2,     # Set memory: STM <reg1> <reg2> (*arg1 = arg2)
    "LDM": 0x80,    # Load from memory: LDM <reg1> <reg2> (arg1 = *arg2)
    "CMP": 0x4,     # Compare: CMP <reg1> <reg2>
    "JMP": 0x20,    # Conditional: JMP <bool_byte> <instruction #>      Unconditional: JMP 0 <instruction #>
    "SYS": 0x40,    # SYS <syscall> <ret_register>
}

# ****** REGISTERS ******
register_map = {
    "A": 0x20,      # General-purpose 1
    "B": 0x4,       # General-purpose 2
    "C": 0x8,       # General-purpose 3
    "D": 0x40,      # General-purpose 4
    "S": 0x1,       # Stack pointer
    "I": 0x10,      # Instruction pointer
    "F": 0x2,       # Flags register
}

# ****** SYSCALLS ******
syscalls = {
    "OPEN": 0x10,           # SYS OPEN <REG> - calls open(filename, flags, mode). Returns fd into provided register
    "READ_CODE": 0x8,       # SYS READ_CODE <REG> - calls read(fd, buffer, num bytes). Reads from memory location 0 to 764. Returns num bytes read into provided register
    "READ_MEMORY": 0x20,    # SYS READ_MEMORY <REG> - calls read(fd, buffer, num bytes). Reads from memory location 765 to 1023. Returns num bytes read into provided register
    "WRITE": 0x2,           # SYS WRITE <REG> - calls write(fd, buffer_offset, num_bytes). Returns num bytes written into provided register
    "SLEEP": 0x1,           # SYS SLEEP <REG> - calls the sleep function. Returns time slept into provided register
    "EXIT": 0x4,            # SYS EXIT <REG> - calls exit
}

# Dictionary to hold the different combinations of instruction orders
INSTRUCTION_ORDERS = {
    "a1_a2_op": "arg1 arg2 opcode",
    "a1_op_a2": "arg1 opcode arg2",
    "a2_op_a1": "arg2 opcode arg1",
    "a2_a1_op": "arg2 arg1 opcode",
    "op_a1_a2": "opcode arg1 arg2",
    "op_a2_a1": "opcode arg2 arg1"
}

INSTRUCTION_ORDER = INSTRUCTION_ORDERS["op_a2_a1"]      # Define the instruction order to use for the current challenge

def assemble_instruction(instruction, order=INSTRUCTION_ORDER):
    """
    Assembles a single Yan85 instruction into bytecode.
    :param instruction: The original instruction string (e.g., 'IMM A 5').
    :param order: The current instruction order.
    :return: 3-byte bytecode for the instruction.
    """

    parts = instruction.strip().split()

    # Error handling: each instruction can only be 3 "bytes"
    if len(parts) != 3:
        raise ValueError(f"Invalid instruction format: {instruction}")

    # Step 1: Map parts based on the current order
    order_components = order.split()
    opcode_str = parts[order_components.index("opcode")]
    arg1_str = parts[order_components.index("arg1")]
    arg2_str = parts[order_components.index("arg2")]

    # Step 2: Convert each part to its bytecode representation
    # Convert opcode
    opcode_byte = opcodes_map.get(opcode_str)
    if opcode_byte is None:
        raise ValueError(f"Unknown opcode: {opcode_str}")

    # Convert arg1
    if arg1_str in register_map:
        arg1_byte = register_map[arg1_str]
    elif arg1_str in syscalls:
        arg1_value = syscalls[arg1_str]
        arg1_byte = arg1_value & 0xFF  # Extract the lower 8 bits
    else:
        try:
            arg1_byte = int(arg1_str, 0)  # Handle immediate values
        except ValueError:
            raise ValueError(f"Invalid arg1 value: {arg1_str}")

    # Convert arg2
    if arg2_str in register_map:
        arg2_byte = register_map[arg2_str]
    elif arg2_str in syscalls:
        arg2_value = syscalls[arg2_str]
        arg2_byte = arg2_value & 0xFF  # Extract the lower 8 bits
    else:
        try:
            arg2_byte = int(arg2_str, 0)
        except ValueError:
            raise ValueError(f"Invalid arg2 value: {arg2_str}")

    # Ensure all bytes are within the 0-255 range
    if not (0 <= opcode_byte <= 255):
        raise ValueError(f"Opcode byte out of range: {opcode_byte}")
    if not (0 <= arg1_byte <= 255):
        raise ValueError(f"Arg1 byte out of range: {arg1_byte}")
    if not (0 <= arg2_byte <= 255):
        raise ValueError(f"Arg2 byte out of range: {arg2_byte}")

    # Step 3: Construct the final 3-byte instruction
    instruction_bytecode = bytes([opcode_byte, arg1_byte, arg2_byte])
    
    return instruction_bytecode


def assemble_instruction(instruction, order=INSTRUCTION_ORDER):
    """
    Assembles a single Yan85 instruction into bytecode.
    :param instruction: The original instruction string (e.g., 'IMM A 5').
    :param order: The current instruction order.
    :return: 3-byte bytecode for the instruction.
    """
    parts = instruction.strip().split()

    if len(parts) != 3:
        raise ValueError(f"Invalid instruction format: {instruction}")

    # Step 1: Create a map from the provided order
    order_components = order.split()
    
    # Prepare a list to store the reordered instruction parts in bytecode order
    bytecode_parts = []

    # Step 2: Convert each part to its bytecode representation based on the order
    for component_type in order_components:
        component_str = parts[order_components.index(component_type)]

        if component_type == "opcode":
            opcode_byte = opcodes_map.get(component_str)
            if opcode_byte is None:
                raise ValueError(f"Unknown opcode: {component_str}")
            bytecode_parts.append(opcode_byte)
        elif component_type == "arg1" or component_type == "arg2":
            bytecode_parts.append(convert_to_bytecode(component_str, component_type))

    # Ensure that all bytecode parts are present
    if len(bytecode_parts) != 3:
        raise ValueError("Assembled instruction does not have exactly 3 bytecode parts.")

    # Ensure all bytes are within the 0-255 range
    for byte in bytecode_parts:
        if not (0 <= byte <= 255):
            raise ValueError(f"Byte out of range: {byte}")

    # Step 3: Construct the final 3-byte instruction
    instruction_bytecode = bytes(bytecode_parts)
    
    return instruction_bytecode


def convert_to_bytecode(component, component_type):
    """
    Helper function to convert an instruction component to its bytecode.
    :param component: The instruction component (e.g., 'A', '0x10', 'OPEN').
    :param component_type: The type of the component (e.g., 'arg1', 'arg2').
    :return: Bytecode for the component.
    """
    if component in register_map:
        return register_map[component]
    elif component in syscalls:
        value = syscalls[component]
        return value & 0xFF
    else:
        try:
            return int(component, 0)  # Convert immediate values
        except ValueError:
            raise ValueError(f"Invalid {component_type} value: {component}")


def reorder_instruction(instruction, order=INSTRUCTION_ORDER):
    """
    Reorders the instructions based on the specified order.
    :param instruction: The original instruction in string format.
    :param order: The desired order for the instruction components.
    :return: Reordered instruction string.
     Steps:
    1. Splits the instruction into its parts (opcode, arg1, arg2).
    2. Maps the original parts to the new order specified.
    3. Constructs a new instruction string based on the new order.
    """

    parts = instruction.strip().split()
    if len(parts) != 3:
        raise ValueError(f"Invalid instruction format: {instruction}")

    # Define a map from the original order
    original_map = {
        "opcode": parts[0],
        "arg1": parts[1],
        "arg2": parts[2]
    }

    # Split the order string into its components
    order_components = order.split()

    # Create a new instruction based on the desired order
    reordered_instruction = " ".join(original_map[component] for component in order_components)

    return reordered_instruction


def adjust_yancode_order(yancode, order=INSTRUCTION_ORDER):
    """
    Adjusts the order of all instructions in the yancode based on the specified order.
    :param yancode: The original yancode string with multiple lines.
    :param order: The desired order for the instruction components.
    :return: The adjusted yancode string.
        Steps:
    1. Splits the yancode into lines and removes comments.
    2. Reorders each instruction using the reorder_instruction function.
    3. Combines the reordered instructions into a new yancode string.
    """

    adjusted_lines = []

    for line in yancode.splitlines():
        line = line.split("#")[0].strip()  # Remove comments
        if not line:
            continue  # Skip empty lines

        adjusted_line = reorder_instruction(line, order)
        adjusted_lines.append(adjusted_line)

    return "\n".join(adjusted_lines)

# ****** YAN85 SHELLCODE ******
# This is where you write your custom yancode
yancode = '''
IMM A 0
IMM B 0x2F
STM A B
etc...
'''

adjusted_yancode = adjust_yancode_order(yancode)        # Adjust the ordering of the yancode, if need be
print(f"Adjusted Yancode: {adjusted_yancode}")          # Print the adjusted yancode for verification

assembled_code = assemble_yancode(adjusted_yancode)     # Assemble the yancode into its corresponding bytecode
print(assembled_code)                                   # Print the assembled yancode for verification

# context.terminal = ['tmux', 'splitw', '-h']
# p = gdb.debug('/path/to/challenge', '''
# b interpret_instruction
# continue
# x/gx $rdi
# ''')

p = process('/path/to/challenge')
p.sendline(assembled_code)
p.interactive()
