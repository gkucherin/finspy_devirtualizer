import idaapi
from enum import Enum

imagebase = idaapi.get_imagebase() # Retrieve the executable image base
virt_segm_addr = 0x41F000 # This variable will store the address of the segment with translated instructions 

# This enum contains all instruction opcodes of our VM
class VMOpcodes(Enum):
    ZeroVirtReg = 0
    Jump = 1
    MovVirtRegToX86Reg = 2
    ExecX86Code = 3
    Jno = 4
    ShlVirtReg = 5
    Je = 6
    Jns = 7
    Jna = 8
    Jo = 9
    MovConstToVirtReg = 10
    Call = 11
    Jnb = 12
    AddConstToVirtReg = 13
    Jp = 14
    IndirectCall = 15
    Jle = 16
    AddX86RegToVirtReg = 17
    ExecX86Code_2 = 18
    DerefVirtReg = 19
    Ja = 20
    Jne = 21
    Jnp = 22
    MovX86RegToVirtReg = 23
    MovX86RegToVirtReg_2 = 24
    Jge = 25
    Js = 26
    Jb = 27
    MovX86RegToAddr = 28
    PushVirtReg = 29
    StoreConstToVirtRegAddr = 30
    Jl = 31
    Jg = 32
    MovVirtRegToAddr = 33
    
# This function rounds a number up, making it divisible by the page size
def align_to_page_size(addr):
    remainder = addr % 4096
    if remainder == 0:
        return addr
    return addr + (4096 - remainder)
    
# This function translates virtual jump instructions to x86
def craft_jump_insn(opcode, virt_insn_args):
    crafted_bytes = bytearray() # Bytearray holding the translation
    is_conditional = opcode != 0xe9
    if is_conditional:
        crafted_bytes.append(0x0f) # Conditional jumps must be preceded with 0x0F
    crafted_bytes.append(opcode) # Append opcode to translation
    offset = int.from_bytes(virt_insn_args[1:1+4], 'little', signed=True) # Extract destination relative offset from virtual instruction
    recalculated_offset = (abs(offset) // 24) * 16 # Recalculate the offset (divide it by the virtual instruction size, multiply by the size of each translated instruction)
    if offset < 0:
        recalculated_offset = -recalculated_offset
    instruction_delta = recalculated_offset - 5 - is_conditional # For x86 jumps, the instruction operand should contain the value "destination address - eip". To correctly calculate this value we have to subtract the instruction size from the offset 
    crafted_bytes += instruction_delta.to_bytes(4, 'little', signed=True) # Add the encoded jump destination operand to the instruction 
    return crafted_bytes
    
def parse_bytecode(bytecode):
    global virt_segm_addr
    virt_reg_addr = virt_segm_addr # The virtual register variable is contained in the first 4 bytes of the segment
    curr_addr = virt_segm_addr + 4 # Skip the first 4 segment bytes as they are used for the virtual register
    for i in range(0, len(bytecode), 24): # 24 is the size of each virtual instruction
        virt_insn_bytes = bytecode[i:i+24] # Extract bytes of the virtual instruction to be processed
        x86_insn_bytes = bytearray(b"\x90"*16) # This bytearray will hold the translated instruction (each translation is of size 16)
       
        insn_id = int.from_bytes(virt_insn_bytes[0:4], 'little') # Extract the instruction ID
        insn_opcode = VMOpcodes(virt_insn_bytes[4]) # Extract the instruction opcode
        insn_args_sz = virt_insn_bytes[5] # Extract the size of the operands bytearray
        reloc_offset1 = virt_insn_bytes[6] # Relocation fixup offset (see below)
        reloc_offset2 = virt_insn_bytes[7] # Another relocation fixup offset
        insn_args = bytearray(virt_insn_bytes[8:]) # Instruction operands bytearray
        
        # Apply relocations to the virtual instruction. If any of the relocation offsets is not zero, then we add imagebase to the DWORD stored at these offsets
        if reloc_offset1 != 0:
            reloc_offset1 &= 0x7f
            dword_to_fix = int.from_bytes(insn_args[reloc_offset1:reloc_offset1 + 4], 'little', signed=True)
            dword_to_fix += imagebase
            insn_args[reloc_offset1:reloc_offset1 + 4] = dword_to_fix.to_bytes(4, 'little', signed=True)
        if reloc_offset2 != 0:
            reloc_offset2 &= 0x7f
            dword_to_fix = int.from_bytes(insn_args[reloc_offset2:reloc_offset2 + 4], 'little', signed=True)
            dword_to_fix += imagebase
            insn_args[reloc_offset2:reloc_offset2 + 4] = dword_to_fix.to_bytes(4, 'little', signed=True)
        
        # Moves an x86 register to the virtual register
        if insn_opcode == VMOpcodes.MovX86RegToVirtReg or insn_opcode == VMOpcodes.MovX86RegToVirtReg_2:
            x86_insn_bytes[0] = 0x89 # Write the mov m32, r32 instruction opcode
            x86_insn_bytes[1] = 5 | ((insn_args[0] & 0x7) << 3) # Encode the register operand value
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True) # Write the virtual register address
        # Moves zero to the virtual register
        elif insn_opcode == VMOpcodes.ZeroVirtReg:
            x86_insn_bytes[0] = 0xc7
            x86_insn_bytes[1] = 0x05 # Write the mov m32, imm32 instruction opcode
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True) # Write the virtual register address
            x86_insn_bytes[6:6+4] = b'\x00\x00\x00\x00' # Write the zero dword to the translated instruction bytes
        # Adds a constant value to the virtual register
        elif insn_opcode == VMOpcodes.AddConstToVirtReg:
            x86_insn_bytes[0] = 0x81
            x86_insn_bytes[1] = 0x05 # Write the add m32, imm32 instruction opcode
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True) # Write the virtual register address
            x86_insn_bytes[6:6+4] = insn_args[0:4] # Write the constant that is to be added
        # Shifts left the bits of the virtual register  
        elif insn_opcode == VMOpcodes.ShlVirtReg:
            x86_insn_bytes[0] = 0xc1
            x86_insn_bytes[1] = 0x35 # Write the shl m32, imm8 instruction opcode
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True) # Write the virtual register address
            x86_insn_bytes[6] = insn_args[0] # Write the number of bits
        # Dereferences an address stored in the virtual register and stores the dereference value inside the virtual register
        elif insn_opcode == VMOpcodes.DerefVirtReg:
            x86_insn_bytes[0] = 0x50 # Write the "push eax" instruction
            x86_insn_bytes[1] = 0xa1 # Write the "mov eax, [virtReg]" instruction
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True)
            x86_insn_bytes[6] = 0x8b # Write the "mov eax, [eax]" instruction
            x86_insn_bytes[7] = 0x00
            x86_insn_bytes[8] = 0xa3 # Write the "mov [virtReg], eax" instruction
            x86_insn_bytes[9:9+4] = virt_reg_addr.to_bytes(4, 'little', signed=True)
            x86_insn_bytes[13] = 0x58 # Write the "pop eax" instruction
        # Adds an x86 register to a virtual register
        elif insn_opcode == VMOpcodes.AddX86RegToVirtReg:
            x86_insn_bytes[0] = 0x01 # Write the add m32, r32 instruction opcode
            x86_insn_bytes[1] = 5 | ((insn_args[0] & 0x7) << 3) # Encode the register operand
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True) # Write the virtual register address
        # Pushes the vitual register value on the stack
        elif insn_opcode == VMOpcodes.PushVirtReg:
            x86_insn_bytes[0] = 0xff # Write the 2-byte opcode of the push m32 instruction
            x86_insn_bytes[1] = 0x35
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True)  # Write the virtual register address
        # Moves a value to an address stored in the virtual register
        elif insn_opcode == VMOpcodes.StoreConstToVirtRegAddr:
            x86_insn_bytes[0] = 0x50 # Write the "push eax" instruction
            x86_insn_bytes[1] = 0xa1 # Write the "mov eax, [virtReg]" instruction
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True)
            x86_insn_bytes[6] = 0xc7 # Write the "mov [eax], imm32" instruction
            x86_insn_bytes[7] = 0x00
            x86_insn_bytes[8:8+4] = insn_args[0:4]
            x86_insn_bytes[12] = 0x58 # Write the "pop eax" instruction
        # Performs an indirect call    
        elif insn_opcode == VMOpcodes.IndirectCall:
            x86_insn_bytes[:insn_args_sz] = insn_args[4:4+insn_args_sz] # Move the bytes stored in the virtual instruction operands
            x86_insn_bytes[1] = (x86_insn_bytes[1] & ~0x38) | 0x10 # Adjust the value of the register used in the indirect call
        # Writes the value of the virtual register to a specified address
        elif insn_opcode == VMOpcodes.MovVirtRegToAddr:
            x86_insn_bytes[0] = 0x50 # Write the "push eax" instruction
            x86_insn_bytes[1] = 0xa1 # Write the "mov eax, [virtReg]" instruction
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True)
            x86_insn_bytes[6] = 0xa3 # Write the "mov m32, r32" instruction
            x86_insn_bytes[7:7+4] = insn_args[0:4]
            x86_insn_bytes[11] = 0x58 # Write the "pop eax" instruction
        # Writes a constant to the virtual register
        elif insn_opcode == VMOpcodes.MovConstToVirtReg:
            x86_insn_bytes[0] = 0xc7 # Write the 2-byte opcode of the mov m32, imm32 instruction
            x86_insn_bytes[1] = 0x05
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True) # Write the virtual register address
            x86_insn_bytes[6:6+4] = insn_args[0:4] # Write the constant value
        # Writes an x86 register to the address stored in the virtual register
        elif insn_opcode == VMOpcodes.MovX86RegToAddr:
            # We use a temporary register here, just like in previous instructions. If this instruction works with the eax register, then the temporary register is ecx. Otherwise, it's eax.
            storage_flag = 1
            if (insn_args[0] & 0x7) != 0:
                storage_flag = 0
            x86_insn_bytes[0] = 0x50 + storage_flag # Write the "push eax" or "push ecx" instruction
            x86_insn_bytes[1] = 0x8b # Write the "mov eax, [virtReg]" or "mov ecx, [virtReg]" instruction
            x86_insn_bytes[2] = 5 | (storage_flag << 3)
            x86_insn_bytes[3:3+4] = virt_reg_addr.to_bytes(4, 'little', signed=True)
            x86_insn_bytes[7] = 0x89 # Write the "mov [eax], r32" or "mov [ecx], r32" instruction
            x86_insn_bytes[8] = storage_flag + ((insn_args[0] & 0x7) << 3)
            x86_insn_bytes[9] = 0x58 + storage_flag # Write the "pop eax" or "pop ecx" instruction
        # Moves the value of the virtual register to an x86 register
        elif insn_opcode == VMOpcodes.MovVirtRegToX86Reg:
            x86_insn_bytes[0] = 0x8b # Write the "mov r32, m32" instruction opcode
            x86_insn_bytes[1] = 5 | ((insn_args[0] & 0x7) << 3) # Encode the destination x86 register
            x86_insn_bytes[2:2+4] = virt_reg_addr.to_bytes(4, 'little', signed=True) # Write the virtual register address
        # Executes x86 code
        elif insn_opcode == VMOpcodes.ExecX86Code or insn_opcode == VMOpcodes.ExecX86Code_2:
            x86_insn_bytes[:insn_args_sz] = insn_args[:insn_args_sz] # Simply copy code to be executed
        # Calls a function
        elif insn_opcode == VMOpcodes.Call:
             x86_insn_bytes[0] = 0xe8 # Write the opcode of the call instruction
             call_arg = int.from_bytes(insn_args[4:4+4], 'little', signed=True)
             call_delta = imagebase + call_arg - (curr_addr + 5) # Calculate the operand, which should be equal to "destination address - EIP"
             x86_insn_bytes[1:1+4] = call_delta.to_bytes(4, 'little', signed=True)
        # Makes a jump
        elif insn_opcode in [VMOpcodes.Jump, VMOpcodes.Jg, VMOpcodes.Je, VMOpcodes.Ja, VMOpcodes.Jl, VMOpcodes.Jo, VMOpcodes.Js, VMOpcodes.Jge, VMOpcodes.Jna, VMOpcodes.Jne,VMOpcodes.Jnp, VMOpcodes.Jp, VMOpcodes.Jns, VMOpcodes.Jb, VMOpcodes.Jle, VMOpcodes.Jnb, VMOpcodes.Jno]:
            virt_opcodes_to_x86_opcodes = {VMOpcodes.Jump: 0xe9, VMOpcodes.Jg: 0x8f, VMOpcodes.Je: 0x84, VMOpcodes.Ja: 0x87, VMOpcodes.Jl: 0x8c, VMOpcodes.Jo: 0x80, VMOpcodes.Js: 0x88, VMOpcodes.Jge: 0x8d, VMOpcodes.Jna: 0x86, VMOpcodes.Jne: 0x85, VMOpcodes.Jnp: 0x8b, VMOpcodes.Jp: 0x8a, VMOpcodes.Jns: 0x89, VMOpcodes.Jb: 0x82, VMOpcodes.Jle: 0x8e, VMOpcodes.Jnb: 0x83, VMOpcodes.Jno: 0x81}
            crafted_jump = craft_jump_insn(virt_opcodes_to_x86_opcodes[insn_opcode], insn_args) # Call this function that assembles jumps
            x86_insn_bytes[:len(crafted_jump)] = crafted_jump
        else:
            print(f"Error: unknown opcode {insn_opcode}!")
        
        idaapi.put_bytes(curr_addr, bytes(x86_insn_bytes)) # Write the translated instruction to our segment
        idaapi.auto_make_code(curr_addr) # Make code at the address where the translation has been written
        idaapi.set_name(curr_addr, "insn_" + hex(insn_id)[2:]) # Assign a name to this address
        curr_addr += 0x10
 
# Creates a new segment that will hold the translated instructions
def make_devirt_code_segment(segment_size):
    seg = idaapi.segment_t()
    seg.start_ea = align_to_page_size(ida_ida.inf_get_max_ea()) # The start address of our segment, which will be located after the last section in our program
    seg.end_ea = align_to_page_size(seg.start_ea + segment_size)
    seg.bitness = 1 # "1" means 32-bit
    seg.perm = idaapi.SEGPERM_EXEC | idaapi.SEGPERM_WRITE | idaapi.SEGPERM_READ # RWX permissions
    idaapi.add_segm_ex(seg, "FinVM", None, 0) # Create the segment
    idaapi.create_dword(seg.start_ea, 4) # Create a virtual register DWORD
    idaapi.set_name(seg.start_ea, "virtReg") 
    return seg.start_ea
with open(r"/home/vb2023/Downloads/vm.txt.unp", "rb") as f:
    bytecode = f.read()
# We divide the bytecode length by 24 to get the number of virtual instructions. Each instruction gets translated to 16 bytes, so we multiply the virtual instruction count by 16 to get the size of the segment with translated bytes.
virt_segm_addr = make_devirt_code_segment(len(bytecode)//24 * 16)
parse_bytecode(bytecode)
