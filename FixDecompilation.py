import ida_hexrays
kernel_register = ida_hexrays.mr_none
register_addr = get_name_ea(idaapi.BADADDR, "virtReg")
class OperandReplacer(ida_hexrays.mop_visitor_t):
    def visit_mop(self, op, op_type, is_target):
        global kernel_register
        # Check if we are dealing with the virtual register variable
        if op.t == ida_hexrays.mop_v and op.g == register_addr:
            # Replace the global variable with a kernel register
            op.make_reg(kernel_register, op.size)       
            if self.blk:
                self.blk.mark_lists_dirty() # inform IDA of microcode changes
        return 0
class DecompilerHook(ida_hexrays.Hexrays_Hooks):
    def preoptimized(self, *args):
        global kernel_register
        mba = args[0] # MBA means “micro block array”. This object contains the               
                      # microcode of the function being decompiled
        kernel_register = mba.alloc_kreg(4) # We allocate a kernel register here
        if kernel_register != ida_hexrays.mr_none:
            repl = OperandReplacer()
            mba.for_all_ops(repl) # Iterate over all operands, invoking the visit_mop method of the OperandReplacer class for each operand                          
        return 0
event_hook = DecompilerHook()
event_hook.hook() # Activate the hook