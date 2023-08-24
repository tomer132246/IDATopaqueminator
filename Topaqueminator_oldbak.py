import idaapi, idautils, idc
import sys
sys.stdout.encoding = 'utf-8'
import angr
import warnings
import keystone
warnings.filterwarnings("ignore")
####################################################################
#Constants.
####################################################################
T_VER = 9
DEBUG = 1



"""
TODO:
-Multiple block analyzing.
-Removing loops.
-This can only be used for really simple predicates.

"""




"""------------------------------"""
class FunctionOpaqueIdentifier:
    current_func_name = idaapi.get_func_name(idaapi.get_screen_ea())
    current_func = idaapi.get_func(idaapi.get_screen_ea())
    current_ea = idaapi.get_screen_ea()

    def __init__(self):
        print("Down the rabbit hole..")
        print("[Topaqueminator] Identifying opaque predicates on function:", self.current_func_name)
        self.run()


    def check_conditional_x86_64(self, inst_ea):
        inst = idautils.DecodeInstruction(inst_ea).get_canon_mnem()
        if inst in ['jl','jle','jns','js','jz', 'ja','jb','je','jo','jne', 'jnz', 'jno', 'jg', 'jno', 'jnp', 'jp']:
            return True
        return False
    
    def get_basic_blocks_shellcode(self):
        fc = idaapi.FlowChart(self.current_func)
        for block in fc:
            block_bytes = idc.get_bytes(block.start_ea, block.end_ea - block.start_ea, False)
            yield block_bytes, block

    def single_block_test(self):
        for basic_block_bytes, block in self.get_basic_blocks_shellcode():
            if DEBUG:
                if basic_block_bytes is not None and self.check_conditional_x86_64(idc.prev_head(block.end_ea)):
                    if(self.analyze_byte_array(basic_block_bytes)):
                        print(idautils.DecodeInstruction(idc.prev_head(block.end_ea)).get_canon_mnem())
                        print("Tomerminatored the opaque.")
                    else:
                        print("Not opaque.")
                    print("this are the blocks start:", hex(block.start_ea), " end:", hex(block.end_ea))
                    print("======================================================================")
                    print("====================================================================== \n\n\n\n\n")
                                  
    def continous_chunks_test(self):
        contblock = ""
        for basic_block_bytes, block in self.get_basic_blocks_shellcode():
            if DEBUG:
                contblock += basic_block_bytes
                if basic_block_bytes is not None and self.check_conditional_x86_64(idc.prev_head(block.end_ea)):
                    if(self.analyze_byte_array(contblock)):
                        print("Tomerminatored the opaque.")
                    else:
                        print("Not opaque.")
                print("======================================================================")
                print("======================================================================")
                    
    def analyze_byte_array(self, bytearray):
        
        p = angr.project.load_shellcode(bytearray, "ArchAMD64") 
        s = p.factory.blank_state()
        #ignore func calls
        s.options.add(angr.options.CALLLESS)
        s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        simMgr = p.factory.simulation_manager(s)

        # Run the code until all paths have errored or the full shellcode has ran
        out =  simMgr.explore()

        # Pretty Print the dissasembly of the shellcode
        #block = p.factory.block(0).pp()

        # If there's only a single path in the shellcode then the conditional branch each sample ends with can't possibly
        # be executed
        if len(out.errored) == 1:
            print("There is only one path in total.")
            return True #Only one path - must be an opaque predicate
        # If there's potentially multiple paths make the path state concrete to ensure
        # they're all definitely possible paths
        sat_paths = 0
        out_locations = set()
        for i in out.errored:
            if i.state.satisfiable():
                sat_paths += 1
        if sat_paths > 1:
            print("multiple valid paths, jmp must be optional")
            return False #multiple valid paths, jmp must be optional
        print("There is only one achievable path.")
        return True #Only one achievable path
    
    def miscTest(self):
        pass

    def shell_test(self):
        
        OP_CODE_EX_1 = "mov ecx, 1; dec ecx; jz 0x0132;"
        OP_CODE_EX_2 = "mov ecx, 1; dec rdx; jz 0x132; jnz 0x132"
        NOP_CODE_EX_3 = "mov ecx, 1; dec rdx; jz 0x0132"
        NOP_CODE_EX_4 = "mov ecx, 1; dec rdx; jz 0x0132; jnz 0x0136"

        ks_assmblr = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        OP_CODE_EX_1_BYTES = ks_assmblr.asm(OP_CODE_EX_1, as_bytes=True)
        OP_CODE_EX_2_BYTES = ks_assmblr.asm(OP_CODE_EX_2, as_bytes=True)
        NOP_CODE_EX_3_BYTES = ks_assmblr.asm(NOP_CODE_EX_3, as_bytes=True)
        NOP_CODE_EX_4_BYTES = ks_assmblr.asm(NOP_CODE_EX_4, as_bytes=True)

        if self.analyze_byte_array(NOP_CODE_EX_4_BYTES[0]):
           print("Opaque")
        else:
            print("Not Opaque")

    def run(self):
        self.single_block_test()
        self.shell_test()
        #self.continous_chunks_test()
        #self.miscTest()
        
        
            

    
         
            
                
        


    
"""------------------------------"""
class Topaqueminator(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "Topaqueminator"
    wanted_hotkey = "Ctrl-Alt-T"
    comment = 'Topaqueminator Comment'
    help = 'TBD'

    def init(self):
        print('--------------------------------------')
        print('Topaqueminator Starting. VER:' , T_VER)
        print('--------------------------------------')
        return idaapi.PLUGIN_OK
    
    def run(self, ctx):
        FunctionOpaqueIdentifier()
        

    def term(self):
        print('Made by Tomerminator, use as you wish.')
        print('Topaqueminator finished.')
"""------------------------------"""
def PLUGIN_ENTRY():
    try:
        return Topaqueminator()
    except Exception as err:
        import traceback
        print('Error: %s\n%s' % str((err), traceback.format_exc()))
        raise
"""------------------------------"""