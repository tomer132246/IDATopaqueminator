import idaapi, idautils, idc, ida_funcs
import sys
sys.stdout.encoding = 'utf-8'
import angr
from keystone import *
from capstone import *
import logging
import sark
####################################################################
#Constants.
####################################################################
T_VER = 9
DEBUG = True
DEBUG_VERBOSE = False



"""
TODO:
-Multiple block analyzing.
-Removing loops.
-This can only be used for really simple predicates.

"""




"""------------------------------"""
class FunctionOpaqueIdentifier:

    def __init__(self):
        if not DEBUG_VERBOSE:
            logger = logging.getLogger('angr')
            logger.propagate = False
            logger = logging.getLogger('claripy')
            logger.propagate = False
            logger = logging.getLogger('cle')
            logger.propagate = False
            logger = logging.getLogger('pyvex')
            logger.propagate = False
        
        self.current_func_name = idaapi.get_func_name(idaapi.get_screen_ea())
        self.current_func = idaapi.get_func(idaapi.get_screen_ea())
        self.angr_prj = angr.Project(idaapi.get_input_file_path(), load_options={'auto_load_libs':False}) 
        
        print("Down the rabbit hole..")
        print("[Topaqueminator] Identifying opaque predicates on function:", self.current_func_name)
        
        self.run()

    def check_if_jmp_x86_64(self, inst_ea):
        inst = idautils.DecodeInstruction(inst_ea).get_canon_mnem()
        if 'jmp' in inst:
            return True
        return False
    
    def check_conditional_x86_64(self, inst_ea):
        inst = idautils.DecodeInstruction(inst_ea).get_canon_mnem()
        if 'j' in inst and 'jmp' not in inst:
            return True
        return False

    def pretty_print_bytes(self, bytes):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for inst in md.disasm(bytes, self.current_func.start_ea):
            print(str(hex(inst.address)) + " " + inst.mnemonic + " " + inst.op_str + ";")

    def get_the_location_of_the_jump(self, jmp_inst_ea):
        if self.check_if_jmp_x86_64(jmp_inst_ea) or self.check_conditional_x86_64(jmp_inst_ea):
            return idc.get_operand_value(jmp_inst_ea, 0)
        return None

    def continous_chunks_test(self):
        #block_bytes does not include the instruction after the jmp BUT, block.end - block.start does.
        done = False
        fc = idaapi.FlowChart(self.current_func)
        counter = 0
        for block in fc:
            print("======================================================================")
            print("======================================================================")
            if (self.check_conditional_x86_64(idc.prev_head(block.end_ea))):
                print("Found conditional jump address in: ", hex(idc.prev_head(block.end_ea)))
                if(self.analyze_opaque(idc.prev_head(block.end_ea))):
                    print("Opaque conditional jump address is: ", hex(idc.prev_head(block.end_ea)))
                    bsetend = idc.append_func_tail(self.current_func.start_ea, idc.get_prev_fchunk(idc.prev_head(block.end_ea)),idc.prev_head(block.end_ea))
                    if bsetend:
                        print("new end set.")
                    else:
                        print("failed setting end.")
                    print("Tomerminatored the opaque.")
                    done = True
                else:
                    print("Block appened, conditional jump not found.")  
            print("Iteration Done.")
            if done:
                break
            counter += 1
            if counter == 100:
                break
    
    def analyze_opaque(self, predicate_ea):
        print("State starting point:", hex(self.current_func.start_ea))

        s = self.angr_prj.factory.blank_state(addr=self.current_func.start_ea)

        #ignore func calls
        s.options.add(angr.options.CALLLESS)
        s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        s.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

        simMgr = self.angr_prj.factory.simgr(s)

        predicate_jmp_address_operand = self.get_the_location_of_the_jump(predicate_ea)

        # Run the code until all paths have errored or the full shellcode has ran
        #FIND is the address RIGHT AFTER the jump.
        #AVOID is the location we maybe will jump to.
        #if all states when we finish are in avoid, than we always jump.
        #if all states when we finish are in found, we never jump
        #if found size is 0, we always jump
        # 
        # 
        # 
        # 
        # 
        simMgr.explore(find=idaapi.next_head(predicate_ea, predicate_ea+0x100), avoid=predicate_jmp_address_operand)
    

        print("find: ", hex(idaapi.next_head(predicate_ea, predicate_ea+0x100)))
        print("avoid: ", hex(predicate_jmp_address_operand))
        print("SimMgr: ", simMgr)

        print("Printing the active states RIP after we got forked:")
        for i in simMgr.active:
            print(i.regs.rip)
        print("Printing the errored states RIP after we got forked:")
        for i in simMgr.errored:
            print(i.state.regs.rip)
        print("Printing the deadended states RIP after we got forked:")
        for i in simMgr.deadended:
            print(i.regs.rip)
        print("Printing the pruned states RIP after we got forked:")
        for i in simMgr.pruned:
            print(i.regs.rip)
        print("Printing the unconstrained states RIP after we got forked:")
        for i in simMgr.unconstrained:
            print(i.regs.rip)
        print("Printing the unsat states RIP after we got forked:")
        for i in simMgr.unsat:
            print(i.regs.rip)
        print("Printing the found states RIP after we got forked:")
        for i in simMgr.found:
            print(i.regs.rip)
        if len(simMgr.found) == 0:
            print("None found, Meaning, ALWAYS JUMP")
            return True
        else:
            total_stashes_len = 0
            for stash in simMgr.stashes:
                total_stashes_len += len(stash)
            total_stashes_len -= len(simMgr.found)
            if total_stashes_len == 0:
                print("All are in found, Meaning, NEVER JUMP")
                return True

        print("Printing the avoid states RIP after we got forked:")
        for i in simMgr.avoid:
            print(i.regs.rip)
        total_stashes_len = 0
        for stash in simMgr.stashes:
            total_stashes_len += len(stash)
        total_stashes_len -= len(simMgr.avoid)
        if total_stashes_len == 0:
            print("All are in found, Meaning, ALWAYS JUMP")
            return True
        
        return False


        # Pretty Print the dissasembly of the shellcode
        #block = p.factory.block(0).pp()

        # If there's only a single path in the shellcode then the conditional branch each sample ends with can't possibly
        # be executed
        # If there's potentially multiple paths make the path state concrete to ensure
        # they're all definitely possible paths

        # sat_paths = 0
        # rip_set = set()
        # for state in simMgr.active:
        #     if state.satisfiable():
        #         sat_paths += 1
        #         rip_set.add(state.regs.rip)
        # print("The set of active states Rip is: ")
        # print(rip_set)

        # if sat_paths > 1:
        #     if len(rip_set) == 1:
        #         print("There is only one achievable path. (jz[x],..,jnz[x])")
        #         return True
        #     else:
        #         print("multiple valid paths, jmp must be optional")
        #         return False
        # else:
        #     print("There is only one achievable path.")
        #     return True
    
    def shell_test(self):
        CODE1 = ["xor rax, rax;",
        "mov rax, rbx;",
        "xor rax, rcx;",
        "xor rax,rax",
        "jnz 0x41444;",
        "mov rax, rcx",
        "jz 0x4143B;",
        ]

        CODE2 = ["xor rax, rax;",
        "mov rax, rbx;",
        "xor rax, rcx;",
        "jnz 0x41444;",
        "mov rax, rcx",
        "xor rbx, rcx",
        "jz 0x4143B;",
        ]

        CODE3 = ["stc;",
        "xchg bh, bh;",
        "movzx	eax, byte ptr [rcx + 0x7e];",
        "movzx	eax, byte ptr [rcx + 0x7e];",
        "mov	qword ptr [rbp], rdx;",
        "lea	rdx, [rip - 0xc7c];",
        "call 0x2311111;",
        "stc;",
        "jbe 0x1240;",
        ]
        
        
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        code_instructions = []
        all_shell_code = b""
        for inst in CODE3:
            encoding, count = ks.asm(inst)
            opcodes = b""
            for i in encoding:
                opcodes += bytes([i])
            all_shell_code += opcodes
            code_instructions.append(opcodes)

    def run(self):
        self.continous_chunks_test()
        
        
        
            

    
         
            
                
        


    
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
        self.plug_instance =  FunctionOpaqueIdentifier()
        return idaapi.PLUGIN_KEEP
    
    def run(self, ctx):
        self.plug_instance.run()
       
        

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