import idaapi, idautils, idc, ida_funcs, ida_auto
import sys
sys.stdout.encoding = 'utf-8'
import angr
from keystone import *
from capstone import *
import logging
from enum import Enum
import sark
import re
import six
####################################################################
#Constants.
####################################################################
T_VER = 14
DEBUG = True
DEBUG_VERBOSE = False
DEPTH = 200
STOP_AFTER_ITERATION = False
X86_NOP = "\x90"
patch_info = []


"""
TODO:
-DEFLOW implementation.
-restart generator.
-handle never jmp

"""

class OpaqueAnalyzeRetValues(Enum):
    NOT_OPAQUE = 1
    ALWAYS_JMP = 2
    NEVER_JMP = 3
    ERROR = 4

##################py compitability funcs################################################################
def to_string(s):
  # python3 bytes
  if six.PY3 and isinstance(s, bytes):
      return s.decode('latin-1')
  # python2 unicode
  elif six.PY2 and isinstance(s, six.text_type):
      return s.encode('utf-8')
  return str(s)

def to_hexstr(buf, sep=' '):
    # for python3 bytes
    if six.PY3 and isinstance(buf, bytes):
        return sep.join("{0:02x}".format(c) for c in buf).upper()
    return sep.join("{0:02x}".format(ord(c)) for c in buf).upper()
########################################################################################################
#########################################################################################################

# return a normalized code, or None if input is invalid
def convert_hexstr(code):
    # normalize code
    code = code.lower()
    code = code.replace(' ', '')    # remove space
    code = code.replace('h', '')    # remove trailing 'h' in 90h
    code = code.replace('0x', '')   # remove 0x
    code = code.replace('\\x', '')  # remove \x
    code = code.replace(',', '')    # remove ,
    code = code.replace(';', '')    # remove ;
    code = code.replace('"', '')    # remove "
    code = code.replace("'", '')    # remove '
    code = code.replace("+", '')    # remove +

    # single-digit hexcode?
    if len(code) == 1 and ((code >= '0' and code <= '9') or (code >= 'a' and code <= 'f')):
        # stick 0 in front (so 'a' --> '0a')
        code = '0' + code

    # odd-length is invalid
    if len(code) % 2 != 0:
        return None

    try:
        hex_data = code.decode('hex')
        # we want a list of int
        return [ord(i) for i in hex_data]
    except:
        # invalid hex
        return None

#################################################################################################

################################ IDA 6/7 Compatibility function #########################################
def get_dtype(ea, op_idx):
    if idaapi.IDA_SDK_VERSION >= 700:
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        dtype = insn.ops[op_idx].dtype
        dtyp_size = idaapi.get_dtype_size(dtype)
    else:
        dtype = idaapi.cmd.Operands[op_idx].dtyp
        dtyp_size = idaapi.get_dtyp_size(dtype)
    return dtype, dtyp_size

def set_comment(ea, comment):
    if idaapi.IDA_SDK_VERSION >= 700:
        idc.set_cmt(ea, comment, 0)
    else:
        idc.MakeComm(ea, comment)

def get_comment(ea):
    if idaapi.IDA_SDK_VERSION >= 700:
        return idc.get_cmt(ea, 0)
    return idc.Comment(ea)

def read_range_selection():
    if idaapi.IDA_SDK_VERSION >= 700:
        return idaapi.read_range_selection(None)
    return idaapi.read_selection()
#########################################################################################################


class Keypatch_Asm:
    # supported architectures
    arch_lists = {
        "X86 16-bit": (KS_ARCH_X86, KS_MODE_16),                # X86 16-bit
        "X86 32-bit": (KS_ARCH_X86, KS_MODE_32),                # X86 32-bit
        "X86 64-bit": (KS_ARCH_X86, KS_MODE_64),                # X86 64-bit
        "ARM": (KS_ARCH_ARM, KS_MODE_ARM),                      # ARM
        "ARM Thumb": (KS_ARCH_ARM, KS_MODE_THUMB),              # ARM Thumb
        "ARM64 (ARMV8)": (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),# ARM64
        "Hexagon": (KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN),       # Hexagon
        "Mips32": (KS_ARCH_MIPS, KS_MODE_MIPS32),               # Mips32
        "Mips64": (KS_ARCH_MIPS, KS_MODE_MIPS64),               # Mips64
        "PowerPC 32": (KS_ARCH_PPC, KS_MODE_PPC32),             # PPC32
        "PowerPC 64": (KS_ARCH_PPC, KS_MODE_PPC64),             # PPC64
        "Sparc 32": (KS_ARCH_SPARC, KS_MODE_SPARC32),           # Sparc32
        "Sparc 64": (KS_ARCH_SPARC, KS_MODE_SPARC64),           # Sparc64
        "SystemZ": (KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN),       # SystemZ
    }

    endian_lists = {
        "Little Endian": KS_MODE_LITTLE_ENDIAN,                 # little endian
        "Big Endian": KS_MODE_BIG_ENDIAN,                       # big endian
    }

    syntax_lists = {
        "Intel": KS_OPT_SYNTAX_INTEL,
        "Nasm": KS_OPT_SYNTAX_NASM,
        "AT&T": KS_OPT_SYNTAX_ATT
    }

    def __init__(self, arch=None, mode=None):
        # update current arch and mode
        self.update_hardware_mode()

        # override arch & mode if provided
        if arch is not None:
            self.arch = arch
        if mode is not None:
            self.mode = mode

        # IDA uses Intel syntax by default
        self.syntax = KS_OPT_SYNTAX_INTEL

    # return Keystone arch & mode (with endianess included)
    @staticmethod
    def get_hardware_mode():
        (arch, mode) = (None, None)

        # heuristically detect hardware setup
        info = idaapi.get_inf_structure()
        
        try:
            cpuname = info.procname.lower()
        except:
            cpuname = info.procName.lower()

        try:
            # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
            is_be = idaapi.cvar.inf.is_be()
        except:
            # older IDA versions
            is_be = idaapi.cvar.inf.mf
        # print("Keypatch BIG_ENDIAN = %s" %is_be)
        
        if cpuname == "metapc":
            arch = KS_ARCH_X86
            if info.is_64bit():
                mode = KS_MODE_64
            elif info.is_32bit():
                mode = KS_MODE_32
            else:
                mode = KS_MODE_16
        elif cpuname.startswith("arm"):
            # ARM or ARM64
            if info.is_64bit():
                arch = KS_ARCH_ARM64
                if is_be:
                    mode = KS_MODE_BIG_ENDIAN
                else:
                    mode = KS_MODE_LITTLE_ENDIAN
            else:
                arch = KS_ARCH_ARM
                # either big-endian or little-endian
                if is_be:
                    mode = KS_MODE_ARM | KS_MODE_BIG_ENDIAN
                else:
                    mode = KS_MODE_ARM | KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("sparc"):
            arch = KS_ARCH_SPARC
            if info.is_64bit():
                mode = KS_MODE_SPARC64
            else:
                mode = KS_MODE_SPARC32
            if is_be:
                mode |= KS_MODE_BIG_ENDIAN
            else:
                mode |= KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("ppc"):
            arch = KS_ARCH_PPC
            if info.is_64bit():
                mode = KS_MODE_PPC64
            else:
                mode = KS_MODE_PPC32
            if cpuname == "ppc":
                # do not support Little Endian mode for PPC
                mode += KS_MODE_BIG_ENDIAN
        elif cpuname.startswith("mips"):
            arch = KS_ARCH_MIPS
            if info.is_64bit():
                mode = KS_MODE_MIPS64
            else:
                mode = KS_MODE_MIPS32
            if is_be:
                mode |= KS_MODE_BIG_ENDIAN
            else:
                mode |= KS_MODE_LITTLE_ENDIAN
        elif cpuname.startswith("systemz") or cpuname.startswith("s390x"):
            arch = KS_ARCH_SYSTEMZ
            mode = KS_MODE_BIG_ENDIAN

        return (arch, mode)

    def update_hardware_mode(self):
        (self.arch, self.mode) = self.get_hardware_mode()

    # normalize assembly code
    # remove comment at the end of assembly code
    @staticmethod
    def asm_normalize(text):
        text = ' '.join(text.split())
        if text.rfind(';') != -1:
            return text[:text.rfind(';')].strip()

        return text.strip()

    @staticmethod
    # check if input address is valid
    # return
    #       -1  invalid address at target binary
    #        0  type mismatch of input address
    #        1  valid address at target binary
    def check_address(address):
        try:
            if idc.is_mapped(address):
                return 1
            else:
                return -1
        except:
            # invalid type
            return 0

    ### resolve IDA names from input asm code
    # todo: a better syntax parser for all archs
    def ida_resolve(self, assembly, address=idc.BADADDR):
        def _resolve(_op, ignore_kw=True):
            names = re.findall(r"[\$a-z0-9_:\.]+", _op, re.I)

            # try to resolve all names
            for name in names:
                # ignore known keywords
                if ignore_kw and name in ('byte', 'near', 'short', 'word', 'dword', 'ptr', 'offset'):
                    continue

                sym = name

                # split segment reg
                parts = name.partition(':')
                if parts[2] != '':
                    sym = parts[2]

                (typ, value) = idaapi.get_name_value(address, sym)

                # skip if name doesn't exist or segment / segment registers
                if typ in (idaapi.NT_SEG, idaapi.NT_NONE):
                    continue

                _op = _op.replace(sym, '0x{0:X}'.format(value))

            return _op

        if self.check_address(address) == 0:
            print("Keypatch: WARNING: invalid input address {0}".format(address))
            return assembly

        # for now, we only support IDA name resolve for X86, ARM, ARM64, MIPS, PPC, SPARC
        if not (self.arch in (KS_ARCH_X86, KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_MIPS, KS_ARCH_PPC, KS_ARCH_SPARC)):
            return assembly

        _asm = assembly.partition(' ')
        mnem = _asm[0]
        opers = _asm[2].split(',')

        for idx, op in enumerate(opers):
            _op = list(op.partition('['))
            ignore_kw = True
            if _op[1] == '':
                _op[2] = _op[0]
                _op[0] = ''
            else:
                _op[0] = _resolve(_op[0], ignore_kw=True)
                ignore_kw = False

            _op[2] = _resolve(_op[2], ignore_kw=ignore_kw)

            opers[idx] = ''.join(_op)

        asm = "{0} {1}".format(mnem, ','.join(opers))
        return asm

    # return bytes of instruction or data
    # return None on failure
    def ida_get_item(self, address, hex_output=False):
        if self.check_address(address) != 1:
            # not a valid address
            return (None, 0)

        # return None if address is in the middle of instruction / data
        if address != idc.get_item_head(address):
            return (None, 0)

        size = idc.get_item_size(address)
        item = idc.get_bytes(address, size)

        if item is None:
            return (None, 0)

        if hex_output:
            item = to_hexstr(item)

        return (item, size)

    @staticmethod
    def get_op_dtype_name(ea, op_idx):
        dtyp_lists = {
            idaapi.dt_byte: 'byte',     #  8 bit
            idaapi.dt_word: 'word',     #  16 bit
            idaapi.dt_dword: 'dword',   #  32 bit
            idaapi.dt_float: 'dword',   #  4 byte
            idaapi.dt_double: 'dword',  #  8 byte
            #idaapi.dt_tbyte = 5        #  variable size (ph.tbyte_size)
            #idaapi.dt_packreal = 6         #  packed real format for mc68040
            idaapi.dt_qword: 'qword',   #  64 bit
            idaapi.dt_byte16: 'xmmword',#  128 bit
            #idaapi.dt_code = 9         #  ptr to code (not used?)
            #idaapi.dt_void = 10        #  none
            #idaapi.dt_fword = 11       #  48 bit
            #idaapi.dt_bitfild = 12     #  bit field (mc680x0)
            #idaapi.dt_string = 13      #  pointer to asciiz string
            #idaapi.dt_unicode = 14     #  pointer to unicode string
            #idaapi.dt_3byte = 15       #  3-byte data
            #idaapi.dt_ldbl = 16        #  long double (which may be different from tbyte)
            idaapi.dt_byte32: 'ymmword',# 256 bit
        }
        idc.get_dtype
        dtype, dtyp_size = get_dtype(ea, op_idx)
        if dtype == idaapi.dt_tbyte and dtyp_size == 10:
          return 'xword'

        dtyp_name = dtyp_lists.get(dtype, None)

        return dtyp_name

    # return asm instructions from start to end
    def ida_get_disasm_range(self, start, end):
        codes = []
        while start < end:
            asm = self.asm_normalize(idc.GetDisasm(start))
            if asm == None:
                asm = ''
            codes.append(asm)
            start = start + idc.get_item_size(start)

        return codes

    # get disasm from IDA
    # return '' on invalid address
    def ida_get_disasm(self, address, fixup=False):

        def GetMnem(asm):
            sp = asm.find(' ')
            if sp == -1:
                return asm
            return asm[:sp]

        if self.check_address(address) != 1:
            # not a valid address
            return ''

        # return if address is in the middle of instruction / data
        if address != idc.get_item_head(address):
            return ''

        asm = self.asm_normalize(idc.GetDisasm(address))
        # for now, only support IDA syntax fixup for Intel CPU
        if not fixup or self.arch != KS_ARCH_X86:
            return asm

        # KS_ARCH_X86 mode
        # rebuild disasm code from IDA
        i = 0
        mnem = GetMnem(asm)
        if mnem == '' or mnem in ('rep', 'repne', 'repe'):
            return asm

        opers = []
        while idc.get_operand_type(address, i) > 0 and i < 6:
            t = idc.get_operand_type(address, i)
            o = idc.print_operand(address, i)

            if t in (idc.o_mem, idc.o_displ):
                parts = list(o.partition(':'))
                if parts[2] == '':
                    parts[2] = parts[0]
                    parts[0] = ''

                if '[' not in parts[2]:
                    parts[2] = '[{0}]'.format(parts[2])

                o = ''.join(parts)

                if 'ptr ' not in o:
                    dtyp_name = self.get_op_dtype_name(address, i)
                    if dtyp_name != None:
                        o = "{0} ptr {1}".format(dtyp_name, o)

            opers.append(o)
            i += 1

        asm = mnem
        for o in opers:
            if o != '':
                asm = "{0} {1},".format(asm, o)

        asm = asm.strip(',')
        return asm

    # assemble code with Keystone
    # return (encoding, count), or (None, 0) on failure
    def assemble(self, assembly, address, arch=None, mode=None, syntax=None):

        # return assembly with arithmetic equation evaluated
        def eval_operand(assembly, start, stop, prefix=''):
            imm = assembly[start+1:stop]
            try:
                eval_imm = eval(imm)
                if eval_imm > 0x80000000:
                    eval_imm = 0xffffffff - eval_imm
                    eval_imm += 1
                    eval_imm = -eval_imm
                return assembly.replace(prefix + imm, prefix + hex(eval_imm))
            except:
                return assembly

        # IDA uses different syntax from Keystone
        # sometimes, we can convert code to be consumable by Keystone
        def fix_ida_syntax(assembly):

            # return True if this insn needs to be fixed
            def check_arm_arm64_insn(arch, mnem):
                if arch == KS_ARCH_ARM:
                    if mnem.startswith("ldr") or mnem.startswith("str"):
                        return True
                    return False
                elif arch == KS_ARCH_ARM64:
                    if mnem.startswith("ldr") or mnem.startswith("str"):
                        return True
                    return mnem in ("stp")
                return False

            # return True if this insn needs to be fixed
            def check_ppc_insn(mnem):
                return mnem in ("stw")

            # replace the right most string occurred
            def rreplace(s, old, new):
                li = s.rsplit(old, 1)
                return new.join(li)

            # convert some ARM pre-UAL assembly to UAL, so Keystone can handle it
            # example: streqb --> strbeq
            def fix_arm_ual(mnem, assembly):
                # TODO: this is not an exhaustive list yet
                if len(mnem) != 6:
                    return assembly

                if (mnem[-1] in ('s', 'b', 'h', 'd')):
                    #print(">> 222", mnem[3:5])
                    if mnem[3:5] in ("cc", "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"):
                        return assembly.replace(mnem, mnem[:3] + mnem[-1] + mnem[3:5], 1)

                return assembly

            if self.arch != KS_ARCH_X86:
                assembly = assembly.lower()
            else:
                # Keystone does not support immediate 0bh, but only 0Bh
                assembly = assembly.upper()

            # however, 0X must be converted to 0x
            # Keystone should fix this limitation in the future
            assembly = assembly.replace("0X", " 0x")

            _asm = assembly.partition(' ')
            mnem = _asm[0]
            if mnem == '':
                return assembly

            # for PPC, Keystone does not accept registers with 'r' prefix,
            # but only the number behind. lets try to fix that here by
            # removing the prefix 'r'.
            if self.arch == KS_ARCH_PPC:
                for n in range(32):
                    r = " r%u," %n
                    if r in assembly:
                        assembly = assembly.replace(r, " %u," %n)
                for n in range(32):
                    r = "(r%u)" %n
                    if r in assembly:
                        assembly = assembly.replace(r, "(%u)" %n)
                for n in range(32):
                    r = ", r%u" %n
                    if assembly.endswith(r):
                        assembly = rreplace(assembly, r, ", %u" %n)

            if self.arch == KS_ARCH_X86:
                if mnem == "RETN":
                    # replace retn with ret
                    return assembly.replace('RETN', 'RET', 1)
                if 'OFFSET ' in assembly:
                    return assembly.replace('OFFSET ', ' ')
                if mnem in ('CALL', 'JMP') or mnem.startswith('LOOP'):
                    # remove 'NEAR PTR'
                    if ' NEAR PTR ' in assembly:
                        return assembly.replace(' NEAR PTR ', ' ')
                elif mnem[0] == 'J':
                    # JMP instruction
                    if ' SHORT ' in assembly:
                        # remove ' short '
                        return assembly.replace(' SHORT ', ' ')
            elif self.arch in (KS_ARCH_ARM, KS_ARCH_ARM64, KS_ARCH_PPC):
                # *** ARM
                # LDR     R1, [SP+rtld_fini],#4
                # STR     R2, [SP,#-4+rtld_fini]!
                # STR     R0, [SP,#fini]!
                # STR     R12, [SP,#4+var_8]!

                # *** ARM64
                # STP     X29, X30, [SP,#-0x10+var_150]!
                # STR     W0, [X29,#0x150+var_8]
                # LDR     X0, [X0,#(qword_4D6678 - 0x4D6660)]
                # TODO:
                # ADRP    X19, #interactive@PAGE

                # *** PPC
                # stw     r5, 0x120+var_108(r1)
                
                if self.arch == KS_ARCH_ARM and mode == KS_MODE_THUMB:
                    assembly = assembly.replace('movt.w', 'movt')

                if self.arch == KS_ARCH_ARM:
                    #print(">> before UAL fix: ", assembly)
                    assembly = fix_arm_ual(mnem, assembly)
                    #print(">> after UAL fix: ", assembly)

                if check_arm_arm64_insn(self.arch, mnem) or (("[" in assembly) and ("]" in assembly)):
                    bang = assembly.find('#')
                    bracket = assembly.find(']')
                    if bang != -1 and bracket != -1 and bang < bracket:
                        return eval_operand(assembly, bang, bracket, '#')
                    elif '+0x0]' in assembly:
                        return assembly.replace('+0x0]', ']')
                elif check_ppc_insn(mnem):
                    start = assembly.find(', ')
                    stop = assembly.find('(')
                    if start != -1 and stop != -1 and start < stop:
                        return eval_operand(assembly, start, stop)
            return assembly

        def is_thumb(address):
            return idc.get_sreg(address, 'T') == 1

        if self.check_address(address) == 0:
            return (None, 0)

        # use default syntax, arch and mode if not provided
        if syntax is None:
            syntax = self.syntax
        if arch is None:
            arch = self.arch
        if mode is None:
            mode = self.mode

        if arch == KS_ARCH_ARM and is_thumb(address):
            mode = KS_MODE_THUMB

        try:
            ks = Ks(arch, mode)
            if arch == KS_ARCH_X86:
                ks.syntax = syntax
            encoding, count = ks.asm(fix_ida_syntax(assembly), address)
        except KsError as e:
            # keep the below code for debugging
            #print("Keypatch Error: {0}".format(e))
            #print("Original asm: {0}".format(assembly))
            #print("Fixed up asm: {0}".format(fix_ida_syntax(assembly)))
            encoding, count = None, 0

        return (encoding, count)


    # patch at address, return the number of written bytes & original data
    # this process can fail in some cases
    @staticmethod
    def patch_raw(address, patch_data, size):
        ea = address
        orig_data = ''

        while ea < (address + size):

            if not idc.has_value(idc.get_full_flags(ea)):
                print("Keypatch: FAILED to read data at 0x{0:X}".format(ea))
                break

            orig_byte = idc.get_wide_byte(ea)
            orig_data += chr(orig_byte)
            patch_byte = ord(patch_data[ea - address])

            if patch_byte != orig_byte:
                # patch one byte
                if idaapi.patch_byte(ea, patch_byte) != 1:
                    print("Keypatch: FAILED to patch byte at 0x{0:X} [0x{1:X}]".format(ea, patch_byte))
                    break
            ea += 1
        return (ea - address, orig_data)

    # patch at address, return the number of written bytes & original data
    # on patch failure, we revert to the original code, then return (None, None)
    def patch(self, address, patch_data, size):
        # save original function end to fix IDA re-analyze issue after patching
        orig_func_end = idc.get_func_attr(address, idc.FUNCATTR_END)

        (patched_len, orig_data) = self.patch_raw(address, patch_data, size)

        if size != patched_len:
            # patch failure
            if patched_len > 0:
                # revert the changes
                (rlen, _) = self.patch_raw(address, orig_data, patched_len)
                if rlen == patched_len:
                    print("Keypatch: successfully reverted changes of {0:d} byte(s) at 0x{1:X} [{2}]".format(
                                        patched_len, address, to_hexstr(orig_data)))
                else:
                    print("Keypatch: FAILED to revert changes of {0:d} byte(s) at 0x{1:X} [{2}]".format(
                                        patched_len, address, to_hexstr(orig_data)))

            return (None, None)

        # ask IDA to re-analyze the patched area
        if orig_func_end == idc.BADADDR:
            # only analyze patched bytes, otherwise it would take a lot of time to re-analyze the whole binary
            idaapi.plan_and_wait(address, address + patched_len + 1)
        else:
            idaapi.plan_and_wait(address, orig_func_end)

            # try to fix IDA function re-analyze issue after patching
            idc.set_func_end(address, orig_func_end)

        return (patched_len, orig_data)

    # return number of bytes patched
    # return
    #    0  Invalid assembly
    #   -1  PatchByte failure
    #   -2  Can't read original data
    #   -3  Invalid address
    def patch_code(self, address, assembly, syntax, padding, save_origcode, orig_asm=None, patch_data=None, patch_comment=None, undo=False):
        global patch_info

        if self.check_address(address) != 1:
            # not a valid address
            return -3

        orig_comment = get_comment(address)
        if orig_comment is None:
            orig_comment = ''

        nop_comment = ""
        padding_len = 0
        if not undo:
            # we are patching via Patcher
            (orig_encoding, orig_len) = self.ida_get_item(address)
            if (orig_encoding, orig_len) == (None, 0):
                return -2

            (encoding, count) = self.assemble(assembly, address, syntax=syntax)
            if encoding is None:
                return 0

            patch_len = len(encoding)
            patch_data = ''.join(chr(c) for c in encoding)

            if patch_data == orig_encoding:
                #print("Keypatch: no need to patch, same encoding data [{0}] at 0x{1:X}".format(to_hexstr(orig_encoding), address))
                return orig_len

            # for now, only support NOP padding on Intel CPU
            if padding and self.arch == KS_ARCH_X86:
                if patch_len < orig_len:
                    padding_len = orig_len - patch_len
                    patch_len = orig_len
                    patch_data = patch_data.ljust(patch_len, X86_NOP)
                elif patch_len > orig_len:
                    patch_end = address + patch_len - 1
                    ins_end = idc.get_item_end(patch_end)
                    padding_len = ins_end - patch_end - 1

                    if padding_len > 0:
                        patch_len = ins_end - address
                        patch_data = patch_data.ljust(patch_len, X86_NOP)

                if padding_len > 0:
                    nop_comment = "\nKeypatch padded NOP to next boundary: {0} bytes".format(padding_len)

            orig_asm = self.ida_get_disasm_range(address, address + patch_len)
        else:
            # we are reverting the change via "Undo" menu
            patch_len = len(patch_data)

        (plen, p_orig_data) = self.patch(address, patch_data, patch_len)
        if plen is None:
            # failed to patch
            return -1

        if not undo: # we are patching
            new_patch_comment = None
            if save_origcode is True:
                # append original instruction to comments
                if orig_comment == '':
                    new_patch_comment = "Keypatch modified this from:\n  {0}{1}".format('\n  '.join(orig_asm), nop_comment)
                else:
                    new_patch_comment = "\nKeypatch modified this from:\n  {0}{1}".format('\n  '.join(orig_asm), nop_comment)

                new_comment = "{0}{1}".format(orig_comment, new_patch_comment)
                set_comment(address, new_comment)

            if padding_len == 0:
                print("Keypatch: successfully patched {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}]".format(plen,
                                        address, to_hexstr(p_orig_data), to_hexstr(patch_data)))
            else:
                print("Keypatch: successfully patched {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}], with {4} byte(s) NOP padded".format(plen,
                                        address, to_hexstr(p_orig_data), to_hexstr(patch_data), padding_len))
            # save this patching for future "undo"
            patch_info.append((address, assembly, p_orig_data, new_patch_comment))
        else:   # we are reverting
            if patch_comment:
                # clean previous IDA comment by replacing it with ''
                new_comment = orig_comment.replace(patch_comment, '')
                set_comment(address, new_comment)

            print("Keypatch: successfully reverted {0:d} byte(s) at 0x{1:X} from [{2}] to [{3}]".format(plen,
                                        address, to_hexstr(p_orig_data), to_hexstr(patch_data)))

        return plen

    # fill a range of code [addr_begin, addr_end].
    # return the length of patched area
    # on failure, return 0 = wrong input, -1 = failed to patch
    def fill_code(self, addr_begin, addr_end, assembly, syntax, padding, save_origcode, orig_asm=None):
        # treat input as assembly code first
        (encoding, _) =  self.assemble(assembly, addr_begin, syntax=syntax)

        if encoding is None:
            # input might be a hexcode string. try to convert it to raw bytes
            encoding = convert_hexstr(assembly)

        if encoding is None:
            # invalid input: this is neither assembly nor hexcode string
            return 0

        # save original assembly code before overwritting them
        orig_asm = self.ida_get_disasm_range(addr_begin, addr_end)

        # save original comment at addr_begin
        # TODO: save comments in this range, but how to interleave them?
        orig_comment = get_comment(addr_begin)
        if orig_comment is None:
            orig_comment = ''

        patch_data = ""
        assembly_new = []
        size = addr_end - addr_begin
        # calculate filling data
        encode_chr = ''.join(chr(c) for c in encoding)
        while True:
            if len(patch_data) + len(encode_chr) <= size:
                patch_data = patch_data + encode_chr
                assembly_new += [assembly.strip()]
            else:
                break

        # for now, only support NOP padding on Intel CPU
        if padding and self.arch == KS_ARCH_X86:
            for i in range(size -len(patch_data)):
                assembly_new += ["nop"]
            patch_data = patch_data.ljust(size, X86_NOP)

        (plen, p_orig_data) = self.patch(addr_begin, patch_data, len(patch_data))
        if plen is None:
            # failed to patch
            return -1

        new_patch_comment = ''
        # append original instruction to comments
        if save_origcode is True:
            if orig_comment == '':
                new_patch_comment = "Keypatch filled range [0x{0:X}:0x{1:X}] ({2} bytes), replaced:\n  {3}".format(addr_begin, addr_end - 1, addr_end - addr_begin, '\n  '.join(orig_asm))
            else:
                new_patch_comment = "\nKeypatch filled range [0x{0:X}:0x{1:X}] ({2} bytes), replaced:\n  {3}".format(addr_begin, addr_end - 1, addr_end - addr_begin, '\n  '.join(orig_asm))

            new_comment = "{0}{1}".format(orig_comment, new_patch_comment)
            set_comment(addr_begin, new_comment)

        print("Keypatch: successfully filled range [0x{0:X}:0x{1:X}] ({2} bytes) with \"{3}\", replaced \"{4}\"".format(
                    addr_begin, addr_end - 1, addr_end - addr_begin, assembly, '; '.join(orig_asm)))

        # save this modification for future "undo"
        patch_info.append((addr_begin, '\n  '.join(assembly_new), p_orig_data, new_patch_comment))

        return plen


    ### Form helper functions
    @staticmethod
    def dict_to_ordered_list(dictionary):
        l = sorted(list(dictionary.items()), key=lambda t: t[0], reverse=False)
        keys = [i[0] for i in l]
        values = [i[1] for i in l]

        return (keys, values)

    def get_value_by_idx(self, dictionary, idx, default=None):
        (keys, values) = self.dict_to_ordered_list(dictionary)

        try:
            val = values[idx]
        except IndexError:
            val = default

        return val

    def find_idx_by_value(self, dictionary, value, default=None):
        (keys, values) = self.dict_to_ordered_list(dictionary)

        try:
            idx = values.index(value)
        except:
            idx = default

        return idx

    def get_arch_by_idx(self, idx):
        return self.get_value_by_idx(self.arch_lists, idx)

    def find_arch_idx(self, arch, mode):
        return self.find_idx_by_value(self.arch_lists, (arch, mode))

    def get_syntax_by_idx(self, idx):
        return self.get_value_by_idx(self.syntax_lists, idx, self.syntax)

    def find_syntax_idx(self, syntax):
        return self.find_idx_by_value(self.syntax_lists, syntax)
    ### /Form helper functions






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
        
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

        self.current_func_name = idaapi.get_func_name(idaapi.get_screen_ea())
        self.current_func = ida_funcs.get_func(idaapi.get_screen_ea())
        self.angr_prj = angr.Project(idaapi.get_input_file_path(), load_options={'auto_load_libs':False}) 

        self.kp_asm = Keypatch_Asm()
        
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

    def fix_function_end(self, new_end_ea):
        logging.debug("Patching function end: {}".format(hex(new_end_ea)))
        #self.current_func.end_ea = new_end_ea
        ida_auto.auto_wait()
        func_ea = idc.next_head(idc.prev_head(new_end_ea))
        ida_auto.auto_wait()
        res = ida_funcs.set_func_end(func_ea, new_end_ea)
        logging.debug("set end result: {}".format(res))
        ida_funcs.reanalyze_function(self.current_func)
        ida_auto.auto_wait()

    def fix_jmp_inst_on_opaque_predicate(self, opaque_addr):
        if 'j' in idc.print_insn_mnem(opaque_addr):
            if idc.generate_disasm_line(opaque_addr, 0)[-2:-1] == "+" and idc.generate_disasm_line(opaque_addr,0)[-1:].isdigit():
                logging.debug("Broken Instruction: {}".format(hex(opaque_addr)))
                code_addr = self.get_the_location_of_the_jump(opaque_addr)
                fix_addr = code_addr -1 
                idc.del_items(fix_addr,1)
                idc.create_insn(code_addr)

    def fix_opaque_predicate(self, opaque_addr, opaque_type_num):
        if opaque_type_num == OpaqueAnalyzeRetValues.ALWAYS_JMP:
            jmp_location_str = hex(self.get_the_location_of_the_jump(opaque_addr))
            raw_assembly = "jmp " + jmp_location_str
            self.kp_asm.patch_code(opaque_addr, raw_assembly, KS_ARCH_X86, 1, "Patched")

    def fix_undef_code_places(self, predicate_ea):
        idc.create_insn(predicate_ea)
        ida_auto.auto_wait
        ida_funcs.reanalyze_function(self.current_func)
        ida_auto.auto_wait()

    def patch_opaque_predicates_loop(self):
        done = False
        fc = idaapi.FlowChart(self.current_func)
        counter = 0
        for block in fc:
            print("======================================================================")
            print("======================================================================")
            opaque_addr = idc.prev_head(block.end_ea)
            if (self.check_conditional_x86_64(idc.prev_head(block.end_ea))):
                print("Found conditional jump address in: ", hex(idc.prev_head(block.end_ea)))
                analyze_res = self.analyze_opaque(idc.prev_head(block.end_ea))
                if analyze_res != OpaqueAnalyzeRetValues.NOT_OPAQUE:
                    print("Opaque conditional jump address is: ", hex(idc.prev_head(block.end_ea)))
                    if analyze_res == OpaqueAnalyzeRetValues.ALWAYS_JMP:
                        self.fix_jmp_inst_on_opaque_predicate(opaque_addr)
                        self.fix_function_end(block.end_ea)
                        logging.debug("Opaque type is ALWAYS JMP")
                    elif analyze_res == OpaqueAnalyzeRetValues.NEVER_JMP:
                        logging.debug("Opaque type is NEVER JMP")
                        break;
                    else:
                        while(self.analyze_opaque(idc.prev_head(block.end_ea)) == OpaqueAnalyzeRetValues.ERROR):
                            pass
                        
                    self.fix_opaque_predicate(opaque_addr, analyze_res)


                    print("Tomerminatored the opaque.")
                    done = STOP_AFTER_ITERATION
            else:
                print("Block appened, conditional jump not found.")  

            print("Iteration Done.")
            if done:
                break
            counter += 1
            if counter == DEPTH:
                logging.debug("MAX DEPTH ACHIEVED, STOPPING.")
                break

    def patch_opaque_predicates(self):
        #block_bytes does not include the instruction after the jmp BUT, block.end - block.start does.
        done = False
        fc = idaapi.FlowChart(self.current_func)
        counter = 0
        for block in fc:
            print("======================================================================")
            print("======================================================================")
            opaque_addr = idc.prev_head(block.end_ea)
            if (self.check_conditional_x86_64(idc.prev_head(block.end_ea))):
                print("Found conditional jump address in: ", hex(idc.prev_head(block.end_ea)))
                analyze_res = self.analyze_opaque(idc.prev_head(block.end_ea))
                if analyze_res != OpaqueAnalyzeRetValues.NOT_OPAQUE:
                    print("Opaque conditional jump address is: ", hex(idc.prev_head(block.end_ea)))
                    if analyze_res == OpaqueAnalyzeRetValues.ALWAYS_JMP:
                        self.fix_jmp_inst_on_opaque_predicate(opaque_addr)
                        self.fix_function_end(block.end_ea)
                        logging.debug("Opaque type is ALWAYS JMP")
                    elif analyze_res == OpaqueAnalyzeRetValues.NEVER_JMP:
                        logging.debug("Opaque type is NEVER JMP")
                        break;
                    else:
                        while(self.analyze_opaque(idc.prev_head(block.end_ea)) == OpaqueAnalyzeRetValues.ERROR):
                            pass
                        
                    self.fix_opaque_predicate(opaque_addr, analyze_res)


                    print("Tomerminatored the opaque.")
                    done = STOP_AFTER_ITERATION
            else:
                print("Block appened, conditional jump not found.")  

            print("Iteration Done.")
            if done:
                break
            counter += 1
            if counter == DEPTH:
                logging.debug("MAX DEPTH ACHIEVED, STOPPING.")
                break
    
    def analyze_opaque(self, predicate_ea):
        s = self.angr_prj.factory.blank_state(addr=self.current_func.start_ea)
        #TODO: think about exploration techniques, do it like this tomer:
        # simgr.use_technique(angr.exploration_techniques.Symbion(find=[address], memory_concretize=memory_concretize,
                                                            #register_concretize=register_concretize, timeout=timeout))
        #exploration = simgr.run()
        ###3
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

        simMgr.explore(find=[idaapi.next_head(predicate_ea, predicate_ea+0x100), idc.next_addr(predicate_ea)], avoid=predicate_jmp_address_operand)
        if '0xffffffffffffffff' in hex(idaapi.next_head(predicate_ea, predicate_ea+0x10)):
            #create code at predicate, anaylze function, return not opaque
            logging.warning("some code needs to be defined manually.")
            self.fix_undef_code_places(predicate_ea)
            return OpaqueAnalyzeRetValues.ERROR
        
        logging.debug("find: {}".format(hex(idaapi.next_head(predicate_ea, predicate_ea+0x100))))
        logging.debug("avoid: {}".format(hex(predicate_jmp_address_operand)))
        logging.debug("SimMgr: {}".format(simMgr))

        total_stashes_len = 0

        if len(simMgr.found) == 0 and len(simMgr.unconstrained) == 0:
            logging.debug("len(simMgr.found) == 0 and len(simMgr.unconstrained) == 0")
            return OpaqueAnalyzeRetValues.ALWAYS_JMP
        else:
            for stash in simMgr.stashes:
                total_stashes_len += len(stash)
            total_stashes_len -= len(simMgr.found)
            if total_stashes_len == 0:
                logging.debug("len(simMgr.found) != 0 or len(simMgr.unconstrained) != 0, total_stashes_len = len(found)")
                return OpaqueAnalyzeRetValues.NEVER_JMP
            
        total_stashes_len = 0

        for stash in simMgr.stashes:
            total_stashes_len += len(stash)
        total_stashes_len -= len(simMgr.avoid)
        if total_stashes_len == 0:
            logging.debug("total_stashes_len = len(avoid)")
            return OpaqueAnalyzeRetValues.ALWAYS_JMP
        
        return OpaqueAnalyzeRetValues.NOT_OPAQUE
    
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
        self.patch_opaque_predicates()
        
        
        
            

    
         
            
                
        


    
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