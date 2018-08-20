import sys
import copy

import ida_idaapi
import ida_idp
import ida_ua
import ida_bytes
import ida_xref
import ida_offset
import ida_problems
import ida_lines
import ida_segment

from ida_idp import CF_USE1, CF_USE2, CF_CHG1, CF_CHG2, CF_STOP, CF_JUMP, CF_SHFT, CF_CALL

# enum definitions from VM engine idb
# enum_vm_size
SIZE_BYTE = 0
SIZE_WORD = 1
SIZE_DWORD = 2
# enum_vm_type
TYPE_REG_VAL = 0
TYPE_REG_PTR = 1
TYPE_IMM_VAL = 2 
TYPE_DATA_OFF = 3
# enum_vm_cmp
CMP_EQUAL = 0
CMP_NOT_EQUAL = 1
CMP_LESS_THAN = 2
# enum_vm_arith
ARITH_XOR = 0
ARITH_ADD = 1
ARITH_SUB = 2
ARITH_SHL = 3
ARITH_SHR = 4
ARITH_ROL = 5
ARITH_ROR = 6
ARITH_MOD = 7

# ----------------------------------------------------------------------
class eset_drv_vm_processor_t(ida_idp.processor_t):
    """
    Processor module classes must derive from ida_idp.processor_t
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8fff

    # Processor features
    flag = ida_idp.PRN_HEX | ida_idp.PR_RNAMESOK 

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['eset_vm']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['ESET Crackme driver VM processor']

    # size of a segment register in bytes
    segreg_size = 0

    # Array of instructions
    instruc = [
      {'name': '',      'feature': 0},  # placeholder for "not an instruction"
      {'name': 'hlt',   'feature': CF_STOP,   'cmt': "halt CPU"},
      {'name': 'mov',   'feature': CF_USE1 | CF_USE2 | CF_CHG1,   'cmt': "move"},      
      {'name': 'ncall', 'feature': CF_USE1 | CF_CALL,   'cmt': "call native function"},
      {'name': 'lcall', 'feature': CF_USE1 | CF_USE2 | CF_CALL,   'cmt': "call library function"},
      {'name': 'push',  'feature': CF_USE1,   'cmt': "push to stack"},
      {'name': 'pop',   'feature': CF_USE1 | CF_CHG1,   'cmt': "pop from stack"},      
      {'name': 'cmpeq', 'feature': CF_USE1 | CF_USE2,   'cmt': "compare #0 (equal)"},
      {'name': 'cmpne', 'feature': CF_USE1 | CF_USE2,   'cmt': "compare #1 (not equal)"},
      {'name': 'cmpb',  'feature': CF_USE1 | CF_USE2,   'cmt': "compare #2 (less than)"},
      {'name': 'jmp',   'feature': CF_USE1 | CF_JUMP | CF_STOP,   'cmt': "jump #0 (unconditional)"},
      {'name': 'cjmp',  'feature': CF_USE1 | CF_JUMP,   'cmt': "jump #1 (conditional)"},
      {'name': 'call',  'feature': CF_USE1 | CF_CALL,   'cmt': "call VM function"},
      {'name': 'ret',   'feature': 0,   'cmt': "return"},
      {'name': 'xor',   'feature': CF_USE1 | CF_USE2 | CF_CHG1,   'cmt': "arithmetic operation #0 (xor)"},
      {'name': 'add',   'feature': CF_USE1 | CF_USE2 | CF_CHG1,   'cmt': "arithmetic operation #1 (add)"},
      {'name': 'sub',   'feature': CF_USE1 | CF_USE2 | CF_CHG1,   'cmt': "arithmetic operation #2 (sub)"},
      {'name': 'shl',   'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT,   'cmt': "arithmetic operation #3 (shift left)"},
      {'name': 'shr',   'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT,   'cmt': "arithmetic operation #4 (shift right)"},
      {'name': 'rol',   'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT,   'cmt': "arithmetic operation #5 (rotation left)"},
      {'name': 'ror',   'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_SHFT,   'cmt': "arithmetic operation #6 (rotation right)"},
      {'name': 'mod',   'feature': CF_USE1 | CF_USE2 | CF_CHG1,   'cmt': "arithmetic operation #7 (modulo)"},
      {'name': 'alloc', 'feature': CF_USE1,   'cmt': "allocate buffer"},
      {'name': 'free',  'feature': CF_USE1,   'cmt': "free buffer"},
      {'name': 'loadVM','feature': CF_USE1 | CF_USE2,   'cmt': "load another VM"},
      {'name': 'nop',   'feature': 0,   'cmt': "nop"},      
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    # tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    #real_width = (0, 7, 0, 0)


    # only one assembler is supported
    assembler = {
        # flag (mostly for the format)
        'flag' : ida_idp.ASH_HEXF3 | ida_idp.ASD_DECF0 | ida_idp.ASO_OCTF5 | ida_idp.ASB_BINF0 | ida_idp.AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        #'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "ESET Crackme driver VM assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': [".esetvm"],

        # array of unsupported instructions (array of insn.itype) (optional)
        #'badworks': [],

        # org directive
        'origin': ".org",

        # end directive
        'end': ".end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".char",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        # 'a_qword': "dq",

        # float;  4bytes; remove if not allowed
        #'a_float': ".float",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': ".space %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        #'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': ".def",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "",

        # "extrn"  name keyword
        'a_extrn': ".ref",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': ".align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # the include directive (format string) (optional)
        'a_include_fmt': '.include "%s"',
    } # Assembler


    # ----------------------------------------------------------------------
    # The following callbacks are optional
    #

    #def notify_newprc(self, nproc):
    #    """
    #    Before changing proccesor type
    #    nproc - processor number in the array of processor names
    #    return 1-ok,0-prohibit
    #    """
    #    return 1

    #def notify_assemble(self, ea, cs, ip, use32, line):
    #    """
    #    Assemble an instruction
    #     (make sure that ida_idp.PR_ASSEMBLE flag is set in the processor flags)
    #     (display a warning if an error occurs)
    #     args:
    #       ea -  linear address of instruction
    #       cs -  cs of instruction
    #       ip -  ip of instruction
    #       use32 - is 32bit segment?
    #       line - line to assemble
    #    returns the opcode string
    #    """
    #    pass

    def notify_get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
             4 bytes for 32-bit function
             2 bytes otherwise
        """
        return 2

    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt']

    # ----------------------------------------------------------------------
    def notify_is_sane_insn(self, insn, no_crefs):
        """
        is the instruction sane for the current file type?
        args: no_crefs
        1: the instruction has no code refs to it.
           ida just tries to convert unexplored bytes
           to an instruction (but there is no other
           reason to convert them into an instruction)
        0: the instruction is created because
           of some coderef, user request or another
           weighty reason.
        The instruction is in 'insn'
        returns: 1-ok, <=0-no, the instruction isn't
        likely to appear in the program
        """
        #w = ida_bytes.get_wide_word(insn.ea)
        #if w == 0 or w == 0xFFFF:
        #  return 0
        #return 1
        return -1

    # ----------------------------------------------------------------------
    def handle_operand(self, insn, op, isRead):
      flags     = ida_bytes.get_flags(insn.ea)
      is_offs   = ida_bytes.is_off(flags, op.n)
      dref_flag = ida_xref.dr_R if isRead else ida_xref.dr_W
      def_arg   = ida_bytes.is_defarg(flags, op.n)
      optype    = op.type

      itype = insn.itype
      # create code xrefs
      if optype == ida_ua.o_imm:        
        makeoff = False
        if itype in [self.itype_ncall, self.itype_call]:
          insn.add_cref(op.value, op.offb, ida_xref.fl_CN)
          makeoff = True
        #elif itype == self.itype_mov: # e.g., mov #addr, PC
        #  insn.add_cref(op.value, op.offb, ida_xref.fl_JN)
        #  makeoff = True        
        if makeoff and not def_arg:
          otype = ida_offset.get_default_reftype(insn.ea)
          ida_offset.op_offset(insn.ea, op.n, otype, ida_idaapi.BADADDR, insn.cs)
          is_offs = True
        if is_offs:
          insn.add_off_drefs(op, ida_xref.dr_O, 0)
      elif optype == ida_ua.o_near:
        if insn.itype in [self.itype_ncall, self.itype_call]:
            fl = ida_xref.fl_CN
        else:
            fl = ida_xref.fl_JN
        insn.add_cref(op.addr, op.offb, fl)
      # create data xrefs
      elif optype == ida_ua.o_mem:
        insn.create_op_data(op.addr, op.offb, op.dtype)
        insn.add_dref(op.addr, op.offb, dref_flag)
        '''
        ds = ida_segment.get_segm_by_name('VM_DATA')        
        start = ds.start_ea
        insn.create_op_data(start + op.addr, op.offb, op.dtype)
        insn.add_dref(start + op.addr, op.offb, dref_flag)
        '''

    # ----------------------------------------------------------------------
    # The following callbacks are mandatory
    #
    def notify_emu(self, insn):
      """
      Emulate instruction, create cross-references, plan to analyze
      subsequent instructions, modify flags etc. Upon entrance to this function
      all information about the instruction is in 'insn' structure.
      If zero is returned, the kernel will delete the instruction.
      """
      aux = self.get_auxpref(insn)
      Feature = insn.get_canon_feature()

      if Feature & CF_USE1:
        self.handle_operand(insn, insn.Op1, 1)
      if Feature & CF_CHG1:
        self.handle_operand(insn, insn.Op1, 0)
      if Feature & CF_USE2:
        self.handle_operand(insn, insn.Op2, 1)
      if Feature & CF_CHG2:
        self.handle_operand(insn, insn.Op2, 0)
      if Feature & CF_JUMP:
        ida_problems.remember_problem(ida_problems.PR_JUMP, insn.ea)

      # is it an unconditional jump?
      uncond_jmp = insn.itype in [self.itype_jmp]

      # add flow
      flow = (Feature & CF_STOP == 0) and not uncond_jmp
      if flow:
        insn.add_cref(insn.ea + insn.size, 0, ida_xref.fl_F)

      return 1

    # ----------------------------------------------------------------------
    def notify_out_operand(self, ctx, op):
      """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by the emu() function.
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
      """
      optype = op.type
      dtype = op.dtype
      signed = 0

      if optype == ida_ua.o_reg:
        if dtype == ida_ua.dt_byte:          
          #ctx.out_register('b')
          ctx.out_keyword('byte ')
        elif dtype == ida_ua.dt_word:          
          #ctx.out_register('w')
          ctx.out_keyword('word ')
        ctx.out_register(self.reg_names[op.reg])
      elif optype == ida_ua.o_phrase:
        if dtype == ida_ua.dt_dword:          
          ctx.out_keyword('dword ptr ')
        elif dtype == ida_ua.dt_byte:
          ctx.out_keyword('byte ptr ')
        elif dtype == ida_ua.dt_word:          
          ctx.out_keyword('word ptr ')
        ctx.out_symbol('[')
        ctx.out_register(self.reg_names[op.reg])
        ctx.out_symbol(']')
      elif optype == ida_ua.o_imm:
        ctx.out_symbol('#')
        ctx.out_value(op, ida_ua.OOFW_IMM | signed )
      elif optype in [ida_ua.o_near, ida_ua.o_mem]:
        r = ctx.out_name_expr(op, op.addr, ida_idaapi.BADADDR)
        if not r:
          ctx.out_tagon(ida_lines.COLOR_ERROR)
          ctx.out_long(op.addr, 16)
          ctx.out_tagoff(ida_lines.COLOR_ERROR)
          ida_problems.remember_problem(ida_problems.PR_NONAME, ctx.insn.ea)
      else:
        return False
        
      # for Op2 of mov instruction
      #if op.specflag1:
      #  ctx.out_keyword(' as ptr')

      return True

    # ----------------------------------------------------------------------
    def notify_out_insn(self, ctx):
        """
        Generate text representation of an instruction in 'ctx.insn' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by emu() function.
        Returns: nothing
        """
        postfix = ""

        ctx.out_mnemonic()

        # output first operand
        # kernel will call outop()
        if ctx.insn.Op1.type != ida_ua.o_void:
            ctx.out_one_operand(0)

        # output the rest of operands separated by commas
        for i in xrange(1, 3):
            if ctx.insn[i].type == ida_ua.o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt() # generate comment at the next call to MakeLine()
        ctx.flush_outbuf()

    def fill_reg(self, op, dtype, regno):
      op.type = ida_ua.o_reg
      op.dtype = dtype
      op.reg = regno
      #op.specflag1 = 0     

    def fill_phrase(self, op, dtype, regno):
      op.type = ida_ua.o_phrase
      op.dtype = dtype
      op.phrase = regno
      #op.specflag1 = 0     

    def fill_imm(self, op, dtype, val):
      op.type = ida_ua.o_imm
      op.dtype = dtype
      op.value = val
      #op.specflag1 = 0     

    def fill_near(self, op, dtype, addr):
      op.type = ida_ua.o_near
      op.dtype = dtype
      op.addr = addr
      #op.specflag1 = 0     

    def fill_mem(self, op, dtype, addr):
      op.type = ida_ua.o_mem
      op.dtype = dtype
      #op.addr = addr
      # add data segment base addr
      ds = ida_segment.get_segm_by_name('VM_DATA')        
      op.addr = ds.start_ea + addr
      #op.specflag1 = 0     

    def get_next_bytes(self, insn, dtype):
      if dtype == ida_ua.dt_byte:
        return insn.get_next_byte()
      elif dtype == ida_ua.dt_word:
        return insn.get_next_word()
      elif dtype == ida_ua.dt_dword:
        return insn.get_next_dword()

    def set_operand(self, insn, op, type_, regno, dtype):
      # check dtype
      if dtype > 2:
        return -1
      
      # IDA data type enum is matched with enum_vm_size of the idb
      if type_ == TYPE_REG_VAL:
        self.fill_reg(op, dtype, regno)
      elif type_ == TYPE_REG_PTR:
        self.fill_phrase(op, dtype, regno)
      elif type_ == TYPE_IMM_VAL:
        val = self.get_next_bytes(insn, dtype)
        self.fill_imm(op, dtype, val)
      elif type_ == TYPE_DATA_OFF:
        dt_off = insn.get_next_dword()
        self.fill_mem(op, dtype, dt_off)
      return 0
    
    # ----------------------------------------------------------------------
    def notify_ana(self, insn):
      """
      Decodes an instruction into 'insn'.
      Returns: insn.size (=the size of the decoded instruction) or zero
      """      
      opc = insn.get_next_byte()        
      # cmp (0x6), jmp (0x7),  arithmetic operation (0xa): multiple instructions
      # 0xe - 0xff: nop
      if opc > 0xd:
        insn.itype = self.itype_nop
      elif opc > 0xa:
        insn.itype = self.itype_hlt + opc + 2 + 1 + 7
      elif opc > 7:
        insn.itype = self.itype_hlt + opc + 2 + 1
      elif opc > 6:
        insn.itype = self.itype_hlt + opc + 2
      else:
        insn.itype = self.itype_hlt + opc

      if insn.itype not in [self.itype_hlt, self.itype_ret, self.itype_nop]:
        if insn.itype in [self.itype_call, self.itype_jmp]:
          if insn.itype == self.itype_jmp:
            cflag = insn.get_next_byte() # check conditional flag
            if cflag > 1:
              return 0 # invalid flag value
            insn.itype += cflag
          addr = insn.get_next_dword()
          self.fill_near(insn.Op1, ida_ua.dt_dword, addr)
        elif insn.itype == self.itype_pop:
          regno = insn.get_next_byte() & 0xf
          self.fill_reg(insn.Op1, ida_ua.dt_dword,  regno)
        elif insn.itype in [self.itype_push, self.itype_alloc, self.itype_free, self.itype_ncall]:
          b1 = insn.get_next_byte()
          dtype = ida_ua.dt_dword if insn.itype == self.itype_ncall else b1 >> 6
          if self.set_operand(insn, insn.Op1, (b1 >> 4) & 3, b1 & 0xf, dtype):
            return 0 # invalid dtype
        elif insn.itype in [self.itype_lcall, self.itype_loadVM]:
          b1 = insn.get_next_byte()
          b2 = insn.get_next_byte()
          if self.set_operand(insn, insn.Op1, b2 & 3, b1 & 0xf, ida_ua.dt_dword):
            return 0 # invalid dtype
          dtype = ida_ua.dt_dword if insn.itype == self.itype_lcall else (b2 >> 4) & 3
          if self.set_operand(insn, insn.Op2, (b2 >> 2) & 3, b1 >> 4, dtype):
            return 0 # invalid dtype
        elif insn.itype == self.itype_mov:
          b1 = insn.get_next_byte()
          b2 = insn.get_next_byte()            
          dtype = (b2 >> 4) & 3
          if self.set_operand(insn, insn.Op2, b2 & 3, b1 >> 4, dtype):
            return 0 # invalid dtype
          dst_regno = b1 & 0xf
          if (b2 >> 2) & 3: # used as pointer
            self.fill_phrase(insn.Op1, dtype, dst_regno)
            #insn.Op2.specflag1 = 1
          else:
            self.fill_reg(insn.Op1, dtype, dst_regno)
        elif insn.itype in [self.itype_cmpeq, self.itype_xor]:
          b1 = insn.get_next_byte()
          b2 = insn.get_next_byte()
          self.fill_reg(insn.Op1, ida_ua.dt_dword, b1 & 0xf)            
          if self.set_operand(insn, insn.Op2, b2 & 3, b1 >> 4, (b2 >> 2) & 3):
            return 0 # invalid dtype
          # update itype
          itype_idx = (b2 >> 4) & 7
          if insn.itype == self.itype_cmpeq and itype_idx > 2:
            return 0 # invalid cmp operation
          else:
            insn.itype += itype_idx                          

      # Return decoded instruction size or zero
      return insn.size if insn.itype != self.itype_null else 0

    # ----------------------------------------------------------------------
    def init_instructions(self):
        Instructions = []
        i = 0
        for x in self.instruc:
            if x['name'] != '':
                setattr(self, 'itype_' + x['name'], i)
            else:
                setattr(self, 'itype_null', i)
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = len(self.instruc) + 1

    # ----------------------------------------------------------------------
    def init_registers(self):
      """
      This function parses the register table and creates corresponding ireg_XXX constants
      """

      # Registers definition
      self.reg_names = [
        # General purpose registers
        "r0", 
        "r1", 
        "r2", 
        "r3", 
        "r4", 
        "r5",        
        # SP
        "r6",
        # VM pointer
        "r7",        
        # VM size
        "r8",
        # ntoskrnl_base
        "r9",
        # arg registers
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        # Fake segment registers
        "CS",
        "DS",
      ]

      # Create the ireg_XXXX constants
      for i in xrange(len(self.reg_names)):
        setattr(self, 'ireg_' + self.reg_names[i], i)

      # Segment register information (use virtual CS and DS registers if your
      # processor doesn't have segment registers):
      self.reg_first_sreg = self.ireg_CS
      self.reg_last_sreg  = self.ireg_DS

      # number of CS register
      self.reg_code_sreg = self.ireg_CS

      # number of DS register
      self.reg_data_sreg = self.ireg_DS

    # ----------------------------------------------------------------------
    def __init__(self):
        ida_idp.processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from ida_idp.processor_t
def PROCESSOR_ENTRY():
    return eset_drv_vm_processor_t()
