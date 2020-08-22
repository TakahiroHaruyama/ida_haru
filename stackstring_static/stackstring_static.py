# stackstring_static.py - IDAPython script statically-recovering strings constructed in stack
# Takahiro Haruyama (@cci_forensics)
# Note: the script internally renames the stack variables so manually-renamed info will be lost

import struct

from ida_ua import *
from ida_allins import *
from idautils import *
#from ida_funcs import *
from idc import *
import ida_kernwin

def extract_unicode(data):
    pat = re.compile(r'^(?:[\x20-\x7E][\x00]){2,}')
    return list(set([w.decode('utf-16le') for w in pat.findall(data)]))

def extract_ascii(data):
    pat = re.compile(r'^(?:[\x20-\x7E]){2,}')
    return list(set([w.decode('ascii') for w in pat.findall(data)]))

class StackString(object):

    def __init__ (self, start, end, debug, do_xor, static_xor_key):
        self.start = start
        self.end = end
        self.debug = debug
        self.do_xor = do_xor
        self.regs_w_value = {}
        self.stack_chars = {}
        self.xor_vars = {}
        self.stack_imm = None
        self.static_xor_key = static_xor_key

    def rename_vars(self):
        stack = GetFrame(self.start)
        stack_size = GetStrucSize(stack)
        args_and_ret_size = stack_size - GetFrameLvarSize(self.start)

        for offset, name, size in StructMembers(stack):
            postfix = stack_size - offset - args_and_ret_size
            if postfix >= 0:
                self.stack_chars[postfix] = 0 # initialize vars
                if name.find('var_') == -1:
                    #postfix = stack_size - offset - args_and_ret_size
                    SetMemberName(stack, offset, 'var_{:X}'.format(postfix))

    def store_bytes_to_reg(self, r, b):
        if r == procregs.sp.reg or r == procregs.bp.reg:
            return
        elif procregs.xmm0.reg <= r and r <= procregs.xmm15.reg:
            self.dprint('reg enum {} = {}'.format(r, repr(b)))
            self.regs_w_value[r] = b
        #if (0x1f < b and b < 0x7f) or b == 0:
        elif 0 <= b and b < 0x100:
            self.dprint('reg enum {} = {:#x}'.format(r, b))
            self.regs_w_value[r] = b
            if procregs.ax.reg <= r and r <= procregs.bx.reg:
                # ax = eax = rax = 0 but al = 16 / ah = 20
                self.regs_w_value[r+16] = b
                self.regs_w_value[r+20] = b

    def store_reg_to_reg(self, dst, src):
        if dst == procregs.sp.reg or dst == procregs.bp.reg:
            return
        if src in self.regs_w_value:
            self.dprint('reg enum {} = reg enum {} ({:#x})'.format(dst, src, self.regs_w_value[src]))
            self.regs_w_value[dst] = self.regs_w_value[src]

    def parse_and_get_var_hex(self, vstr):
        # e.g., mov     [ebp+68h+var_18+0Ch], 61h
        var_off = vstr.split('_')[1][:-1].rstrip('h').split('+') # '18+0C'
        if len(var_off) == 2:
            res = int(var_off[0], 16) - int(var_off[1], 16)
        else:
            res = int(var_off[0], 16)

        # handle base+index registers (e.g., mov     [rsp+rax+258h+var_C0], 6Fh)
        try:
            the_reg = eval('procregs.{}.reg'.format(vstr.split('+')[1]))
            if the_reg in self.regs_w_value:
                res = res - self.regs_w_value[the_reg]
        except SyntaxError:
            pass
        return res
        #return eval('0x{}'.format(var_num)) # '18-4' = 20

    def store_byte_to_var(self, v, b):
        #if (0x1f < b and b < 0x7f) or b == 0:
        if 0 <= b and b < 0x100:
            #'''
            try:
                if self.stack_chars[v] != 0: # should not be overwritten
                    return
            except KeyError: # when not initialized (to handle the bytes one by one)
                #print 'keyerror var_{:X} = {}'.format(v, b)
                pass
            #'''
            self.dprint('var_{:X} = {:#x}'.format(v, b))
            self.stack_chars[v] = b

    def store_bytes_to_vars(self, v, bs):
        if isinstance(bs, str): # binary sequence for xmm registers
            blist = [ord(x) for x in bs]
        else: # int or long
            blist = self.int_to_bytes_list(bs)

        for i, b in enumerate(blist):
            #self.store_byte_to_var(v - i, blist[i])
            self.store_byte_to_var(v - i, b)

    def store_key_to_name(self, v, b):
        #if (0x1f < b and b < 0x7f) or b == 0:
        if 0 <= b and b < 0x100:
            self.dprint('{} ^ {:#x}'.format(v, b))
            self.xor_vars[v] = b

    def int_to_bytes_list(self, v):
        if v == 0:
            return [0]
        res = []
        while(1):
            b = v & 0xff
            v = v >> 8
            #if 0x1f < b and b < 0x7f or b == 0:
            if 0 <= b and b < 0x100:
                res.append(b)
                #if v == 0 and (len(res) == 1 or len(res) == 2 or len(res) == 4 or len(res) == 8):
                if v == 0 and (len(res) == 2 or len(res) == 4 or len(res) == 8):
                    # e.g., mov     [rsp+3A8h+var_290], 6E0069h
                    return res
            else:
                break
        return []

    def store_byte_to_stack(self, b):
        if 0 <= b and b < 0x100:
            self.stack_imm = b

    def dprint(self, s):
        if self.debug:
            print s

    def traverse(self):
        print '----------------------------------------------'
        print '{:#x}:'.format(self.start)

        # replace analyzed names with 'var_*' in stack for calculation
        try:
            self.rename_vars()
        #except TypeError: # caused by StructMembers()
        except:
            return

        for head in Heads(self.start, self.end):
            self.dprint('{:#x}'.format(head))
            insn = insn_t()
            inslen = decode_insn(insn, head)

            if insn.itype == NN_mov or insn.itype == NN_movsxd:
                if insn.Op1.type == o_reg and insn.Op2.type == o_imm: # e.g., mov     cl/cx/ecx, 6Ch
                    self.store_bytes_to_reg(insn.Op1.reg, insn.Op2.value)

                elif insn.Op1.type == o_reg and insn.Op2.type == o_reg: # e.g., mov     cl/cx/ecx, al/ax/eax
                    self.store_reg_to_reg(insn.Op1.reg, insn.Op2.reg)

                elif insn.Op1.type == o_reg and insn.Op2.dtype == dt_byte and insn.Op2.type == o_mem: # e.g., mov     al, ds:byte_100040F8
                    self.store_bytes_to_reg(insn.Op1.reg, Byte(insn.Op2.addr))

                elif insn.Op1.type == o_displ and GetOpnd(head, 0).find('var_') != -1 and insn.Op2.type == o_reg and (insn.Op2.dtype == dt_byte or insn.Op2.dtype == dt_word): # e.g., mov     [esp+180h+var_127], cl
                #elif insn.Op1.type == o_displ and GetOpnd(head, 0).find('var_') != -1 and insn.Op2.type == o_reg: # e.g., mov [rsp+258h+var_1F0], eax (index register)
                    try:
                        var_hex = self.parse_and_get_var_hex(GetOpnd(head, 0))
                    except (AttributeError, IndexError, ValueError): # e.g., var_10.S_un
                        continue
                    if insn.Op2.reg in self.regs_w_value:
                        self.store_bytes_to_vars(var_hex, self.regs_w_value[insn.Op2.reg])

                elif insn.Op1.type == o_displ and insn.Op2.type == o_imm: # e.g., mov     [esp+188h+var_130], 6Ah/2E32h/3362646Fh
                    #print 'o_displ = o_imm'
                    try:
                        var_hex = self.parse_and_get_var_hex(GetOpnd(head, 0))
                    except (AttributeError, IndexError, ValueError): # e.g., var_10.S_un
                        continue
                    self.store_bytes_to_vars(var_hex, insn.Op2.value)
                elif insn.Op1.type == o_reg and insn.Op2.type == o_displ: # e.g., mov     eax, [rsp+258h+var_1F0]
                    try:
                        var_hex = self.parse_and_get_var_hex(GetOpnd(head, 1))
                    except (AttributeError, IndexError, ValueError): # e.g., var_10.S_un
                        continue
                    if var_hex in self.stack_chars:
                        self.store_bytes_to_reg(insn.Op1.reg, self.stack_chars[var_hex])

            elif insn.itype == NN_xor:
                if insn.Op1.type == o_reg and insn.Op2.type == o_reg and insn.Op1.reg == insn.Op2.reg:
                    # e.g., xor ebx, ebx
                    self.store_bytes_to_reg(insn.Op1.reg, 0)
                elif insn.Op1.type == o_displ:
                    # e.g., xor     [esp+eax+384h+var_2A4], bl
                    try:
                        var_hex = self.parse_and_get_var_hex(GetOpnd(head, 0))
                    except (AttributeError, IndexError, ValueError): # e.g., var_10.S_un
                        continue
                    str_var_hex = 'var_{:X}'.format(var_hex)
                    if insn.Op2.type == o_reg and insn.Op2.reg in self.regs_w_value:
                        self.store_key_to_name(str_var_hex, self.regs_w_value[insn.Op2.reg])
                    elif insn.Op2.type == o_imm:
                        self.store_key_to_name(str_var_hex, insn.Op2.value)

            elif insn.itype == NN_and:
                if insn.Op1.type == o_displ and GetOpnd(head, 0).find('var_') != -1 and insn.Op2.value == 0:
                    # e.g., and     [ebp+var_24], 0
                    try:
                        var_hex = self.parse_and_get_var_hex(GetOpnd(head, 0))
                    except (AttributeError, IndexError, ValueError): # e.g., var_10.S_un
                        continue
                    self.store_byte_to_var(var_hex, 0)

            # e.g., push    7; pop     edx
            elif insn.itype == NN_push and insn.Op1.type == o_imm:
                self.store_byte_to_stack(insn.Op1.value)
            elif insn.itype == NN_pop and insn.Op1.type == o_reg and self.stack_imm:
                    self.store_bytes_to_reg(insn.Op1.reg, self.stack_imm)
                    self.stack_imm = None

            # for SSE registers
            elif (insn.itype == NN_movdqa or insn.itype == NN_movaps) and insn.Op1.type == o_reg:
                # e.g., movdqa  xmm1, ds:xmmword_155680
                self.store_bytes_to_reg(insn.Op1.reg, GetManyBytes(insn.Op2.addr, 0x10))
            elif (insn.itype == NN_movdqu or insn.itype == NN_movups) and insn.Op1.type == o_displ:
                # e.g., movdqu  [ebp+var_27C], xmm1
                try:
                    var_hex = self.parse_and_get_var_hex(GetOpnd(head, 0))
                except (AttributeError, IndexError, ValueError): # e.g., var_10.S_un
                    continue
                if insn.Op2.reg in self.regs_w_value:
                    self.store_bytes_to_vars(var_hex, self.regs_w_value[insn.Op2.reg])

            # for o_displ operand with base+index registers (increment index)
            elif insn.itype == NN_inc and insn.Op1.type == o_reg and insn.Op1.reg in self.regs_w_value:
                self.dprint('{}: incremented {}->{}'.format(GetOpnd(head, 0), self.regs_w_value[insn.Op1.reg], self.regs_w_value[insn.Op1.reg]+1))
                self.regs_w_value[insn.Op1.reg] += 1

        strings = {}
        result = []
        prev = 0
        len_ = 0
        uresult = []
        uprev = 0
        ulen = 0
        for k in sorted(self.stack_chars.keys(), reverse=True):
            self.dprint('{:x}: prev={:x}, uprev={:x}'.format(k, prev, uprev))

            # detect discontinuous chars
            if prev != 0 and prev != k + 1:
                self.dprint('discontinuous chars detected')
                stack_var = 'var_{:X}'.format(prev - 1  + len_)
                strings[stack_var] = ''.join(result)
                if strings[stack_var][0] != '\x00':
                    print '{} = {}'.format(stack_var, repr(strings[stack_var]))
                result = []
                prev = 0
                len_ = 0
                uresult = []
                uprev = 0
                ulen = 0
            elif uprev != 0 and uprev != k + 1:
            #elif uprev != 0 and uprev != k + 1 and uresult[1] == 0: # tiny check for unicode
                self.dprint('discontinuous chars detected (unicode)')
                stack_var = 'var_{:X}'.format(uprev - 1  + ulen)
                try:
                    #strings[stack_var] = ''.join(uresult).decode('utf-16')
                    self.dprint('data: {}'.format(repr(''.join(uresult))))
                    if extract_unicode(''.join(uresult)):
                        strings[stack_var] = extract_unicode(''.join(uresult))[0]
                        if strings[stack_var][0] != '\x00':
                            print '{} = {}'.format(stack_var, repr(strings[stack_var]))
                #except UnicodeDecodeError:
                except (TypeError, IndexError):
                    self.dprint('exception: {}'.format(stack_var))
                    #strings[stack_var] = ''.join(uresult)
                    pass
                uresult = []
                uprev = 0
                ulen = 0
                result = []
                prev = 0
                len_ = 0

            self.dprint('{:x}: {} (len={}, ulen={})'.format(k, repr(chr(self.stack_chars[k])), len_, ulen))
            result.append(chr(self.stack_chars[k]))
            uresult.append(chr(self.stack_chars[k]))

            # detect null-terminated chars
            #'''
            if self.stack_chars[k] == 0:
            #if self.stack_chars[k] == 0 and (prev != 0 and self.stack_chars[prev] == 0):
                #stack_var = 'var_{:X}'.format(k + len_)
                #if uprev != 0 and self.stack_chars[uprev] == 0:
                if uprev != 0 and self.stack_chars[uprev] == 0 and uresult[1] == 0: # tiny check for unicode
                    self.dprint('null-terminated chars detected (unicode)')
                    stack_var = 'var_{:X}'.format(k + ulen)
                    try:
                        #print ''.join(uresult)
                        #strings[stack_var] = ''.join(uresult)[:-1].decode('utf-16')
                        if extract_unicode(''.join(uresult)):
                            strings[stack_var] = extract_unicode(''.join(uresult))[0]
                            if strings[stack_var][0] != '\x00':
                                print '{} = {}'.format(stack_var, repr(strings[stack_var]))
                    #except UnicodeDecodeError:
                    except (TypeError, IndexError):
                        #strings[stack_var] = ''.join(uresult)
                        pass
                    uresult = []
                    uprev = 0
                    ulen = 0
                    prev = k
                    len_ += 1
                else:
                    self.dprint('null-terminated chars detected')
                    stack_var = 'var_{:X}'.format(k + len_)
                    strings[stack_var] = ''.join(result)
                    if strings[stack_var][0] != '\x00':
                        print '{} = {}'.format(stack_var, repr(strings[stack_var]))
                    result = []
                    prev = 0
                    len_ = 0
                    uprev = k
                    ulen += 1
            else:
            #'''
                prev = k
                len_ += 1
                uprev = k
                ulen += 1

        if len(result) > 0:
            print('the string is not null-terminated: {}'.format(repr(''.join(result))))

        stack = GetFrame(self.start)
        results = []
        for offset, name, size in StructMembers(stack):
            if name in strings:
                if self.do_xor:
                    if name in self.xor_vars:
                        k = self.xor_vars[name]
                    else:
                        k = self.static_xor_key
                    res = ''.join([chr(ord(x) ^ k) for x in strings[name][:-1]])
                    #print k
                    print '{} (xor-decoded): {} ({})'.format(name, repr(res), repr(strings[name]))
                    res = res + ' (decoded)'
                else:
                    res = strings[name]
                if res[0] != '\x00':
                    SetMemberComment(stack, offset, repr(res.rstrip('\x00')), 1)
                    results.append(repr(res.rstrip('\x00')))

        # set comment at the function start ea
        if results:
            cmt = ', '.join(results)
            if len(cmt) < 128:
                set_func_cmt(self.start, cmt, True)
            else:
                set_func_cmt(self.start, 'a lot of stack strings recovered (need to be checked)', True)

        # restore analyzed names in stack
        AnalyzeArea(self.start, self.end)

class SSSForm(ida_kernwin.Form):
    def __init__(self):
        ida_kernwin.Form.__init__(self,
r"""BUTTON YES* Run
BUTTON CANCEL Cancel
stackstring_static

{FormChangeCb}
<current function only:{cCurrentOnly}>
<enable debug messages:{cDebug}>
<enable xor decoding:{cDecode}>{cGroup}>
<default xor value in hex (single byte):{iXorValue}>
""",
        {
            'FormChangeCb': ida_kernwin.Form.FormChangeCb(self.OnFormChange),
            'cGroup': ida_kernwin.Form.ChkGroupControl(("cCurrentOnly", "cDebug", "cDecode")),
            'iXorValue': ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_HEX),
        })

    def OnFormChange(self, fid):
        if fid == -1:
            self.SetControlValue(self.cCurrentOnly, True)
            self.EnableField(self.iXorValue, False)                
        if fid == self.cDecode.id:
            #print('cDecode changed: {}'.format(self.cDecode.checked))
            #if self.cDecode.checked:
            self.EnableField(self.iXorValue, True)
            #else:
                #self.EnableField(self.iXorValue, False)                
        return 1

def main():
    print 'start'

    f = SSSForm()
    f.Compile()
    f.iXorValue.value = 0x55
    r = f.Execute()
    if r == 1: # Run
        if f.cCurrentOnly.checked:
            start = GetFunctionAttr(here(), FUNCATTR_START)
            end = GetFunctionAttr(here(), FUNCATTR_END)
            ss = StackString(start, end, f.cDebug.checked, f.cDecode.checked, f.iXorValue.value)
            ss.traverse()
        else:
            for start in Functions():
                end = GetFunctionAttr(start, FUNCATTR_END)
                ss = StackString(start, end, f.cDebug.checked, f.cDecode.checked, f.iXorValue.value)
                ss.traverse()
    else:  # Cancel
        print 'cancel'

    Refresh()
    print '----------------------------------------------'
    print 'done'

if __name__ == '__main__':
    main()




