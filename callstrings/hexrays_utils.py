'''
hexrays_utils.py - common classes/functions using Hex-Rays decompiler APIs
Takahiro Haruyama (@cci_forensics)
'''

#from abc import ABCMeta, abstractmethod

from idc import *
import idaapi, ida_ida, ida_ua, ida_typeinf, ida_kernwin
from ida_hexrays import *
from ida_allins import NN_callni, NN_call, NN_callfi
import idautils
import re

# Global options/variables
g_DEBUG = False
g_CACHE = True
g_ASCII_TYPES = ['CHAR *', 'CONST CHAR *', 'LPSTR', 'LPCSTR']
g_UNICODE_TYPES = ['WCHAR *', 'CONST WCHAR *', 'LPWSTR', 'LPCWSTR']
g_STR_TYPES = g_ASCII_TYPES + g_UNICODE_TYPES
g_stub_GetProcAddress = 'fn_resolve_API_addr'
g_RENAME_RETRY_CNT = 100

def info(msg):
    print("\033[34m\033[1m[*]\033[0m {}".format(msg))

def success(msg):
    print("\033[32m\033[1m[+]\033[0m {}".format(msg))
    
def error(msg):
    print("\033[31m\033[1m[!]\033[0m {}".format(msg))

def debug(msg):
    if g_DEBUG:
        print("\033[33m\033[1m[D]\033[0m {}".format(msg))


def extract_ascii(data):
    pat = re.compile(rb'^(?:[\x20-\x7E]){2,}')
    return list(set([w.decode('ascii') for w in pat.findall(data)]))

def extract_unicode(data):
    pat = re.compile(r'^(?:[\x20-\x7E][\x00]){2,}')
    return list(set([w.decode('utf-16le') for w in pat.findall(data)]))

def get_ctree_root(ea, cache=True):
    
    cfunc = None
    try:
        if cache:
            cfunc = decompile(ea)
        else:
            cfunc = decompile(ea, flags=DECOMP_NO_CACHE)        
    except:
        error('Decompilation of a function {:#x} failed'.format(ea))

    return cfunc

# Detect constant value used in string decoding
class cnt_val_finder_t(ctree_visitor_t):

    def __init__(self):
        
        ctree_visitor_t.__init__(self, CV_FAST)

        self.cst_val = None

    def visit_expr(self, expr):

        if expr.op == cot_asgxor and expr.y.op == cot_xor and expr.y.y.op == cot_num:
            cst = expr.y.y.n._value
            
            if expr.y.x.op == cot_add:
                expr_add = expr.y.x
            elif expr.y.x.op == cot_cast and expr.y.x.x.op == cot_add:
                expr_add = expr.y.x.x
            else:
                expr_add = None

            if expr_add and expr_add.y.op == cot_num and \
                (expr_add.y.n._value == cst) and (0 < cst < 0xff):
                success(f'{expr.ea:#x}: string decoding constant value {cst:#x} detected')
                self.cst_val = cst
                return 1
            
            # x ^ (y - 0x1d) ^ 0xe3 == x ^ (y + 0xe3) ^ 0xe3
            if expr.y.x.op == cot_sub:
                expr_sub = expr.y.x
            elif expr.y.x.op == cot_cast and expr.y.x.x.op == cot_sub:
                expr_sub = expr.y.x.x
            else:
                expr_sub = None

            if expr_sub and expr_sub.y.op == cot_num and \
                (expr_sub.y.n._value + cst == 0x100) and (0 < cst < 0xff):
                success(f'{expr.ea:#x}: string decoding constant value {cst:#x} detected')
                self.cst_val = cst
                return 1
            
        return 0
    
    def get_cnt_val(self):

        return self.cst_val

# Detect assignments when inserting comments
class asg_parent_finder_t(ctree_visitor_t):

    def __init__(self, call_ea):
        
        ctree_visitor_t.__init__(self, CV_PARENTS)
        self.call_ea = call_ea
        self.asg_ea = BADADDR

    def visit_expr(self, expr):

        if expr.op == cot_asg and \
            ((expr.y.op == cot_call and expr.y.ea == self.call_ea) or \
             (expr.y.op == cot_cast and expr.y.x.op == cot_call and expr.y.x.ea == self.call_ea)):
            self.asg_ea = expr.ea
            info(f'{self.call_ea:#x}: assignment detected, replaced with the ea {self.asg_ea:#x}')
            return 1
        
        return 0

# Change type/name of the specified lvar name
class my_lvar_modifier_t(user_lvar_modifier_t):

    def __init__(self, target_name, new_name=None, new_decl=None, new_tif=None):
        
        user_lvar_modifier_t.__init__(self)
        self.target_name = target_name
        self.new_name = new_name
        self.new_decl = new_decl
        self.new_tif = new_tif

    def modify_lvars(self, lvars):

        # Note: Variables without user-specified info are not present in lvvec
        if len(lvars.lvvec) == 0:
            error('modify_lvars: len(lvars.lvvec) == 0')

        for idx, one in enumerate(lvars.lvvec):
            debug('modify_lvars: target_name = "{}" current = "{}"'.format(self.target_name, one.name))

            # Set the type to the target var
            if one.name == self.target_name:
                if self.new_name:
                    one.name = self.new_name
                    info('modify_lvars: Name "{}" set to {}'.format(one.name, self.target_name))

                tif = None
                if self.new_decl:                    
                    tif = ida_typeinf.tinfo_t()
                    res = ida_typeinf.parse_decl(tif, None, self.new_decl, 0)
                    #if not res:
                    #    error('{}: parse_decl from {} FAILED'.format(one.name, self.new_decl))
                elif self.new_tif:
                    tif = self.new_tif
                if tif:
                    one.type = tif
                    info('modify_lvars: Type "{}" set to {}'.format(str(tif), one.name))

                return True

        return False

#class HexRaysUtils(metaclass=ABCMeta):
class HexRaysUtils():

    def __init__(self):

        self.cmts = {}
        self.call_eas = []

    #@abstractmethod
    def get_reg_value(self, reg_name):
        raise NotImplementedError()
    
    #@abstractmethod
    def get_dword_ptr(self, ptr):
        raise NotImplementedError()

    #@abstractmethod
    def get_string(self, ea, is_unicode=False):
        raise NotImplementedError()

    def get_fn_offset(self, ea):

        func_ea = get_func_attr(ea, FUNCATTR_START)
        return get_name(func_ea) + f'+{ea-func_ea:#x}'
    '''
    def set_decomplier_cmt(self, cfunc, ea, cmt):

        tl = idaapi.treeloc_t()
        tl.ea = ea
        tl.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(tl, cmt)
        cfunc.save_user_cmts()
    '''
    def set_decomplier_cmt(self, cfunc, ea, cmt):

        # Prevent orphan comment issues in assignments
        finder = asg_parent_finder_t(ea)
        finder.apply_to_exprs(cfunc.body, None)
        #print(f'{finder.asg_ea=:#x}')
        cmt_ea = ea if finder.asg_ea == BADADDR else finder.asg_ea

        tl = idaapi.treeloc_t()
        tl.ea = cmt_ea
        tl.itp = idaapi.ITP_SEMI

        cfunc.set_user_cmt(tl, cmt)
        cfunc.save_user_cmts()
        cfunc.refresh_func_ctext()

    # This function was ported from https://github.com/RolfRolles/Miscellaneous/blob/master/PrintTypeSignature.py
    # If an indirect API call still has a cast after the var type is set, apply "Force call type" on the var in Pseudocode view
    def GetTypeSignature(self, apiName):
        
        # Look up the prototype by name from the main TIL
        o = ida_typeinf.get_named_type(None, apiName, ida_typeinf.NTF_SYMU)
        
        # Found?
        if o is not None:
            code, type_str, fields_str, cmt, field_cmts, sclass, value = o
            
            # Create a tinfo_t by deserializing the data returned above
            t = ida_typeinf.tinfo_t()
            if t.deserialize(None, type_str, fields_str, field_cmts):
                
                # And change the prototype into a function pointer
                ptrType = ida_typeinf.tinfo_t()
                ptrType.create_ptr(t)
                return ptrType
        
        # On any failure, return None
        return None

    # IDA decompiler has no API forcing lvar name
    def force_rename_lvar(self, ea, var, new_name):

        func_ea = get_func_attr(ea, FUNCATTR_START)
        debug('force_rename_lvar: function ea = {:#x}'.format(func_ea))
        old_name = var.name
        
        if rename_lvar(func_ea, var.name, new_name):
            info('force_rename_lvar {:#x}: lvar name changed "{}" ->  "{}"'.format(ea, old_name, new_name))
            var.name = new_name # to refresh immediately
            return
                
        for i in range(g_RENAME_RETRY_CNT):            
            if rename_lvar(func_ea, var.name, new_name + '_{}'.format(i + 1)):
                info('force_rename_lvar {:#x}: lvar name changed "{}" -> "{}"'.format(ea, old_name, new_name + '_{}'.format(i + 1)))
                var.name = new_name + '_{}'.format(i + 1)
                break
        else:
            error('{:#x}: renaming {} failed (rename_lvar, {} times)'.format(ea, var.name, g_RENAME_RETRY_CNT))

    def get_arg_strings(self, address):

        if address in self.call_eas:
            info(f'{address:#x} ({self.get_fn_offset(address)}): already-visited call')
            return
        else:
            self.call_eas.append(address)

        cfunc = get_ctree_root(address, cache=g_CACHE)

        if cfunc:
            item = cfunc.body.find_closest_addr(address)

            if item.op == cot_call:
                expr = item.cexpr
                print('-' * 80)

                if expr.x.obj_ea == BADADDR:
                    # dynamically-resolved API
                    if expr.x.op == cot_var:
                        callee_name = expr.x.v.getv().name
                    elif expr.x.op == cot_cast and expr.x.x.op == cot_var:
                        callee_name = expr.x.x.v.getv().name
                        # Force call type (remove the cast)
                        tif = ida_typeinf.tinfo_t()
                        if print_insn_mnem(expr.ea) == 'call' and not ida_nalt.get_op_tinfo(tif, expr.ea, 0): # Skip an already-specified operand
                            tif = self.GetTypeSignature(callee_name)
                            if tif:
                                if ida_nalt.set_op_tinfo(expr.ea, 0, tif):
                                    success(f'{expr.ea:#x}: Force call type "{str(tif)}" to the operand "{callee_name}"')
                                else:
                                    error(f'{expr.ea:#x}: Force call type failed')
                    else:
                        callee_name = 'UNRESOLVED'
                else:
                    callee_name = get_name(expr.x.obj_ea)
                
                info(f'{address:#x} ({self.get_fn_offset(address)}): call {callee_name} ({expr.x.obj_ea:#x})')
                debug(f'{str(expr.x.type)}')
                
                debug(f'argc = {expr.a.size()}')
                arg_strs = []
                for i in range(expr.a.size()):
                    #breakpoint()
                    arg = expr.a.at(i)

                    # Sometimes the arg type in stubs is int *
                    if str(arg.type).upper() in g_STR_TYPES or callee_name.find(g_stub_GetProcAddress) != -1:
                        debug(f'arg{i} = {str(arg.type)}')

                        ea = 0
                        if str(expr.x.type).find('__thiscall') != -1:
                            debug('thiscall')
                            if i == 0:
                                ea = self.get_reg_value("ECX")
                            else:
                                ea = self.get_dword_ptr(self.get_reg_value("ESP") + (i - 1) * 4)
                        else: # __stdcall, __cdecl, __thiscall, etc.
                            debug('other calling conventions')
                            ea = self.get_dword_ptr(self.get_reg_value("ESP") + i * 4)
                        
                        debug(f'{ea=:#x}')
                        if str(arg.type).upper() in g_ASCII_TYPES or callee_name.find(g_stub_GetProcAddress) != -1:
                            res = self.get_string(ea)
                        else: # g_UNICODE_TYPES
                            res = self.get_string(ea, is_unicode=True)
                        
                        if res:
                            arg_strs.append(f'arg{i} = {res}')
                            debug(f'arg{i} = {res}')

                            # Set the function prototype if the callee is the GetProcAddress stubs or GetProcAddress API
                            if (i == 0 and callee_name.find(g_stub_GetProcAddress) != -1) or \
                                (i == 1 and callee_name == "GetProcAddress"):
                                #breakpoint()
                                p_item = cfunc.body.find_parent_of(expr)
                                p_expr = p_item.cexpr

                                if p_expr.op == cot_cast:
                                    p_item = cfunc.body.find_parent_of(p_expr)
                                    p_expr = p_item.cexpr

                                if p_expr.op == cot_asg and p_expr.x.op == cot_var:
                                    var = p_expr.x.v.getv()
                                    tif = self.GetTypeSignature(res)
                                    # We need to use rename_lvar calling modify_user_lvar_info indirectly to add the var into lvvec
                                    self.force_rename_lvar(address, var, res)
                                    my_lvar_mod = my_lvar_modifier_t(var.name, new_tif=tif)
                                    modify_user_lvars(get_func_attr(address, FUNCATTR_START), my_lvar_mod)

                # Set the arguments comment at the call instruction address
                if arg_strs:
                    cmt = f'{address:#x} ({self.get_fn_offset(address)}): {",".join(arg_strs)}'
                    success(cmt)
                    self.set_decomplier_cmt(cfunc, address, cmt)
                    self.cmts[address] = cmt
                    cfunc.refresh_func_ctext()

    def print_summary(self):

        if self.cmts:
            success('Summary:')
            for k,v in self.cmts.items():
                print(f'{v}')

    def decode(self, enc, cst_val):

        return bytes([enc[i] ^ ((i + cst_val) & 0xff) ^ cst_val for i in range(len(enc))])
