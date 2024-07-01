'''
ida_callstrings_static.py - string deobfuscation for Hodur
Takahiro Haruyama (@cci_forensics)
'''

import idaapi
idaapi.require('hexrays_utils', package='*')
from hexrays_utils import *

g_DEBUG = False
g_CACHE = True
g_memcpy_names = ['qmemcpy', 'wmemcpy', 'strcpy']

def info(msg):
    print("\033[34m\033[1m[*]\033[0m {}".format(msg))

def success(msg):
    print("\033[32m\033[1m[+]\033[0m {}".format(msg))
    
def error(msg):
    print("\033[31m\033[1m[!]\033[0m {}".format(msg))

def debug(msg):
    if g_DEBUG:
        print("\033[33m\033[1m[D]\033[0m {}".format(msg))


class static_decoder_t(ctree_visitor_t, HexRaysUtils):

    def __init__(self, cst_val, cfunc):
        
        ctree_visitor_t.__init__(self, CV_PARENTS | CV_POST | CV_RESTART)
        HexRaysUtils.__init__(self)

        self.cst_val = cst_val
        self.cfunc = cfunc

    def visit_expr(self, expr):

        # Decode the src string by the constant value
        if expr.op == cot_call and expr.x.op == cot_helper and expr.x.helper in g_memcpy_names:
            #breakpoint()
            info(f'{expr.ea:#x}: target helper function "{expr.x.helper}" is called')
            arg_dst = expr.a.at(0)
            arg_src = expr.a.at(1)
            #arg_size = expr.a.at(2)

            #if (arg_dst.op == cot_var or (arg_dst.op == cot_ref and arg_dst.x.op == cot_var)) and \
            #    (arg_src.op == cot_str or (arg_src.op == cot_cast and arg_src.x.op == cot_str)):
            if (arg_src.op == cot_str or (arg_src.op == cot_cast and arg_src.x.op == cot_str)):
                enc = arg_src.string if arg_src.op == cot_str else arg_src.x.string
                enc = enc.encode('utf-16-le') if expr.x.helper == 'wmemcpy' else enc.encode()
                info(f'{expr.ea:#x}: src bytes = {enc}')
                dec = self.decode(enc, self.cst_val).decode()
                if dec:
                    success(f'{expr.ea:#x}: string decoded "{dec}"')
                    self.set_decomplier_cmt(self.cfunc, expr.ea, dec)
                else:
                    error(f'{expr.ea:#x}: string decoding failed using a constant value ({self.cst_val:#x})')

        return 0
    

def main():

    info('start')

    ans = ida_kernwin.ask_yn(0, 'only decode the selected function?')
    if ans == ida_kernwin.ASKBTN_YES:
        fvas = [get_func_attr(get_screen_ea(), FUNCATTR_START)]
    elif ans == ida_kernwin.ASKBTN_NO:
        fvas = idautils.Functions()
    else:
        info('canceled')
        return
    
    for fva in fvas:
        if get_func_flags(fva) & (FUNC_LIB | FUNC_THUNK):
            debug(f"{fva:#x}: skipping library or thunk function")
            continue

        fn_name = get_name(get_func_attr(fva, FUNCATTR_START))
        if fn_name.find(g_stub_GetProcAddress) != -1:
            debug(f"{fva:#x}: skipping GetProcAddress stub function")
            continue

        print('-' * 100)
        info(f'{get_name(fva)} ({fva:#x})')

        cfunc = get_ctree_root(fva, cache=g_CACHE)

        cvf = cnt_val_finder_t()
        cvf.apply_to_exprs(cfunc.body, None)
        cnt_val = cvf.get_cnt_val()

        if cnt_val:
            sd = static_decoder_t(cnt_val, cfunc)
            sd.apply_to_exprs(cfunc.body, None)
        else:
            error(f'{fva:#x}: A constant value for decoding is not found')

        refresh_idaview_anyway()

    print('-' * 100)

    info('done')    

if __name__ == '__main__':
    main()