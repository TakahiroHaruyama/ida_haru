'''
ida_callstrings_flare_emu.py - string deobfuscation using flare-emu
Takahiro Haruyama (@cci_forensics)
'''

import idaapi
#idaapi.require('logging') # <- This suppresses the flare-emu debug messages!
import logging, hexdump
#logging.basicConfig(level=logging.DEBUG, force=True)

idaapi.require('hexrays_utils', package='*')
from hexrays_utils import *

idaapi.require('flare_emu')
idaapi.require('flare_emu_hooks')
import flare_emu, flare_emu_hooks, unicorn

# Global options
g_DEBUG = True
g_DEBUG_FLARE_EMU = False
g_FLAG_ALL_PATHS = False # True: iterateAllPaths, False: emulateRange
g_MAX_SAME_STATE_VAR = 0x1000 # to detect infinite loop by CFF
g_MAX_INST_VISIT = 10000 # to detect infinite loop
#g_MAX_EMU_INSN = 1000000
g_MAX_STACK_BUF = 0x100
#g_ENC_OFFSET = 0x0

def info(msg):
    print("\033[34m\033[1m[*]\033[0m {}".format(msg))

def success(msg):
    print("\033[32m\033[1m[+]\033[0m {}".format(msg))
    
def error(msg):
    print("\033[31m\033[1m[!]\033[0m {}".format(msg))

def debug(msg):
    if g_DEBUG:
        print("\033[33m\033[1m[D]\033[0m {}".format(msg))

def debug_bin(n, v):
    if g_DEBUG:
        debug(n)
        hexdump.hexdump(v)


class HexRaysEmu(HexRaysUtils):

    def __init__(self, eh):

        HexRaysUtils.__init__(self)
        self.eh = eh

    def get_reg_value(self, reg_name):

        return self.eh.getRegVal(reg_name.lower())

    def get_dword_ptr(self, ptr):
        
        return self.eh.getEmuPtr(ptr)
    
    def get_string(self, ea, is_unicode=False):

        return self.eh.getEmuWideString(ea).decode('utf-16') if is_unicode else self.eh.getEmuString(ea).decode()


def call_hook(address, argv, funcName, userData):

    #is_64bit = True if idaapi.get_inf_structure().lflags & idaapi.LFLG_64BIT == 4 else False
    hremu = userData["hremu"]

    try:
        hremu.get_arg_strings(address)
    except unicorn.UcError as e:
        error(f'{address:#x} ({hremu.get_fn_offset(address)}): Unicorn emulation exception in get_arg_strings() ({e})')

def mem_write_hook(unicornObject, accessType, memAccessAddress, memAccessSize, memValue, userData):

    if accessType == unicorn.UC_MEM_WRITE:

        hremu = userData["hremu"]
        sp = hremu.eh.getRegVal('esp')
        ip = hremu.eh.getRegVal('ip')

        if sp < memAccessAddress < sp + g_MAX_STACK_BUF:
            userData["enc_heads"][ip] = memAccessAddress

def is_high_entropy(v):

    res = True
    vbytes = v.to_bytes(4, 'little')

    for b in vbytes:
        if b & 0xff == 0: # e.g., 0, 1, 0x10000000, etc.
            res = False
            break
    else:
        vlist = [b for b in vbytes]
        for b in vbytes:
            if b == vlist[0] and b == vlist[1] and b == vlist[2] and b == vlist[3]: # e.g., 0x11111111, 0xffffffff, etc.
                res = False
                break
        
    return res

def inst_hook_cff(unicornObject, address, instructionSize, userData):

    eh = userData["EmuHelper"]
    state_var_cnt = userData["state_var_cnt"]
    state_excluded = userData["state_excluded"]
    abort = False

    if print_insn_mnem(address) == 'cmp' and get_operand_type(address, 0) == o_reg and get_operand_type(address, 1) == o_imm and \
        is_high_entropy(get_operand_value(address, 1)) and print_insn_mnem(next_head(address)) in ['jz', 'jnz']:
        #debug(f'{address:#x}: compare state var with cmp var')

        reg_name = print_operand(address, 0)
        state_var = eh.getRegVal(reg_name)        
        cmp_var = get_operand_value(address, 1)

        if state_var != cmp_var:
            abort = True

    elif print_insn_mnem(address) in ['cmovz'] and get_operand_type(address, 0) == o_reg:

        reg_name = print_operand(address, 0)
        state_var = eh.getRegVal(reg_name)
        
        cmp_var = None
        if is_high_entropy(state_var):

            op1type = get_operand_type(address, 1)
            if op1type == o_imm:
                cmp_var = get_operand_value(address, 1)
            elif op1type == o_reg:
                op1_reg_name = print_operand(address, 1)
                cmp_var = eh.getRegVal(op1_reg_name)

            if cmp_var and state_var != cmp_var:
                abort = True

    if abort:        
        if address not in state_excluded:
            uid = (address, state_var)
            state_var_cnt[uid] = 1 if uid not in state_var_cnt else state_var_cnt[uid] + 1
            #debug(f'{address:#x}: The same state variable is compared or conditional moved {state_var_cnt[uid]} times')

            if state_var_cnt[uid] >= g_MAX_SAME_STATE_VAR:
                error(f'{address:#x}: CFF infinite loop detected. Update the state variable {state_var:#x} with the new one {cmp_var:#x}')
                debug([f'{ea:#x}: {var=:#x}, {cnt=}' for (ea, var), cnt in state_var_cnt.items()])
                debug(f'excluded: {[f"{e:#x}" for e in state_excluded]}')

                eh.uc.reg_write(eh.regs[reg_name], cmp_var)
                state_excluded.append(address)
                # Reset the counts of the external loops
                state_var_cnt = {}

def inst_hook(unicornObject, address, instructionSize, userData):

    eh = userData["EmuHelper"]
    inst_visit_cnt = userData["inst_visit_cnt"]

    inst_visit_cnt[address] = 1 if address not in inst_visit_cnt else inst_visit_cnt[address] + 1
    if inst_visit_cnt[address] >= g_MAX_INST_VISIT:
        error(f'{address:#x}: Infinite loop detected. Aborted.')
        eh.stopEmulation(userData)

def noop(*args):

    pass

def main():

    info('start')
    #breakpoint()

    if g_DEBUG_FLARE_EMU:
        eh = flare_emu.EmuHelper(verbose=10)
        eh.logger.setLevel(logging.DEBUG)
    else:
        eh = flare_emu.EmuHelper()

    hremu = HexRaysEmu(eh)

    selection = idaapi.read_range_selection(None)
    if selection[0]:
        info(f'Emulating the selection {selection[1]:#x} to {selection[2]:#x}')
        enc_heads = {}
        userData = {
            'hremu': hremu,
            'enc_heads': enc_heads
        }
        eh.emulateSelection(memAccessHook=mem_write_hook, hookData=userData)

        # Get the head of encoded string
        stack_buf = eh.getEmuBytes(eh.getRegVal('esp'), g_MAX_STACK_BUF)
        debug_bin('stack', stack_buf)
        for i in range(len(stack_buf)):
            if 65 <= stack_buf[i] <= 122: # A to z
                offset = i
                break
        else:
            offset = 0
        #offset = 0x48 # Sometimes you need to adjust the offset manually :-(
        debug(f'detected offset = {offset:#x}')
        
        # Decode the string after detecting the constant value
        cfunc = get_ctree_root(selection[1], cache=g_CACHE)
        cvf = cnt_val_finder_t()
        cvf.apply_to_exprs(cfunc.body, None)
        cnt_val = cvf.get_cnt_val()

        if cnt_val:
            if stack_buf[offset + 1] != 0:
                enc = stack_buf[offset:]
                debug(f'enc {enc} is ascii')
            else:
                enc = eh.getEmuWideString(eh.getRegVal('esp') + offset).decode('utf-16-le')
                enc = enc.encode()
                debug(f'enc {enc} is unicode (utf-16-le)')
            dec = hremu.decode(enc, cnt_val)
            debug_bin('dec', dec)

            # Extract the ascii strings (no null termination)
            head = eh.getRegVal('esp') + offset
            ascs = extract_ascii(dec)
            if ascs:
                keys = [k for k, v in enc_heads.items() if v == head]
                if len(keys) == 1:
                    success(f'{keys[0]:#x}: string decoded "{ascs[0]}"')
                    hremu.set_decomplier_cmt(cfunc, keys[0], ascs[0])
                else:
                    success(f'string decoded "{ascs[0]}"')

        else:
            error(f'A constant value for decoding is not found')            

    else:        
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
        
            '''
            state_var_cnt = {}
            state_excluded = []
            userData = {
                'hremu': hremu,
                'state_var_cnt': state_var_cnt,
                'state_excluded': state_excluded,
            }
            eh.emulateRange(fva, callHook=call_hook, instructionHook=inst_hook_cff, hookData=userData, count=g_MAX_EMU_INSN)
            '''
            inst_visit_cnt = {}
            userData = {
                'hremu': hremu,
                'inst_visit_cnt': inst_visit_cnt,
            }
            if g_FLAG_ALL_PATHS:
                info('The mode is iterateAllPaths')
                eh.iterateAllPaths(fva, noop, hookData=userData, callHook=call_hook)
            else:
                info('The mode is emulateRange')
                eh.emulateRange(fva, callHook=call_hook, instructionHook=inst_hook, hookData=userData)

            refresh_idaview_anyway()
            eh.resetEmulatorHeapAndStack()

    print('-' * 100)
    hremu.print_summary()

    info('done')

if __name__ == '__main__':
    main()
    
