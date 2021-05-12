# idapy3_ADVobfuscator_deob.py - IDAPython script deobfuscating ADVobfuscator strings, applied to a TrickBoot sample
# Takahiro Haruyama (@cci_forensics)

from idc import *
from idautils import *
import idaapi

try:
    import flare_emu
except ImportError as e:
    print(("Could not import flare_emu: {}\nExiting.".format(e.message)))
    raise

import re, unicorn
'''
dec 


'''
g_pat_sub = re.compile(rb'^\x33\xD2\x8A\x04\x0A\x0F\xBE\xC0\x83\xE8(.)\x88\x04\x0A\x42\x83\xFA(.)\x72\xEE\x8B\xC1\xC3$', re.DOTALL)
g_pat_xor1 = re.compile(rb'^\x53\x55\x56\x57\x8b\xf9\x6a(.)\x5d\x8d\x47\x04\x8a\x10\x0f\xbe\x37\x0f\xbe\xca\x33\xce\x88\x08\x40\x83\xed\x01\x75\xee\xc6\x47.\x00\x8d\x47\x04\x5f\x5e\x5d\x5b\xc3$', re.DOTALL)
g_pat_xor2 = re.compile(rb'^\x53\x56\x57\x8b\xf1\x33\xdb\x8a\x54\x1e\x04\x8b\x06\x02\xc3\x0f\xbe\xca\x33\xc1\x88\x44\x1e\x04\x43\x83\xfb(.)\x72\xe9\x5f\xc6\x46.\x00\x8d\x46\x04\x5e\x5b\xc3$', re.DOTALL)
g_pat_dec = re.compile(rb'^\x33\xd2\x8a\x04\x0a\x0f\xbe\xc0\x48\x88\x04\x0a\x42\x83\xfa(.)\x72\xf0\x8b\xc1\xc3$', re.DOTALL)
g_pats = {
    'sub': g_pat_sub,
    'xor1': g_pat_xor1,
    'xor2': g_pat_xor2,
    'dec': g_pat_dec,
}

def info(msg):
    print(("[*] {}".format(msg)))

def success(msg):
    print(("[+] {}".format(msg)))

def error(msg):
    print(("[!] {}".format(msg)))

def set_decomplier_cmt(ea, cmt):
    try:
        cfunc = idaapi.decompile(ea)
        tl = idaapi.treeloc_t()
        tl.ea = ea
        tl.itp = idaapi.ITP_SEMI
        if cfunc:
          cfunc.set_user_cmt(tl, cmt)
          cfunc.save_user_cmts()
        else:
          error("Decompile failed: {:#x}".format(ea))
    except:
        error("Decompile failed: {:#x}".format(ea))

def add_bookmark(ea, comment):
    last_free_idx = -1
    for i in range(0, 1024):
        slot_ea = get_bookmark(i)
        if slot_ea == BADADDR or slot_ea == ea:
            # empty slot found or overwrite existing one
            last_free_idx = i
            break
    # Check Empty Slot
    if last_free_idx < 0:
        return False
    # Register Slot
    put_bookmark(ea, 0, 0, 0, last_free_idx, comment)
    return True

def get_emu_range(ea):
    func = idaapi.get_func(ea)
    if func is None:
        return None, None

    for bb in idaapi.FlowChart(func):
        if bb.start_ea <= ea <= bb.end_ea:            
            #return bb.start_ea, next_head(ea) # 
            return bb.start_ea, ea
    return None, None

# enable a step into emulation for the decoder (disabled)
def call_hook(address, argv, funcName, userData):
    if funcName == userData["dec_fn_name"]:
        #print('dec_fn detected')
        userData['skipCalls'] = False
    else:
        userData['skipCalls'] = True

# validate the emulation result, based on the encoded buf ptr (disabled)
def inst_hook(uc, address, size, userData):
    #info('instr_hook {:#x}'.format(address))
    if address == userData['ref']:
        eh = userData["EmuHelper"]
        try:
            pc = uc.reg_read(eh.regs["pc"])
            enc_ea = uc.reg_read(eh.regs["ecx"])
            info('pc = {:#x}, address = {:#x}), enc_ea = {:#x}'.format(pc, address, enc_ea))
            userData["enc_ea"] = enc_ea
        except unicorn.UcError as e:
            error("emulation error: {}".format(str(e)))
    elif address == userData['end'] and userData.get('enc_ea'):
        eh = userData["EmuHelper"]
        try:
            pc = uc.reg_read(eh.regs["pc"])
            if userData["dec_fn_name"].find('sub') != -1:
                dec = uc.mem_read(userData["enc_ea"], userData['size'])
            else: # xor
                dec = uc.mem_read(userData["enc_ea"] + 4, userData['size'])
            success('{:#x}: {}'.format(userData['ref'], dec))
            
        except unicorn.UcError as e:
            error("emulation error: {}".format(str(e)))

def emulate(pname, eh, dec_fn, size, key):
    cnt = 0
    
    refs = CodeRefsTo(dec_fn, False)
    for ref in refs:
        if GetMnem(ref) == 'call':
            start, end = get_emu_range(ref)
            
            if start and end:
                info('{:#x}: emulating from {:#x} to {:#x}'.format(ref, start, end))
                userData = {
                    'dec_fn_name': get_name(dec_fn),
                    'start': start,
                    'end': end,
                    'ref': ref,
                    'size': size,
                }
                try:
                    #eh.emulateRange(start, endAddr=end, callHook=call_hook, instructionHook=inst_hook, hookData=userData)
                    #eh.emulateRange(start, endAddr=end, callHook=call_hook, hookData=userData)
                    eh.emulateRange(start, endAddr=end)
                    
                    pc = eh.uc.reg_read(eh.regs["pc"])
                    ea = eh.uc.reg_read(eh.regs["ecx"])
                    if pname == 'sub':
                        enc = eh.uc.mem_read(ea, size)
                        #info('key = {:#x}, enc = {}'.format(key, enc))
                        dec = bytes([(x - key) & 0xff for x in enc]).decode()
                    elif pname == 'dec':
                        enc = eh.uc.mem_read(ea, size)
                        dec = bytes([(x - 1) & 0xff for x in enc]).decode()
                    else:
                        key = eh.uc.mem_read(ea, 4)[0]
                        enc = eh.uc.mem_read(ea + 4, size)
                        #info('key = {:#x}, enc = {}'.format(key, enc))
                        if pname == 'xor1':
                            dec = bytes([x ^ key for x in enc]).decode()
                        else: # xor2
                            dec = bytes([x ^ (key + i) for i, x in enumerate(enc)]).decode()

                    # to obtain the step into emulation (disabled)
                    #dec_ea = eh.uc.reg_read(eh.regs["eax"])
                    #info('{:#x}: dec_ea = {:#x}'.format(pc, dec_ea))
                    #dec = eh.uc.mem_read(dec_ea, size)
                    
                    success('{:#x}: {}'.format(ref, dec))
                    MakeComm(ref, dec)
                    set_decomplier_cmt(ref, dec)
                    add_bookmark(ref, 'decoded: {}'.format(dec))
                    cnt += 1
                    
                except unicorn.UcError as e:
                    pc = eh.uc.reg_read(eh.regs["pc"])
                    error("{:#x}: {} when reading {:#x}".format(pc, str(e), ea))
                    
                finally:
                    eh.resetEmulatorHeapAndStack()

    return cnt

def main():
    info('start')
    eh = flare_emu.EmuHelper()

    # search the decoding functions
    cnts = {}
    for fva in Functions():
        #if fva != 0x1000A19F:
        #    continue
        if idc.get_func_flags(fva) & (idc.FUNC_LIB | idc.FUNC_THUNK):
            continue

        size = 0
        fn_bytes = idc.get_bytes(fva, get_func_attr(fva, FUNCATTR_END) - fva)

        for pname, pat in g_pats.items():
            m = pat.search(fn_bytes)
            if m:
                try:
                    if pname == 'sub':
                        key = int.from_bytes(m.group(1), 'little')
                        size = int.from_bytes(m.group(2), 'little')
                    else:
                        key = None
                        size = int.from_bytes(m.group(1), 'little')
                except ValueError:
                    pass
                else:
                    print('\n')
                    info('{:#x}: {}-encoded function detected (size = {:#x})'.format(fva, pname, size))
                    idaapi.do_name_anyway(fva, 'fn_ADVobfuscator_decode_{}_len{}'.format(pname, size))
                    
                    cnt = emulate(pname, eh, fva, size, key)
                    if cnts.get(pname):
                        cnts[pname] += cnt
                    else:
                        cnts[pname] = cnt
                    break

    info('number of decoded strings: {}'.format(cnts))
    info('done')    

if __name__ == '__main__':
    main()
    
