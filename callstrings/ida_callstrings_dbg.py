'''
ida_callstrings_dbg.py - string deobfuscation using IDA debug hook class
Takahiro Haruyama (@cci_forensics)
'''

import idaapi
idaapi.require('hexrays_utils', package='*')
from hexrays_utils import *
from ida_dbg import *

# Global options/variables
g_DEBUG = False
g_MAX_INSTRUCTIONS = 0 # 0 = disabled

def info(msg):
    print("\033[34m\033[1m[*]\033[0m {}".format(msg))

def success(msg):
    print("\033[32m\033[1m[+]\033[0m {}".format(msg))
    
def error(msg):
    print("\033[31m\033[1m[!]\033[0m {}".format(msg))

def debug(msg):
    if g_DEBUG:
        print("\033[33m\033[1m[D]\033[0m {}".format(msg))


class TraceHook(DBG_Hooks, HexRaysUtils):

    def __init__(self, target_ea):

        DBG_Hooks.__init__(self)
        HexRaysUtils.__init__(self)

        self.traces = 0
        self.target_ea = target_ea
        #self.current_tid = get_current_thread()

    def get_reg_value(self, reg_name):

        return get_reg_val(reg_name)

    def get_dword_ptr(self, ptr):
        
        return get_wide_dword(ptr)
    
    def get_string(self, ea, is_unicode=False):

        res = get_strlit_contents(ea, strtype=STRTYPE_C_16) if is_unicode else get_strlit_contents(ea)

        return res.decode() if res else None

    def dbg_trace(self, tid, ea):

        debug("[tid %X] trace %08X" % (tid, ea))

        if ea < ida_ida.inf_get_min_ea() or ea > ida_ida.inf_get_max_ea():
            raise Exception(
                "Received a trace callback for an address outside this database!"
            )
        
        insn = ida_ua.insn_t()
        insnlen = ida_ua.decode_insn(insn, ea)
        fn_name = get_name(get_func_attr(ea, FUNCATTR_START))
        if insnlen > 0 and insn.itype in [NN_callni, NN_call, NN_callfi] and fn_name.find(g_stub_GetProcAddress) == -1:
            refresh_debugger_memory()
            self.get_arg_strings(ea)

        self.traces += 1
        if g_MAX_INSTRUCTIONS and self.traces >= g_MAX_INSTRUCTIONS:
            request_disable_step_trace()
            request_suspend_process()

            if run_requests():
                info('Requests suspending the process executed (g_MAX_INSTRUCTIONS)')
            else:
                error('Requests suspending the process failed (g_MAX_INSTRUCTIONS)')

        #return 1
        return 0 # log it
    
    def dbg_thread_start(self, pid, tid, ea):

        info(f'[Thread {tid:#x}] {ea:#x}: New thread started')
        '''
        add_bpt(ea)
        select_thread(tid)
        request_suspend_process()

        #if tid != self.current_tid:
        if not self.unhook():
            error("Error uninstalling hooks!")
        else:
            info('Hooks uninstalled')
        #self.current_tid = tid
        end = prev_head(get_func_attr(ea, FUNCATTR_END))
        self.target_ea = end
        info(f'Selecting the new thread to trace until {end:#x}')
        #dbg_del_thread(self.current_tid)
        #suspend_thread(self.current_tid)
        select_thread(tid)
        set_trace_base_address(ea)
        dbg_add_thread(tid)
        self.hook()
        enable_step_trace(1) # needed per thread?
        set_step_trace_options(ST_OPTIONS_MASK)
        request_enable_step_trace(1)
        request_run_to(end)
        #request_continue_process()

        if run_requests():
            info('Requests successful')
        else:
            error('Requests failed')
        '''
        
    def dbg_thread_exit(self, pid, tid, ea, exit_code):

        info(f'[Thread {tid:#x}] {ea:#x}: Thread exited with {exit_code:#x}')

    def dbg_run_to(self, pid, tid=0, ea=0):

        if ea == self.target_ea:
            info(f'[Thread {tid:#x}] Reached to the target {self.get_fn_offset(ea)}')
        elif pid != 0:
            error(f'[Thread {tid:#x}] The suspended address {self.get_fn_offset(ea)} is different from the target {self.get_fn_offset(self.target_ea)}. Probably another breakpoint set?')
        else:
            error(f'[Thread {tid:#x}] The suspended address {self.get_fn_offset(ea)} is different from the target {self.get_fn_offset(self.target_ea)}. Probably suspended by users manually?')

        info(f"Traced {self.traces} instructions")
        refresh_debugger_memory()
        self.print_summary()

    def dbg_process_exit(self, pid, tid, ea, code):

        error(f"[Thread {tid:#x}] Process exited with {code:#x} before reaching to the target")
        info(f"Traced {self.traces} instructions")
        self.print_summary()

        return 0
    '''
    def dbg_suspend_process(self):

        self.dbg_run_to(0, ea=get_ip_val())
    '''

            
def main():

    info('start')

    if not is_debugger_on():
        error("Please run the process first!")
        return

    end = prev_head(get_func_attr(get_reg_val("EIP"), FUNCATTR_END))
    info(f"Tracing to the end of function {end:#x}")

    debugHook = TraceHook(end)
    debugHook.hook()
    enable_step_trace(1) # Only the same thread works
    #set_step_trace_options(ST_OVER_DEBUG_SEG | ST_OVER_LIB_FUNC | ST_SKIP_LOOPS | ST_ALREADY_LOGGED | ST_DIFFERENTIAL)
    #set_step_trace_options(ST_OVER_DEBUG_SEG | ST_OVER_LIB_FUNC)
    set_step_trace_options(ST_OPTIONS_MASK) # all included

    run_to(end)

    while get_process_state() == DSTATE_RUN:
    #while get_process_state() != DSTATE_NOTASK: # as long as process is currently debugged
        wait_for_next_event(WFNE_ANY, 0)

    if not debugHook.unhook():
        error("Error uninstalling hooks!")
    else:
        info('Hooks uninstalled')
    del debugHook

    info('done')

if __name__ == '__main__':
    main()
    
