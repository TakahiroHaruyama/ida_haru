import os, pickle, re
from idautils import *

g_track_parent_th = 2 # parent function tracking level threshold
g_parent_func_exclude_list = ['__NMSG_WRITE', '__fassign_l']
g_pfe_list = [get_name_ea_simple(p) for p in g_parent_func_exclude_list]

def get_pfuncs(ea, track_th):
    pfuncs = [get_func_attr(ref, FUNCATTR_START) for ref in CodeRefsTo(ea, False)]
    track_th -= 1
    if track_th > 0:
        ppfuncs = [ppfunc for pfunc in pfuncs for ppfunc in get_pfuncs(pfunc, track_th)]
        pfuncs.extend(ppfuncs)
    return pfuncs

def main():    
    #Wait()

    # not change the database to maintain the window setting
    process_config_line("ABANDON_DATABASE=YES")

    # -Odecomp:option1:option2:option3
    options = idaapi.get_plugin_options("save_func_names").split(':')
    func_regex = options[0]
    pickle_path = ':'.join(options[1:])
    p = re.compile(func_regex)

    func_names = {}
    with open(pickle_path, 'wb') as f:
        for ea in Functions(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA):
            func_name = idc.get_func_name(ea)
            if p.search(func_name):
                flags = idc.get_func_attr(ea, FUNCATTR_FLAGS)
                if flags & FUNC_LIB or flags & FUNC_THUNK:
                    continue
                pfuncs = get_pfuncs(ea, g_track_parent_th)
                if not (set(pfuncs) & set(g_pfe_list)):
                    func_names[ea] = func_name
        pickle.dump(func_names, f)

    ida_pro.qexit(0)

    #with open(os.path.splitext(idc.get_idb_path())[0] + '_func_names.pickle', 'rb') as f:
    #    func_names = pickle.load(f)
    #    print func_names

if ( __name__ == "__main__" ):
    main()


