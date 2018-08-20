import idaapi
import ida_segment
from idc import *
from struct import *

DATA_SEG_START = 0x10000 # may be changed

def accept_file(li, filename):
    sig = int16(li.read(2))
    if sig in [0x3713, 0x481c, 0x1337]:
        return {'format': "ESET Crackme driver VM program"}
    else:
        return 0

def int16(b):
    return unpack('<H', b)[0]
    
def int32(b):
    return unpack('<I', b)[0]

def myAddSeg(startea, endea, base, use32, name, clas):
    s = idaapi.segment_t()
    s.start_ea = startea
    s.end_ea   = endea
    s.sel      = idaapi.setup_selector(base)
    s.bitness  = use32
    s.align    = idaapi.saRelPara
    s.comb     = idaapi.scPub
    #idaapi.add_segm_ex(s, name, clas, idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_OR_DIE)
    idaapi.add_segm(base, startea, endea, name, clas)

def load_file(li, neflags, format):
    li.seek(0) # needed to read signature
    sig = int16(li.read(2)) 
    size = int32(li.read(4)) # the program size
    code_off = int32(li.read(4)) # the code segment offset
    if sig != 0x3713: # for inline VM
        code_off = 0x12 
    data_off = int32(li.read(4)) # the data segment offset
    flag_kernel_mode = int32(li.read(4))
    
    #set_processor_type('eset_vm', SETPROC_USER | SETPROC_LOADER)
    set_processor_type('eset_vm', SETPROC_LOADER)

    # Create segment & Populate
    #'''
    myAddSeg(0, data_off - code_off, 0, 1, 'VM_CODE', "CODE")
    li.file2base(li.tell(), 0, data_off - code_off, 1)
    myAddSeg(DATA_SEG_START, DATA_SEG_START + size - data_off, 0, 1, 'VM_DATA', "DATA") # flat memory space
    #myAddSeg(DATA_SEG_START, DATA_SEG_START + size - data_off, DATA_SEG_START >> 4, 1, 'VM_DATA', "DATA") # segmentation (base should be in paragraphs 16-bits)    
    li.file2base(li.tell(), DATA_SEG_START, DATA_SEG_START + size - data_off, 1)
    '''
    myAddSeg(code_off, data_off, 0, 1, 'VM_CODE', "CODE")
    li.file2base(li.tell(), code_off, data_off, 1)
    myAddSeg(data_off, size, 0, 1, 'VM_DATA', "DATA")
    li.file2base(li.tell(), data_off, size, 1)
    '''

    # initialize
    set_inf_attr(INF_START_EA, 0)
    set_inf_attr(INF_START_IP, 0)
    set_inf_attr(INF_START_CS, 0)
    #add_entry(0, ep, "start", 1)
    add_entry(0, 0, "start", 1)

    # should return 1 or terminate immediately
    return 1 

