from struct import unpack

# ---------
# --- PACSI
# ---------
# mandatory fields in PACSI header
PACSI_HEAD_LEN         = 5
PACSI_HEAD_FMT         = 'BBBBB'
F_MASK                 = 0x80
NRI_MASK               = 0x60
TYPE_MASK              = 0x1f 
R_MASK                 = 0x80
I_MASK                 = 0x40
PRID_MASK              = 0x3f
N_MASK                 = 0x80
DID_MASK               = 0x70
QID_MASK               = 0x0f
TID_MASK               = 0xe0
U_MASK                 = 0x10
D_MASK                 = 0x08
O_MASK                 = 0x04
RR_MASK                = 0x03
X_MASK                 = 0x80
Y_MASK                 = 0x40
T_MASK                 = 0x20
A_MASK                 = 0x10
P_MASK                 = 0x08
C_MASK                 = 0x04
S_MASK                 = 0x02
E_MASK                 = 0x01
# optional fields based on Y flag in PACSI header
PACSI_Y_OPT_FIELDS_LEN = 3
PACSI_Y_OPT_FIELDS_FMT = '>BH'
# optional fields based on T flag in PACSI header
PACSI_T_OPT_FIELDS_LEN = 2
PACSI_T_OPT_FIELDS_FMT = '>H'
# ----------------
# --- SEI STANDARD
# ----------------
# SEI size field
SEI_SIZE_LEN           = 2
SEI_SIZE_FMT           = '>H'
# SEI header (F_NRI_TYPE, PAYLOAD_TYPE, PAYLOAD_SIZE)
SEI_HDR_LEN            = 3
SEI_HDR_FMT            = 'BBB'
# UUID
STREAM_LAYOUT_UUID     = '\x13\x9F\xB1\xA9\x44\x6A\x4D\xEC\x8C\xBF\x65\xB1\xE1\x2D\x2C\xFD'
BITSREAM_INFO_UUID     = '\x05\xFB\xC6\xB9\x5A\x80\x40\xE5\xA2\x2A\xAB\x40\x20\x26\x7E\x26'
UUID_LEN               = 16
# ---------------------
# --- SEI STREAM LAYOUT
# ---------------------
# LPB fields
LPB_LEN                = 8
LPB_FMT                = 'BBBBBBBB'
# R and P fields
R_P_LEN                = 1
R_P_FMT                = 'B'
SL_R_MASK              = 0xfe
SL_P_MASK              = 0x01
# Layer description length field
LDL_LEN                = 1 
LDL_FMT                = 'B'
# Layer description fields
LD_LEN                 = 16
LD_FMT                 = '>HHHHIBBH'
FPS_IDX_MASK           = 0xf8 
LT_MASK                = 0x07
LD_PRID_MASK           = 0xfc
CB_MASK                = 0x02
LD_R_MASK              = 0x01
# FPS idx -> FPS
FPS_MAP                = {0:'7.5',1:'12.5',2:'15',3:'25',4:'30',5:'50',6:'60'}
# -----------------------
# --- SEI BIT STREAM INFO
# -----------------------
# Bit-Stream-Info specific fields (REF_FRM_COUNT, NUM_OF_NAL_UNIT)
BSINFO_LEN             = 2
BSINFO_FMT             = 'BB'

class Pacsi:
    
    def __init__(self, f_nri_type, r_i_prid, 
                       n_did_qid, tid_u_d_o_rr,
                       x_y_t_a_p_c_s_e ):
        self.f    = get_bitfield(f_nri_type, F_MASK)    
        self.nri  = get_bitfield(f_nri_type, NRI_MASK) 
        self.type = get_bitfield(f_nri_type, TYPE_MASK)
        self.r    = get_bitfield(r_i_prid, R_MASK)
        self.i    = get_bitfield(r_i_prid, I_MASK)
        self.prid = get_bitfield(r_i_prid, PRID_MASK)
        self.n    = get_bitfield(n_did_qid, N_MASK)
        self.did  = get_bitfield(n_did_qid, DID_MASK)
        self.qid  = get_bitfield(n_did_qid, QID_MASK)
        self.tid  = get_bitfield(tid_u_d_o_rr, TID_MASK)
        self.u    = get_bitfield(tid_u_d_o_rr, U_MASK)
        self.d    = get_bitfield(tid_u_d_o_rr, D_MASK)
        self.o    = get_bitfield(tid_u_d_o_rr, O_MASK)
        self.rr   = get_bitfield(tid_u_d_o_rr, RR_MASK)
        self.x    = get_bitfield(x_y_t_a_p_c_s_e, X_MASK)
        self.y    = get_bitfield(x_y_t_a_p_c_s_e, Y_MASK)
        self.t    = get_bitfield(x_y_t_a_p_c_s_e, T_MASK)
        self.a    = get_bitfield(x_y_t_a_p_c_s_e, A_MASK)
        self.p    = get_bitfield(x_y_t_a_p_c_s_e, P_MASK)
        self.c    = get_bitfield(x_y_t_a_p_c_s_e, C_MASK)
        self.s    = get_bitfield(x_y_t_a_p_c_s_e, S_MASK)
        self.e    = get_bitfield(x_y_t_a_p_c_s_e, E_MASK)
        
        self.tl0picidx = None
        self.idrpicid  = None
        self.donc      = None
        self.seiList   = []
        
    def add_opt_Y(self, tl0picidx, idrpicid):
        self.tl0picidx = tl0picidx
        self.idrpicid  = idrpicid
        
    def add_opt_T(self, donc):
        self.donc = donc
        
    def add_sei(self, sei):
        self.seiList.append(sei)
        
    def __str__(self):
        s  = "------------"             + "\n"
        s += "-- HEADER --"             + "\n"
        s += "------------"             + "\n"
        s += "F    :" + str(self.f)     + "\n"
        s += "NRI  :" + str(self.nri)   + "\n"
        s += "TYPE :" + str(self.type)  + "\n"
        s += "R    :" + str(self.r)     + "\n"
        s += "I    :" + str(self.i)     + "\n"
        s += "PRID :" + str(self.prid)  + "\n"
        s += "N    :" + str(self.n)     + "\n"
        s += "DID  :" + str(self.did)   + "\n"
        s += "QID  :" + str(self.qid)   + "\n"
        s += "TID  :" + str(self.tid)   + "\n"
        s += "U    :" + str(self.u)     + "\n"
        s += "D    :" + str(self.d)     + "\n"
        s += "RR   :" + str(self.rr)    + "\n"
        s += "X    :" + str(self.x)     + "\n"
        s += "Y    :" + str(self.y)     + "\n"
        s += "T    :" + str(self.t)     + "\n"
        s += "A    :" + str(self.a)     + "\n"
        s += "P    :" + str(self.p)     + "\n"
        s += "C    :" + str(self.c)     + "\n"
        s += "S    :" + str(self.s)     + "\n"
        s += "E    :" + str(self.e)     + "\n"
        if self.tl0picidx is not None:
            s += "TL0PICIDX :" + str(self.tl0picidx) + "\n"
        if self.idrpicid  is not None:
            s += "IDRPICID  :" + str(self.idrpicid)  + "\n"
        if self.donc is not None:
            s += "DONC :" + str(self.donc)+ "\n"
        for sei in self.seiList:
            s += str(sei)
        return s
        
class Sei:
    
    def __init__(self, F_NRI_TYPE, payloadType, payloadSize, payload):
        self.f           = get_bitfield(F_NRI_TYPE, F_MASK)
        self.nri         = get_bitfield(F_NRI_TYPE, NRI_MASK)
        self.type        = get_bitfield(F_NRI_TYPE, TYPE_MASK)  
        self.payloadType = payloadType
        self.payloadSize = payloadSize
        self.payload     = payload
    
    def __print_hex(self, bs):
        s = ''
        for i in range(len(bs)):
            if i == 0:
                s += ''
            elif i % 4 == 0:
                s += '\n' + ' ' * len("PAYLOAD SIZE :")    
            else:
                s += ' '
            s += hex(bs[i])
        return s
    
    def print_head(self):
        s  = "F            :" + str(self.f)           + "\n"
        s += "NRI          :" + str(self.nri)         + "\n"
        s += "TYPE         :" + str(self.type)        + "\n"
        s += "PAYLOAD TYPE :" + str(self.payloadType) + "\n"
        s += "PAYLOAD SIZE :" + str(self.payloadSize) + "\n"
        return s    
    
    def __str__(self):
        s  = "---------" + "\n"
        s += "-- SEI --" + "\n"
        s += "---------" + "\n"
        s += self.print_head()
        s += "PAYLOAD      :"
        s += self.__print_hex(self.payload)
        return s      
        
class StreamLayout(Sei):
    
    def __init__(self, F_NRI_TYPE, payloadType, payloadSize, payload):
        Sei.__init__(self, F_NRI_TYPE, payloadType, payloadSize, payload)
        ptr = UUID_LEN
        self.lpb0, self.lpb1, \
        self.lpb2, self.lpb3, \
        self.lpb4, self.lpb5, \
        self.lpb6, self.lpb7 = extract_fields(payload, ptr, LPB_FMT, LPB_LEN)
        ptr   += LPB_LEN
        r_p    = extract_fields(payload, ptr, R_P_FMT, R_P_LEN)[0]
        self.r = get_bitfield(r_p, SL_R_MASK)
        self.p = get_bitfield(r_p, SL_P_MASK)
        ptr   += R_P_LEN
        
        self.layerList = []
        if self.p:
            ldLen = extract_fields(payload, ptr, LDL_FMT, LDL_LEN)[0]
            ptr  += LDL_LEN
            while ptr < len(payload):
                ld    = extract_fields(payload, ptr, LD_FMT, ldLen)
                self.layerList.append(LayerDescription(*ld))
                ptr  += ldLen
                
    def __str__(self):
        s  = "-----------------------" + "\n"
        s += "-- SEI STREAM LAYOUT --" + "\n"
        s += "-----------------------" + "\n"
        s += self.print_head()
        s += "------" + "\n"
        s += "LPB0 :" + str(self.lpb0) + "\n"
        s += "LPB1 :" + str(self.lpb1) + "\n" 
        s += "LPB2 :" + str(self.lpb2) + "\n"
        s += "LPB3 :" + str(self.lpb3) + "\n"
        s += "LPB4 :" + str(self.lpb4) + "\n"
        s += "LPB5 :" + str(self.lpb5) + "\n"
        s += "LPB6 :" + str(self.lpb6) + "\n"
        s += "LPB7 :" + str(self.lpb7) + "\n"
        s += "LPB7 :" + str(self.lpb7) + "\n"
        s += "R    :" + str(self.r)    + "\n"
        s += "P    :" + str(self.p)    + "\n"
        for ld in self.layerList:
            s += str(ld)
        return s
                 
class LayerDescription:
    
    def __init__(self, codedWidth, codedHeight, dispWidth, dispHeight, bitrate,
                       fpsIdx_lt, prid_cb_r, r2):
        self.codedWidth  = codedWidth
        self.codedHeight = codedHeight
        self.dispWidth   = dispWidth
        self.dispHeight  = dispHeight
        self.bitrate     = bitrate
        self.fpsIdx      = get_bitfield(fpsIdx_lt, FPS_IDX_MASK) 
        self.lt          = get_bitfield(fpsIdx_lt, LT_MASK)
        self.prid        = get_bitfield(prid_cb_r, LD_PRID_MASK)
        self.cb          = get_bitfield(prid_cb_r, CB_MASK)
        self.r           = get_bitfield(prid_cb_r, LD_R_MASK)
        self.r2          = r2
        
    def __str__(self):
        s  = "-- LAYER DESCRIPTION --"                      + "\n"
        s += "CODED WIDTH    :" + str(self.codedWidth)      + "\n"
        s += "CODED HEIGHT   :" + str(self.codedHeight)     + "\n" 
        s += "DISPLAY WIDTH  :" + str(self.dispWidth)       + "\n"
        s += "DISPLAY HEIGHT :" + str(self.dispHeight)      + "\n"
        s += "BITRATE        :" + str(self.bitrate)         + "\n"
        s += "FPSIDX         :" + str(self.fpsIdx)          + "\n"
        s += "FPS            :" + str(FPS_MAP[self.fpsIdx]) + "\n"
        s += "LT             :" + str(self.lt)              + "\n"
        s += "PRID           :" + str(self.prid)            + "\n"
        s += "CB             :" + str(self.cb)              + "\n"
        s += "R              :" + str(self.r)               + "\n"
        s += "R2             :" + str(self.r2)              + "\n"
        return s   

class BitStreamInfo(Sei):
    
    def __init__(self, F_NRI_TYPE, payloadType, payloadSize, payload):
        Sei.__init__(self, F_NRI_TYPE, payloadType, payloadSize, payload)
        ptr = UUID_LEN
        self.refFrmCount, self.numOfNaluUnit = extract_fields(payload, ptr, BSINFO_FMT, BSINFO_LEN)

    def __str__(self):
        s  = "------------------------" + "\n"
        s += "-- SEI BITSTREAM INFO --" + "\n"
        s += "------------------------" + "\n"        
        s += self.print_head()
        s += "------------------" + "\n"
        s += "REF FRAME COUNT  :" + str(self.refFrmCount)   + "\n"
        s += "NUM OF NALU UNIT :" + str(self.numOfNaluUnit) + "\n" 
        return s

def get_bitfield(field, mask):
    bitfield = field & mask
    shifts   = 0
    while not mask & 0x01:
        mask    = mask >> 1
        shifts += 1
    return bitfield >> shifts

def extract_fields(byteArray, startByte, fmtString, totalLen):
    return unpack(fmtString, str(byteArray[startByte : startByte + totalLen]))
    
def parse_pacsi(nal, nalSize):
    ptr       = 0
    pacsi     = Pacsi(*extract_fields(nal, ptr, PACSI_HEAD_FMT, PACSI_HEAD_LEN))
    ptr      += PACSI_HEAD_LEN
    if pacsi.y:
        pacsi.add_opt_Y(*extract_fields(nal, ptr, PACSI_Y_OPT_FIELDS_FMT, PACSI_Y_OPT_FIELDS_LEN))
        ptr += PACSI_Y_OPT_FIELDS_LEN
    if pacsi.t:
        pacsi.add_opt_T(*extract_fields(nal, ptr, PACSI_T_OPT_FIELDS_FMT, PACSI_T_OPT_FIELDS_LEN))
        ptr += PACSI_T_OPT_FIELDS_LEN
    while ptr < nalSize:
        # get SEI size and SEI
        seiSize    = extract_fields(nal, ptr, SEI_SIZE_FMT, SEI_SIZE_LEN)[0]
        ptr       += SEI_SIZE_LEN
        seiNal     = nal[ptr : ptr + seiSize]
        ptr       += seiSize
        # identify first fields of SEI
        fNriType, paylType, paylSize = extract_fields(seiNal, 0, SEI_HDR_FMT, SEI_HDR_LEN)
        if SEI_HDR_LEN + UUID_LEN < seiSize:
            uuid = seiNal[SEI_HDR_LEN : SEI_HDR_LEN + UUID_LEN]
        else:
            uuid = bytearray()
        payload    = seiNal[SEI_HDR_LEN :]
        # create SEI of proper type
        if   uuid == STREAM_LAYOUT_UUID:
            sei = StreamLayout(fNriType, paylType, paylSize, payload)
            pacsi.add_sei(sei)
        elif uuid == BITSREAM_INFO_UUID:
            sei = BitStreamInfo(fNriType, paylType, paylSize, payload)
            pacsi.add_sei(sei)      
        else:
            sei = Sei(fNriType, paylType, paylSize, payload)
            pacsi.add_sei(sei)
    return pacsi
    
          
        
