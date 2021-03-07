import unittest
import pacsi

F_NRI_TYPE      = 0b10011111
R_I_PRID        = 0b10111111
N_DID_QID       = 0b10001111
TID_U_D_O_RR    = 0b11101011
X_Y_T_A_P_C_S_E = 0b10101010

PAYLOAD_TYPE = 5
PAYLOAD_SIZE = 8
PAYLOAD      = bytearray('\xaa\xbb\xcc\xdd\xaa\xbb\xcc\xdd')

SEI_S_LAYOUT_F_NRI_TYPE = 6
SEI_S_LAYOUT_PAY_TYPE   = 5
SEI_S_LAYOUT_PAY_SIZE   = 0x3a
SEI_S_LAYOUT_STR        = '\x13\x9f\xb1\xa9\x44\x6a\x4d\xec\x8c\xbf\x65\xb1\xe1\x2d\x2c'
SEI_S_LAYOUT_STR       += '\xfd\x03\x00\x00\x00\x00\x00\x00\x00\x01\x10\x01\x40\x00\xb4'
SEI_S_LAYOUT_STR       += '\x01\x40\x00\xb4\x00\x01\x28\xe1\x00\x02\x00\x00\x01\x40\x00'
SEI_S_LAYOUT_STR       += '\xb4\x01\x40\x00\xb4\x00\x00\x4a\x37\x11\x06\x00\x00'
SEI_S_LAYOUT            = bytearray(SEI_S_LAYOUT_STR)

SEI_BS_INFO_F_NRI_TYPE  = 6
SEI_BS_INFO_PAY_TYPE    = 5
SEI_BS_INFO_PAY_SIZE    = 0x12
SEI_BS_INFO_STR         = '\x05\xfb\xc6\xb9\x5a\x80\x40\xe5\xa2\x2a\xab\x40\x20\x26\x7e'
SEI_BS_INFO_STR        += '\x26\x01\x04'
SEI_BS_INFO             = bytearray(SEI_BS_INFO_STR)

PACSI_HEAD = '\x7e\xc0\x80\x07\x22\x00\x00'
SEI1_SIZE  = '\x00\x3d'
SEI1_HEAD  = '\x06\x05\x3a'
SEI2_SIZE  = '\x00\x15'
SEI2_HEAD  = '\x06\x05\x12'
PACSI_STR  = PACSI_HEAD + SEI1_SIZE + SEI1_HEAD + SEI_S_LAYOUT_STR + SEI2_SIZE + SEI2_HEAD + SEI_BS_INFO_STR
PACSI      = bytearray(PACSI_STR)

class Test(unittest.TestCase):

    def test_pacsi_when_alternate(self):
        pa = pacsi.Pacsi(F_NRI_TYPE, R_I_PRID, N_DID_QID, TID_U_D_O_RR, X_Y_T_A_P_C_S_E)
        self.assertEquals(pa.f, 0b1)
        self.assertEquals(pa.nri, 0b00)
        self.assertEquals(pa.type, 0b11111)
        
        self.assertEquals(pa.r, 0b1)
        self.assertEquals(pa.i, 0b0)
        self.assertEquals(pa.prid, 0b111111)
        
        self.assertEquals(pa.n, 0b1)
        self.assertEquals(pa.did, 0b000)
        self.assertEquals(pa.qid, 0b1111)
        
        self.assertEquals(pa.tid, 0b111)
        self.assertEquals(pa.u, 0b0)
        self.assertEquals(pa.d, 0b1)
        self.assertEquals(pa.o, 0b0)
        self.assertEquals(pa.rr, 0b11)
        
        self.assertEquals(pa.x, 0b1)
        self.assertEquals(pa.y, 0b0)
        self.assertEquals(pa.t, 0b1)
        self.assertEquals(pa.a, 0b0)
        self.assertEquals(pa.p, 0b1)
        self.assertEquals(pa.c, 0b0)
        self.assertEquals(pa.s, 0b1)
        self.assertEquals(pa.e, 0b0)
        
    def test_pacsi_when_inverted_alternate(self):
        pa = pacsi.Pacsi(~F_NRI_TYPE, ~R_I_PRID, ~N_DID_QID, 
                         ~TID_U_D_O_RR, ~X_Y_T_A_P_C_S_E )
        self.assertEquals(pa.f, 0b0)
        self.assertEquals(pa.nri, 0b11)
        self.assertEquals(pa.type, 0b00000)
        
        self.assertEquals(pa.r, 0b0)
        self.assertEquals(pa.i, 0b1)
        self.assertEquals(pa.prid, 0b000000)
        
        self.assertEquals(pa.n, 0b0)
        self.assertEquals(pa.did, 0b111)
        self.assertEquals(pa.qid, 0b0000)
        
        self.assertEquals(pa.tid, 0b000)
        self.assertEquals(pa.u, 0b1)
        self.assertEquals(pa.d, 0b0)
        self.assertEquals(pa.o, 0b1)
        self.assertEquals(pa.rr, 0b00)
        
        self.assertEquals(pa.x, 0b0)
        self.assertEquals(pa.y, 0b1)
        self.assertEquals(pa.t, 0b0)
        self.assertEquals(pa.a, 0b1)
        self.assertEquals(pa.p, 0b0)
        self.assertEquals(pa.c, 0b1)
        self.assertEquals(pa.s, 0b0)
        self.assertEquals(pa.e, 0b1)       
        
    def test_sei(self):
        sei = pacsi.Sei(F_NRI_TYPE, PAYLOAD_TYPE, PAYLOAD_SIZE, PAYLOAD)
        self.assertEquals(sei.f, 0b1)
        self.assertEquals(sei.nri, 0b00)
        self.assertEquals(sei.type, 0b11111)
        
        self.assertEquals(sei.payloadType, PAYLOAD_TYPE)
        self.assertEquals(sei.payloadSize, PAYLOAD_SIZE)
        self.assertEquals(sei.payload, PAYLOAD)
        print '***** test_sei *****'
        print sei
        
    def test_streamlayout(self, sl=None):
        if not sl:
            sl = pacsi.StreamLayout(SEI_S_LAYOUT_F_NRI_TYPE, SEI_S_LAYOUT_PAY_TYPE, SEI_S_LAYOUT_PAY_SIZE,
                                    SEI_S_LAYOUT)
        self.assertEquals(sl.f, 0)
        self.assertEquals(sl.nri, 0)
        self.assertEquals(sl.type, 6)
        
        self.assertEquals(sl.payloadType, SEI_S_LAYOUT_PAY_TYPE)
        self.assertEquals(sl.payloadSize, SEI_S_LAYOUT_PAY_SIZE)
        
        self.assertEquals(sl.lpb0, 3)
        self.assertEquals(sl.lpb1, 0)
        self.assertEquals(sl.lpb2, 0)
        self.assertEquals(sl.lpb3, 0)
        self.assertEquals(sl.lpb4, 0)
        self.assertEquals(sl.lpb5, 0)
        self.assertEquals(sl.lpb6, 0)
        self.assertEquals(sl.lpb7, 0)
        self.assertEquals(sl.r, 0)
        self.assertEquals(sl.p, 1)
        
        ldIter = iter(sl.layerList)
        
        ld1 = ldIter.next()
        self.assertEquals(ld1.codedWidth, 320)
        self.assertEquals(ld1.codedHeight, 180)
        self.assertEquals(ld1.dispWidth, 320)
        self.assertEquals(ld1.dispHeight, 180)
        self.assertEquals(ld1.bitrate, 76001)
        self.assertEquals(ld1.fpsIdx, 0)
        self.assertEquals(ld1.lt, 0)
        self.assertEquals(ld1.prid, 0)
        self.assertEquals(ld1.cb, 1)
        self.assertEquals(ld1.r, 0)
        self.assertEquals(ld1.r2, 0)
        
        ld2 = ldIter.next()
        self.assertEquals(ld2.codedWidth, 320)
        self.assertEquals(ld2.codedHeight, 180)
        self.assertEquals(ld2.dispWidth, 320)
        self.assertEquals(ld2.dispHeight, 180)
        self.assertEquals(ld2.bitrate, 18999)
        self.assertEquals(ld2.fpsIdx, 2)
        self.assertEquals(ld2.lt, 1)
        self.assertEquals(ld2.prid, 1)
        self.assertEquals(ld2.cb, 1)
        self.assertEquals(ld2.r, 0)
        self.assertEquals(ld2.r2, 0)
        
    def test_bitstreaminfo(self, bi=None):
        if not bi:
            bi = pacsi.BitStreamInfo(SEI_BS_INFO_F_NRI_TYPE, SEI_BS_INFO_PAY_TYPE, SEI_BS_INFO_PAY_SIZE,
                                     SEI_BS_INFO)
        self.assertEquals(bi.f, 0)
        self.assertEquals(bi.nri, 0)
        self.assertEquals(bi.type, 6)
        
        self.assertEquals(bi.payloadType, SEI_BS_INFO_PAY_TYPE)
        self.assertEquals(bi.payloadSize, SEI_BS_INFO_PAY_SIZE) 
        
        self.assertEquals(bi.refFrmCount, 1)
        self.assertEquals(bi.numOfNaluUnit, 4)
       
    def test_parse_pacsi(self):
        pa = pacsi.parse_pacsi(PACSI, len(PACSI))
        
        self.assertEquals(pa.f, 0)
        self.assertEquals(pa.nri, 3)
        self.assertEquals(pa.type, 30)
        
        self.assertEquals(pa.r, 1)
        self.assertEquals(pa.i, 1)
        self.assertEquals(pa.prid, 0)
        
        self.assertEquals(pa.n, 1)
        self.assertEquals(pa.did, 0)
        self.assertEquals(pa.qid, 0)
        
        self.assertEquals(pa.tid, 0)
        self.assertEquals(pa.u, 0)
        self.assertEquals(pa.d, 0)
        self.assertEquals(pa.o, 1)
        self.assertEquals(pa.rr, 3)
        
        self.assertEquals(pa.x, 0)
        self.assertEquals(pa.y, 0)
        self.assertEquals(pa.t, 1)
        self.assertEquals(pa.a, 0)
        self.assertEquals(pa.p, 0)
        self.assertEquals(pa.c, 0)
        self.assertEquals(pa.s, 1)
        self.assertEquals(pa.e, 0)  
        
        seiIter = iter(pa.seiList)
        
        sei1 = seiIter.next()
        self.assertTrue(isinstance(sei1,pacsi.StreamLayout))
        self.test_streamlayout(sei1)

        sei2 = seiIter.next()
        self.assertTrue(isinstance(sei2,pacsi.BitStreamInfo))
        self.test_bitstreaminfo(sei2)
        
        print '***** test_parse_pacsi *****'
        print pa 

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()