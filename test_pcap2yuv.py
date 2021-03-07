import unittest
import pcap2yuv
import filecmp

PCAP_FILE      = 'pcap/ref.pcap'
PCAP_FILE_FILT = 'pcap/ref_FILTERED.pcap'
SRC_IP_FILT    = '10.17.53.168'
SSRC_FILT      = '889614168,889614169'
SSRC_FILT_HALF = '889614168'
OUT_FILE       = '/tmp/out.yuv'
OUT_PACSI_FILE = '/tmp/pacsi.txt'
OUT_NAL_FILE   = '/tmp/nal.txt'
REF_YUV        = 'raw/ref.yuv'
REF_YUV_HALF   = 'raw/ref_half.yuv'

class Test(unittest.TestCase):

    def test_when_standard(self):
        pcap2yuv.main(PCAP_FILE, SRC_IP_FILT, SSRC_FILT, OUT_FILE, OUT_PACSI_FILE, OUT_NAL_FILE)
        self.assertTrue(filecmp.cmp(OUT_FILE, REF_YUV))

    def test_when_half_fps(self):
        pcap2yuv.main(PCAP_FILE, SRC_IP_FILT, SSRC_FILT_HALF, OUT_FILE, OUT_PACSI_FILE, OUT_NAL_FILE)
        self.assertTrue(filecmp.cmp(OUT_FILE, REF_YUV_HALF))
        
    def test_when_no_filt_srcip(self):
        pcap2yuv.main(PCAP_FILE, '', SSRC_FILT, OUT_FILE, OUT_PACSI_FILE, OUT_NAL_FILE)
        self.assertTrue(filecmp.cmp(OUT_FILE, REF_YUV))
        
    def test_when_filt_srcip_is_wrong(self):
        rval = pcap2yuv.main(PCAP_FILE, '1.1.1.1', SSRC_FILT, OUT_FILE, OUT_PACSI_FILE, OUT_NAL_FILE)
        self.assertEquals(rval, 1)
    
    def test_when_filt_ssrc_is_wrong(self):
        rval = pcap2yuv.main(PCAP_FILE, SRC_IP_FILT, '12345', OUT_FILE, OUT_PACSI_FILE, OUT_NAL_FILE)
        self.assertEquals(rval, 1)
        
    def test_when_pcap_not_exist(self):
        rval = pcap2yuv.main('notexist', SRC_IP_FILT, SSRC_FILT, OUT_FILE, OUT_PACSI_FILE, OUT_NAL_FILE)
        self.assertEquals(rval, 1)
    
    def test_when_out_dir_not_exist(self):
        rval = pcap2yuv.main(PCAP_FILE, SRC_IP_FILT, SSRC_FILT, '/notexist/out.yuv', OUT_PACSI_FILE, OUT_NAL_FILE)
        self.assertEquals(rval, 1)        
       
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()