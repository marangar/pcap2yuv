from ctypes import * #IGNORE:W0614

SVC_RVAL = c_int
SVC_STATUS_ERROR = SVC_RVAL(-1)
SVC_STATUS_OK    = SVC_RVAL(0)
SVC_IMAGE_READY  = SVC_RVAL(1)
SVC_GHOST_IMAGE  = SVC_RVAL(2)	

class OPENSVCFRAME(Structure):
    _fields_ = [("Width", c_int),
                ("Height", c_int),
                ("pY", POINTER(c_ubyte) * 1),
                ("pU", POINTER(c_ubyte) * 1),
                ("pV", POINTER(c_ubyte) * 1)]

class SVCException(Exception):
    pass

class SVCDecoder():
    def __init__(self):
        # init decoder
        self.lib = CDLL("libopensvc.so")
        self.dec_data = c_void_p()
        rval = self.lib.SVCDecoder_init(byref(self.dec_data))
        if rval == SVC_STATUS_ERROR: 
            raise SVCException('SVCDecoder_init failed')
        # init command table		
        self.command_table = (c_int * 4) ()
        t_com = c_int(0)	
        self.lib.SetCommandLayer(self.command_table, c_int(255), c_int(0), byref(t_com), c_int(0))
        # init frame
        self.frame = OPENSVCFRAME()

    def decode_nal(self, nal, nal_size):
        # set command table		
        t_com = c_int(3)	
        self.lib.SetCommandLayer(self.command_table, c_int(0), c_int(0), byref(t_com), c_int(0))
        # init input data
        nal_data = (c_ubyte * nal_size) (*[nal[i] for i in range(nal_size)])
        # decode nal		
        rval = self.lib.decodeNAL(self.dec_data, nal_data, c_int(nal_size), byref(self.frame), self.command_table)
        if rval == SVC_STATUS_ERROR.value:
            raise SVCException('decodeNAL failed')
        elif rval == SVC_STATUS_OK.value:
            return 0
        elif rval == SVC_IMAGE_READY.value:
            return 1		
        elif rval == SVC_GHOST_IMAGE.value:
            return 2
        else:
            raise SVCException('Unexpected return value from decodeNAL: ' + str(rval))

    def write_frame(self, fd):
        # check file is opened correctly
        try:
            if fd.closed:
                raise SVCException('File-descriptor not opened')
            if fd.mode != 'wb':
                raise SVCException('Invalid file-descriptor mode')
        except AttributeError:
            raise SVCException('Invalid file-descriptor')
        # get last frame data        
        PicWidth  = self.frame.Width  + 32
        PicHeight = self.frame.Height + 32
        Y = self.frame.pY[0]
        U = self.frame.pU[0]
        V = self.frame.pV[0]
        # write yuv
        XDIM = PicWidth  - 32
        YDIM = PicHeight - 32
        for i in range(YDIM):
            l = i * PicWidth                
            fd.write(bytearray( Y[l : l + XDIM] ))
        for i in range(YDIM >> 1):
            l = i * (PicWidth >> 1)
            fd.write(bytearray( U[l : l + (XDIM >> 1)] ))
        for i in range(YDIM >> 1):
            l = i * (PicWidth >> 1)
            fd.write(bytearray( V[l : l + (XDIM >> 1)] ))

    def close(self):
        # close decoder		
        self.lib.SVCDecoder_close(self.dec_data)

