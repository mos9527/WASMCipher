import math
class CRC:
    @staticmethod
    def inv_bit(v,size):        
        new = 0
        for i in range(0,size):
            new |= v & 1
            new <<= 1 if i != size - 1 else 0
            v = v >> 1                      
        return new        
    @staticmethod
    def poly_size(poly):
        return math.ceil(math.log2(poly) / 8)
    @staticmethod
    def make_initial(init,size):
        crc,size = 0,size>>2
        for _ in range(0,size):
            crc <<= 4
            crc |= init        
        return crc
    @staticmethod
    def gen_table(poly):
        table = [0] * 256
        for i in range(0,256):    
            r = i        
            for _ in range(0,8):r = (r >> 1) ^ poly if (r & 1) else r >> 1
            table[i] = r
        return table            
    def calc(self,data):
        crc = self.init
        for n in data:crc = (crc>>8) ^ self.table[(crc ^ n) & 0xFF]
        return self.mask ^ crc
    def __init__(self,poly,init=0xF,inv=False):        
        self.size = self.poly_size(poly) << 3 # in bits
        self.mask = self.make_initial(0xF,self.size)
        self.poly = self.inv_bit(poly,self.size) if inv else poly
        self.table = self.gen_table(self.poly)        
        self.init = self.make_initial(init,self.size)        
import sys
if len(sys.argv) == 2:
    poly = int(sys.argv[1],base=16)
    crc = CRC(poly,inv=True)
    print('** CRC Size(in bits) :',crc.size)
    print('** CRC Poly:',hex(crc.poly))
    print('** CRC Mask:',hex(crc.mask))
    print('** CRC Table:',end='\n{\n')
    for a in range(0,16):        
        print(end='    ')
        for b in range(0,16):
            print('0x'+hex(crc.table[a * 8 + b])[2:].rjust(crc.size // 4,'0'),end=',')
        print(' ')
    print('}')
    print('** Test with data 0x01020304:',hex(crc.calc(b'\x01\x02\x03\x04')))