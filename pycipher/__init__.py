from . import cipher
# Modes (see cipher.cpp)
MODE_BASE85 = 0b100
MODE_BASE64 = 0b000
MODE_CBC    = 0b010
MODE_ECB    = 0b000
MODE_FENCE  = 0b001
def encrypt(src,password,iv=None,mode = MODE_BASE85 | MODE_CBC | MODE_FENCE):
    return cipher.encrypt(src,password,iv or '',mode)

def decrypt(src,password,iv=None,mode = MODE_BASE85 | MODE_CBC | MODE_FENCE):
    return cipher.decrypt(src,password,iv or '',mode) 