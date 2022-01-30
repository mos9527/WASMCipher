import subprocess
def encrypt(text,pwd,iv):
    return subprocess.check_output(["./cipher","encrypt",text,pwd,iv],text=True)[:-1]
def decrypt(text,pwd,iv):
    return subprocess.check_output(["./cipher","decrypt",text,pwd,iv],text=True)[:-1]    
__all__ = [encrypt,decrypt]