import subprocess,os,stat
path = os.path.join(os.path.abspath(__file__,'cipher'))
os.chmod(path,os.stat(path) | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
def encrypt(text,pwd,iv):
    return subprocess.check_output([path,"encrypt",text,pwd,iv],text=True)[:-1]
def decrypt(text,pwd,iv):
    return subprocess.check_output([path,"decrypt",text,pwd,iv],text=True)[:-1]    
__all__ = [encrypt,decrypt]