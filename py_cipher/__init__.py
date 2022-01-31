import subprocess,os,stat
path = os.path.join(os.path.dirname(os.path.abspath(__file__)),'cipher')
os.chmod(path,os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
def encrypt(text,pwd,iv):
    try:
        return subprocess.check_output([path,"encrypt",text,pwd,iv],text=True)[:-1]
    except subprocess.CalledProcessError as e:
        return e.returncode
def decrypt(text,pwd,iv):
    try:
        return subprocess.check_output([path,"decrypt",text,pwd,iv],text=True)[:-1]
    except subprocess.CalledProcessError as e:
        return e.returncode
__all__ = [encrypt,decrypt]