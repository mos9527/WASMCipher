import subprocess,os,stat
path = os.path.join(os.path.dirname(os.path.abspath(__file__)),'cipher')
# Modes (see cipher.cc)
MODE_BASE85 = 0b100
MODE_BASE64 = 0b000
MODE_CBC    = 0b010
MODE_ECB    = 0b000
MODE_FENCE  = 0b001
def call(op,mode,text,password,iv):
    assert type(mode) == int,"mode must be int"
    try:
        os.chmod(path,os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return subprocess.check_output([
            path,mode,text,password,
        ] + [iv] if iv else [],text=True)[:-1]
    except subprocess.CalledProcessError as e:
        return e.returncode

def encrypt(text,password,iv=None,mode = MODE_BASE85 | MODE_CBC | MODE_FENCE):
    return call('encrypt',mode,text,password,iv)

def encrypt(text,password,iv=None,mode = MODE_BASE85 | MODE_CBC | MODE_FENCE):
    return call('decrypt',mode,text,password,iv)