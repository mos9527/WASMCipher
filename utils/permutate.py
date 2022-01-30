import random,sys

def randcombo(src): # dfs,O(N)
    if not src: return []
    c=random.choice(src)
    src.remove(c)
    return [c] + randcombo(src)

def pstr(str):
    return ''.join(randcombo(list(str)))

if len(sys.argv) == 2:
    print(pstr(sys.argv[1]))
elif len(sys.argv) == 3:
    _,a1,a2 = sys.argv
    _ = 0
    print('** Finding %s in random combos of %s' % (a1,a2))
    while not a1 in (a3:=pstr(a2)):_ += 1
    print('** Found %s with %s passes' % (a3,_))
else:    
    print(randcombo(list(range(0,256))))