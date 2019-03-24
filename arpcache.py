from win_arptable import arptable
import os
try:
    from python_arptable import ARPTABLE
except:
    pass


# class ARPTABLE:
#
# def __init__(self):
#     pass

def ARPcache():
    if os.name == 'poxit':
        return ARPTABLE
    elif os.name is 'nt':
        return arptable()
    else:
        raise Exception("Platform not supported")

def SARPtable():
    if os.name == 'nt':
        separator = "\\"
    separator ="/"
    sapconf ="conf%sSARP.conf"%separator
    addressess = []
    with open(sapconf, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith('#') or line.startswith('\n'):
                continue
            else:
                line = line.strip(" ").rstrip('\n')
                line = line.split(" ")
                for i in range(len(line)):
                    for word in line:
                        if word is '' or word is ' ':
                            line.remove(word)
                ip,mac = line

                addressess.append((ip,mac))

    return addressess

def DARPtable():
    pass


print(SARPtable())