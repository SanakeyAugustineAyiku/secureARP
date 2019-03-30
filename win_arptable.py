import os
def f_arptable():
    '''
    reads the arp cache table and returns  a dictionary of lists on success
    :return:
    '''
    F_ARPTABLE = {}
    if os.name == 'nt':
        lines = os.popen('arp -a')
        index = ""
        for line in lines:
            if line == '\n':
                continue

            if line.startswith("Interface"):
                index = line
                F_ARPTABLE[index] = []
                continue
            F_ARPTABLE[index].append(line)
    else:
        raise Exception("This function works only on windows platform")
    return F_ARPTABLE


def arptable():
    '''
    reads the arp cache table and returns  a list on success
    :return:
    '''
    ARPTABLE = []
    if os.name == 'nt':
        lines = os.popen('arp -a')
        for line in lines:
            if line == '\n':
                continue
            ARPTABLE.append(line)
    else:
        raise Exception("This function works only on windows platform")
    return ARPTABLE
