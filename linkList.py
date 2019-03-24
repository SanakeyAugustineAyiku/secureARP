class Node:

    def __init__(self, ip, mac, r_type):
        self.ip = ip
        self.mac = mac
        self.r_type = r_type
        self.next = None


class linkList:

    def __init__(self):
        self.head = None
        self.items = 0

    def append(self, ip, mac, r_type):

        new_node = Node(ip, mac, r_type)

        if self.head is None:
            self.head = new_node
        else:
            self.head.next = new_node
        self.items += 1

    def pop(self, ip, mac, ):

        ptr = self.head
        prev = None

        while ptr.next is not None:
            prev = ptr
            if ptr.ip == ip and ptr.mac == mac:
                node = ptr
                break
            else:
                ptr.next

        if prev is not None:
            prev.next = None

        return node.ip, node.mac, node.r_type

    def length(self):
        return self.items

    def display(self):
        ptr = self.head
        # print("%s%s%s" % ("_"*17, "_"*17, "_"*17))
        # print("|%s\t|%s\t|%s|" % ("address".center(15), "mac".center(17), "type".center(10)))
        # print("%s%s%s" % ("-" * 17, "-" * 17, "-" * 17))
        while ptr:
            print("|%s\t|%s\t|%s|" % (ptr.ip.center(15), ptr.mac.center(17), ptr.r_type.center(10)))
            ptr = ptr.next

    def isEmpty(self):
        return self.head is None



if __name__ == '__main__':
    llist = linkList()
    llist.append("192.168.10.10", "aa:00:ff:aa:00:01", "static")
    llist.append("192.168.10.101", "aa:00:ff:aa:00:11", "dynamic")
    print(llist.length())
    llist.display()
    print(llist.pop("192.168.10.10", "aa:00:ff:aa:00:01"))
    llist.display()
