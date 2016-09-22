"""
@author: Luca Doglione, Marco Senno
@license: 
@contact: 
"""

import socket
import base64
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.pslist as linux_pslist

class linux_dump_unix_sock(linux_pslist.linux_pslist):
    """Dumps infos about opened socket of a process"""


    peers = {}

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)


    def calculate(self):
        if not self._config.PID:
            debug.error("You have to specify a process to dump. Use the option -p.\n")
        
        #Retrieve the task_struct of the process
        tasks = linux_pslist.linux_pslist.calculate(self)
        for task in tasks:
            yield task 


    def SOCKET_I(self, addr_space, inode):
        # if too many of these, write a container_of
        backsize = addr_space.profile.get_obj_size("socket")
        addr = inode - backsize

        return obj.Object('socket', offset = addr, vm = addr_space)

   
    def get_sock_info(self, addr_space_arg, task):

        sockets = []

        addr_space = addr_space_arg

        sfop = addr_space.profile.get_symbol("socket_file_ops")
        dfop = addr_space.profile.get_symbol("sockfs_dentry_operations")
        
        for filp, fdnum in task.lsof(): 
            if filp.f_op == sfop or filp.dentry.d_op == dfop:
                iaddr = filp.dentry.d_inode
                skt = self.SOCKET_I(addr_space, iaddr)
                inet_sock = obj.Object("inet_sock", offset = skt.sk, vm = addr_space)

                if inet_sock.protocol in ("TCP", "UDP", "IP", "HOPOPT"):
                    family = inet_sock.sk.__sk_common.skc_family

                    if family == 1: # AF_UNIX
                        node = obj.Object("unix_sock", offset = inet_sock.sk.v(), vm = addr_space)
                       

                        #print "Node: {0:#x}".format(node)
                        #print "Peer: {0:#x}".format(node.peer)
                        #continue
                        
                        sock_ino = iaddr.i_ino

                        if node.addr:
                            name_obj = obj.Object("sockaddr_un", offset = node.addr.name.obj_offset, vm = addr_space)
                            name   = str(name_obj.sun_path)
                        else:
                            name = ""

                        sock_state = node.sk.__sk_common.skc_state
                        sock_type = node.sk.sk_type

                        
                        sock_backlog =  0 ###Cercarlo
                        sock_sndbuf = node.sk.sk_sndbuf
                        sock_rcvbuf = node.sk.sk_rcvbuf

                        if node.sk.__sk_common.skc_reuse == 0:
                            sock_reuseaddr = False
                        else:
                            sock_reuseaddr = True

                        sock_priority = node.sk.sk_priority
                        sock_rowlat = node.sk.sk_rcvlowat
                        sock_mark = node.sk.sk_mark
                        sock_flags = filp.f_flags
                        sock_id = fdnum -1

                        sockets.append({ 
                                                "id":int(sock_id),
                                                "ino":int(sock_ino),
                                                "type":int(sock_type),
                                                "state":int(sock_state),
                                                "flags":"{0:#x}".format(sock_flags),
                                                "uflags":"0x0",
                                                "backlog":int(sock_backlog),
                                                "peer":1,
                                                "opts":{
                                                            "so_sndbuf":int(sock_sndbuf),
                                                            "so_rcvbuf":int(sock_rcvbuf),
                                                            "so_snd_tmo_sec":0,
                                                            "so_snd_tmo_usec":0,
                                                            "so_rcv_tmo_sec":0,
                                                            "so_rcv_tmo_usec":0,
                                                            "reuseaddr": sock_reuseaddr,
                                                            "so_priority":int(sock_priority),
                                                            "so_rcvlowat":int(sock_rowlat),
                                                            "so_mark":int(sock_mark),
                                                            "so_passcred": False,
                                                            "so_passsec":False, 
                                                            "so_dontroute": False,
                                                            "so_no_check": False

                                                        },
                                                "name": base64.b64encode(name.encode('ascii')) + '\n'
                                                })
                        
                        #peer for the socket
                        peer = node.peer
                        peerNode = obj.Object("unix_sock", offset=peer.v(), vm=addr_space)
                        if peerNode.addr:
                            peer_name_obj = obj.Object("sockaddr_un", offset = peerNode.addr.name.obj_offset, vm = addr_space)
                            peer_name   = str(peer_name_obj.sun_path)
                        else:
                            peer_name = ""
                        sockets.append({ 
                                                "id":0,
                                                "ino":1,
                                                "type":1,
                                                "state":1,
                                                "flags":"0x0",
                                                "uflags":"0x1",
                                                "backlog":0,
                                                "peer":0,
                                                "opts":{
                                                            "so_sndbuf":0,
                                                            "so_rcvbuf":0,
                                                            "so_snd_tmo_sec":0,
                                                            "so_snd_tmo_usec":0,
                                                            "so_rcv_tmo_sec":0,
                                                            "so_rcv_tmo_usec":0
                                                        },
                                                "name":base64.b64encode(peer_name.encode('ascii')) + '\n'
                                                })

                        if peer_name != "":
                            self.peers[sock_id] = peer_name

        return sockets
                        
    def render_text(self, outfd, data):
        
        for task in data:
            sock = self.get_sock_info(self.addr_space, task)
            print "Unix Socket for process with pid: " + self._config.PID
            self.table_header(outfd, [("INode", "10"), ("FD",   "6"), ("State", "6"), ("Unix Socket Name", "")])
            for val in sock:
               if val["id"] != 0:

                    if val["name"] == '\n' and val["id"] in self.peers:
                        self.table_row(outfd, val["ino"], val["id"]+1, val["state"], self.peers[val["id"]].split('\n')[0])
                    else:
                        self.table_row(outfd, val["ino"], val["id"]+1, val["state"], base64.b64decode(val["name"].split('\n')[0]))
