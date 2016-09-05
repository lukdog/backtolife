import socket
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.pslist as linux_pslist

class linux_dump_sock(linux_pslist.linux_pslist):
    """Dumps infos about opened socket of a process"""
    
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)


    def calculate(self):
        if not self._config.PID:
            debug.error("You have to specify a process to dump. Use the option -p.\n")
        
        #Retrieve the task_struct of the process
        tasks = linux_pslist.linux_pslist.calculate(self)
        for task in tasks:
            yield task 

    def get_sock_info(self, task):

        sockets_dic = {}
        sockets = []
        flags = []
        fds = []

        for inode, fd in task.lsof():
                path = linux_common.get_path(task, inode)
                if "socket" in path:
                    path = path.replace("[", "")
                    path = path.replace("]", "")
                    ino = path.split(":")[1]
                    fds.append(fd-1)
                    sockets.append(ino)
                    flags.append(inode.f_flags)

         

        i = 0
        for ents in task.netstat():
                if ents[0] == socket.AF_INET:
                    (node, proto, sock_saddr, sock_sport, sock_daddr, sock_dport, state) = ents[1]

                    sock_state = node.sk.__sk_common.skc_state
                    sock_proto = node.sk.sk_protocol
                    sock_family = node.sk.__sk_common.skc_family
                    sock_type = node.sk.sk_type
                    sock_backlog = node.sk.sk_type
                    sock_sndbuf = node.sk.sk_sndbuf
                    sock_rcvbuf = node.sk.sk_rcvbuf

                    if node.sk.__sk_common.skc_reuse == 0:
                        sock_reuseaddr = False
                    else:
                        sock_reuseaddr = True

                    sock_priority = node.sk.sk_priority
                    sock_rowlat = node.sk.sk_rcvlowat
                    sock_mark = node.sk.sk_mark
                    sock_ino = sockets[i]
                    sock_flags = flags[i]
                    sock_id = fds[i]
                    i += 1

                    sockets_dic[sock_ino] = { 
                                                "id":int(sock_id),
                                                "ino":int(sock_ino),
                                                "family":int(sock_family),
                                                "type":int(sock_type),
                                                "proto":int(sock_proto),
                                                "state":int(sock_state),
                                                "src_port":int(sock_sport),
                                                "dst_port":int(sock_dport),
                                                "flags":"{0:#x}".format(sock_flags),
                                                "backlog":int(sock_backlog),
                                                "src_addr":[str(sock_saddr)],
                                                "dst_addr":[str(sock_daddr)],
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
                                                "ip_opts":{}
                                                }

        return sockets_dic

                #elif ents[0] == 1 and not self._config.IGNORE_UNIX:
                 #   (name, inum) = ents[1]
                  #  outfd.write("UNIX {0:<8d} {1:>17s}/{2:<5d} {3:s}\n".format(inum, task.comm, task.pid, name)).sk.sk_rcvbuf

    def render_text(self, outfd, data):
        
        for task in data:
            dic = self.get_sock_info(task)

            for key, val in dic.iteritems():
                print val
