# This plugins requires kernel structures which are not inside default volatility linux profile.
# In order to use it, is necessary to modify module.c file importing two diffferent libraries:
# tcp_sock: #include <linux/tcp.h>
# inet_connection_sock: #include <net/inet_connection_sock.h>

"""
@author: Luca Doglione, Marco Senno
@license: 
@contact: 
"""

import socket
import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.pslist as linux_pslist

class linux_dump_sock(linux_pslist.linux_pslist):
    """Dumps infos about opened socket of a process"""
    
    TCPI_OPT_TIMESTAMPS = 1
    TCPI_OPT_SACK = 2
    TCPI_OPT_WSCALE = 4
    TCPI_OPT_ECN = 8
    TCPI_OPT_ECN_SEEN = 16
    TCPI_OPT_SYN_DATA = 32
    TCP_ECN_OK = 1
    TCP_ECN_SEEN = 8

    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)


    def calculate(self):
        if not self._config.PID:
            debug.error("You have to specify a process to dump. Use the option -p.\n")
        
        #Retrieve the task_struct of the process
        tasks = linux_pslist.linux_pslist.calculate(self)
        for task in tasks:
            yield task 

    def get_tcpi_options(self, tcp_sock):
        options = 0

        if tcp_sock.rx_opt.tstamp_ok:
            options |= self.TCPI_OPT_TIMESTAMPS

        if tcp_sock.rx_opt.sack_ok:
            options |= self.TCPI_OPT_SACK

        if tcp_sock.rx_opt.wscale_ok:
            options |= self.TCPI_OPT_WSCALE

        if tcp_sock.ecn_flags & self.TCP_ECN_OK:
            options != self.TCPI_OPT_ECN

        if tcp_sock.ecn_flags & self.TCP_ECN_SEEN:
            options != self.TCPI_OPT_ECN_SEEN

        if tcp_sock.syn_data_acked:
            options != self.TCPI_OPT_SYN_DATA

        return options



    def get_sock_info(self, task):

        sockets_dic = {}
        sockets = []
        flags = []
        fds = []

        for inode, fd in task.lsof():
                path = linux_common.get_path(task, inode)
                if "socket:[" in path:
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

                    inet_sock = node.cast("inet_connection_sock")
                    sock_backlog = inet_sock.icsk_backoff
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

                    if proto == "TCP":

                        # Readig values for tcp_info structure, this structure is used by CRIU, 
                        # but it's not a kernel structure,
                        # in kernel source (http://lxr.free-electrons.com/source/net/ipv4/tcp.c#L2644) 
                        # values are read using 2 different kernel structures (tcp_sock, inet_connection_sock)
                        # tcp_get_info: http://lxr.free-electrons.com/source/include/linux/tcp.h#L371
                        tcp_sock = node.cast("tcp_sock")

                        tcp_snd_wscale = tcp_sock.rx_opt.snd_wscale
                        tcp_rcv_wscale = tcp_sock.rx_opt.rcv_wscale
                        tcp_mss_clamp = tcp_sock.rx_opt.mss_clamp
                        tcp_mask = self.get_tcpi_options(tcp_sock)
                        tcp_inq_len = tcp_sock.rcv_nxt - tcp_sock.copied_seq
                        tcp_outq_len = tcp_sock.write_seq - tcp_sock.snd_una
                        tcp_inq_seq = tcp_sock.rcv_nxt
                        tcp_outq_seq = tcp_sock.write_seq
                        tcp_unsq_len = 0 #Not Found
                        tcp_timestamp = 0 #Not Found
                        tcp_stream_data = {
                                            "inq_len":int(tcp_inq_len),
                                            "inq_seq":int(tcp_inq_seq),
                                            "outq_len":int(tcp_outq_len),
                                            "outq_seq":int(tcp_outq_seq),
                                            "opt_mask":"{0:#x}".format(tcp_mask),
                                            "snd_wscale":int(tcp_snd_wscale),
                                            "mss_clamp":int(tcp_mss_clamp),
                                            "rcv_wscale":int(tcp_rcv_wscale),
                                            "timestamp":int(tcp_timestamp),
                                            "unsq_len":int(tcp_unsq_len),
                                            "extra":{"outq":"", "inq":""}
                                            }
                        sockets_dic[sock_ino]["tcp_stream"] = tcp_stream_data

        return sockets_dic

                #elif ents[0] == 1 and not self._config.IGNORE_UNIX:
                 #   (name, inum) = ents[1]
                  #  outfd.write("UNIX {0:<8d} {1:>17s}/{2:<5d} {3:s}\n".format(inum, task.comm, task.pid, name)).sk.sk_rcvbuf

    def render_text(self, outfd, data):
        
        for task in data:
            dic = self.get_sock_info(task)

            for key, val in dic.iteritems():
                print val
