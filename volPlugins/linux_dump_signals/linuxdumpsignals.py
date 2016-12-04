"""
@author: Luca Doglione, Marco Senno
@license: GNU General Public Licens 2.0
@contact: doglione.luca@gmail.com, senno.marco@gmail.com
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

signals = {
    1:"SIGHUP",
    2:"SIGINT",
    3:"SIGQUIT",
    4:"SIGILL",
    5:"SIGTRAP",
    6:"SIGABRT",
    7:"SIGBUS",
    8:"SIGFPE",
    9:"SIGKILL",
    10:"SIGUSR1",
    11:"SIGSEGV",
    12:"SIGUSR2",
    13:"SIGPIPE",
    14:"SIGALRM",
    15:"SIGTERM",
    16:"SIGSTKFLT",
    17:"SIGCHLD",
    18:"SIGCONT",
    19:"SIGSTOP",
    20:"SIGTSTP",
    21:"SIGTTIN",
    22:"SIGTTOU",
    23:"SIGURG",
    24:"SIGXCPU",
    25:"SIGXFSZ",
    26:"SIGVTALRM",
    27:"SIGPROF",
    28:"SIGWINCH",
    29:"SIGIO",
    30:"SIGPWR",
    31:"SIGSYS",
    32:"SIGWAITING",
    33:"SIGLWP",
    34:"SIGRTMIN",
    35:"SIGRTMIN+1",
    36:"SIGRTMIN+2",
    37:"SIGRTMIN+3",
    38:"SIGRTMIN+4",
    39:"SIGRTMIN+5",
    40:"SIGRTMIN+6",
    41:"SIGRTMIN+7",
    42:"SIGRTMIN+8",
    43:"SIGRTMIN+9",
    44:"SIGRTMIN+10",
    45:"SIGRTMIN+11",
    46:"SIGRTMIN+12",
    47:"SIGRTMIN+13",
    48:"SIGRTMIN+14",
    49:"SIGRTMIN+15",
    50:"SIGRTMAX-14",
    51:"SIGRTMAX-13",
    52:"SIGRTMAX-12",
    53:"SIGRTMAX-11",
    54:"SIGRTMAX-10",
    55:"SIGRTMAX-9",
    56:"SIGRTMAX-8",
    57:"SIGRTMAX-7",
    58:"SIGRTMAX-6",
    59:"SIGRTMAX-5",
    60:"SIGRTMAX-4",
    61:"SIGRTMAX-3",
    62:"SIGRTMAX-2",
    63:"SIGRTMAX-1",
    64:"SIGRTMAX"
}

class linux_dump_signals(linux_pslist.linux_pslist):
    """Dumps sigactions of a process"""
   
    def __init__(self, config, *args, **kwargs):
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)


    def calculate(self):
        if not self._config.PID:
            debug.error("You have to specify a process to dump. Use the option -p.\n")
        
        #Retrieve the task_struct of the process
        tasks = linux_pslist.linux_pslist.calculate(self)
        for task in tasks:
            yield task 

    
    #Method for reading an address range in memory dump
    def read_addr_range(self, task, start, size):
        proc_as = task.get_process_address_space()
        segment = proc_as.zread(start, size)
        return segment

    #Method for reading a value from memory and reverse it to Big-Endian format
    def read_field(self, task, start, size):
        reverse = []
        #sigaction
        data = self.read_addr_range(task, start, size)
        for c in data:
            reverse.insert(0, "{0:02x}".format(ord(c)))
            
        reverse.insert(0, "0x")
        return ''.join(reverse)

    #Method for generating sigactions
    def read_sigactions(self, task):
    
        sigacts = []
        handler = task.sighand
        action_vector = handler+8
        
        #Signal SIGKILL(9) and SIGSTOP(19) are not considered
        for i in range(1, 65):
            if i == 9 or i == 19:
                action_vector += 32
                continue
        
            action = self.read_field(task, action_vector, 8)
            action_vector += 8

            flags = self.read_field(task, action_vector, 4)
            #Sarebbero 4 di flags ma ci sono altri 4 a 0(?)
            action_vector += 8
    
            restorer = self.read_field(task, action_vector, 8)
            action_vector += 8
            
            mask = self.read_field(task, action_vector, 8)
            
            action_element = {"sigaction":action, "flags":flags, "restorer":restorer, "mask":mask}
            sigacts.append(action_element)
            
            action_vector += 8
        
        return sigacts


    def render_text(self, outfd, data):
        global signals

        for task in data:

            print "Dumping sigactions for process: {0}".format(self._config.PID)
            acts = self.read_sigactions(task)
            self.table_header(outfd, [("ID", "2"), ("Signal", "12"), ("Sigaction", "18"), ("Flags",   "10"), ("Restorer", "18"), ("Mask", "18")])

            #Print results
            for i in range(0, 62):
                if i >= 8 and i < 17:
                    sig_id = i + 2
                    # print signal 9
                elif i >= 17:
                    sig_id = i + 3
                    # print signal 19
                else:
                    sig_id = i + 1

                self.table_row(outfd, sig_id, signals[sig_id], acts[i]["sigaction"], acts[i]["flags"], acts[i]["restorer"], acts[i]["mask"])
            
