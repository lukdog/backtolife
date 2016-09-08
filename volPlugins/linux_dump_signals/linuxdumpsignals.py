"""
@author: Luca Doglione, Marco Senno
@license: 
@contact: 
"""

import volatility.obj as obj
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.lsof as linux_lsof
import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address

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

    #Method for generating sigactions
    def read_sigactions(self, task):
    
        sigacts = []
        handler = task.sighand
        action_vector = handler+8
        
        #Signal SIGKILL(9) and SIGSTOP(19) are not considered
        for i in range(1, 65):
            if i == 9 or i == 19:
                action_vector+=32
                continue
        
            reverse = []
            #sigaction
            sigaction = self.read_addr_range(task, action_vector, 8)
            for c in sigaction:
                reverse.insert(0, "{0:02x}".format(ord(c)))
                
            reverse.insert(0, "0x")
            action = ''.join(reverse)
            
            reverse = []
            action_vector+=8
            #flags
            sigaction = self.read_addr_range(task, action_vector, 4)
            for c in sigaction:
                reverse.insert(0, "{0:02x}".format(ord(c)))
                
            reverse.insert(0, "0x")
            flags = ''.join(reverse)
            
            reverse = []
            #Sarebbero 4 di flags ma ci sono altri 4 a 0(?)
            action_vector+=8
            #restorer
            sigaction = self.read_addr_range(task, action_vector, 8)
            for c in sigaction:
                reverse.insert(0, "{0:02x}".format(ord(c)))
                
            reverse.insert(0, "0x")
            restorer = ''.join(reverse)
            
            reverse = []
            action_vector += 8
            #mask
            sigaction = self.read_addr_range(task, action_vector, 8)
            for c in sigaction:
                reverse.insert(0, "{0:02x}".format(ord(c)))
                
            reverse.insert(0, "0x")
            mask = ''.join(reverse)
            
            action_element = {"sigaction":action, "flags":flags, "restorer":restorer, "mask":mask}
            sigacts.append(action_element)
            
            action_vector += 8
        
        return sigacts


    def render_text(self, outfd, data):
        
        for task in data:

            print "Dumping sigactions for process: {0}".format(self._config.PID)
            acts = self.read_sigactions(task)
            self.table_header(outfd, [("Signal", "2"), ("Sigaction", "18"), ("Flags",   "10"), ("Restorer", "18"), ("Mask", "18")])

            #Print results
            for i in range(1, 62):
                if i == 7 or i == 17:
                    sig_id = i+2
                    continue
                else:
                    sig_id = i

                self.table_row(outfd,sig_id, acts[i]["sigaction"], acts[i]["flags"], acts[i]["restorer"], acts[i]["mask"])
            
