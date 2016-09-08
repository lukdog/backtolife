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

class linux_dump_auxv(linux_pslist.linux_pslist):
    """Read Auxiliary Vector of a process"""
    
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

    #Method for reading auxiliary vector
    def read_auxv(self, task):
        mm = task.mm
        saved_auxv = []
        addr = int(mm.__str__()) + 320
        ymmh_space_vect = []
        for i in range(0, 38):
            reverse = []
            dataByte = self.read_addr_range(task, addr, 8)
            for c in dataByte:
                reverse.insert(0, "{0:02x}".format(ord(c)))
            
            reverse.insert(0, "0x")
            value = ''.join(reverse)
            saved_auxv.append(int(value, 16))
            addr += 8

        return saved_auxv
        


    def render_text(self, outfd, data):
        
        for task in data:

            print "Auxiliary Vector for process: {0}".format(self._config.PID)
            aux = self.read_auxv(task)
            self.table_header(outfd, [("Key", "10"), ("Value", "#018x")])

            for i in range(0, 38, 2):
                self.table_row(outfd, aux[i], aux[i+1])
            
