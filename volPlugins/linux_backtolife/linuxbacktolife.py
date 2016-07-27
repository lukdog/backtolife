
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.dump_map as linux_dump_map
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import struct
import os
import json
from ctypes import *

class linux_backtolife(linux_proc_maps.linux_proc_maps):
    """Generate pages file for CRIU"""

    def __init__(self, config, *args, **kwargs):
        linux_proc_maps.linux_proc_maps.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = "./", help = 'Output directory', action = 'store', type = 'str')
        #self._config.add_option('BUILD_JSON', short_option = 'j', default = None, help = 'Output json file with memory map', action = 'store', type = 'str') 
    
    def read_addr_range(self, task, start, end):
        pagesize = 4096 
        proc_as = task.get_process_address_space()
        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize

    def protText(self, flag):
        prot = ""
        r = False
        if "r" in flag:
            prot += "PROT_READ"
            r = True

        if "w" in flag:
            if r:
                prot += " | "
            prot += "PROT_WRITE"
            r = True

        if "x" in flag:
            if r:
                prot += " | "
            prot += "PROT_EXEC"

        return prot

    def flagsText(self, name):
        flags = ""
        
        if ".cache" in name:
            flags += "MAP_SHARED"
            return flags
        
        flags += "MAP_PRIVATE"
        
        if name == "" or "[" in name:
            flags += " | MAP_ANON"
            
        if name == "[stack]":
            flags += " | MAP_GROWSDOWN"

        return flags
        
    def statusText(self, name):
        flags = "VMA_AREA_REGULAR"
        
        if ".cache" in name:
            flags += " | VMA_FILE_SHARED"
            return flags
        
        if name != "" and not "[" in name:
            flags += " | VMA_FILE_PRIVATE"
                
        if name == "[heap]":
            flags += " | VMA_AREA_HEAP"
            
        if name == "[vdso]":
            flags += " | VMA_AREA_VDSO"
        
        if name == "" or "[" in name:
            flags += " | VMA_ANON_PRIVATE"

        return flags
    
    def getShmid(self, progname, current_name, dic):
        if current_name == "" or "[" in current_name:
            return 0

        if current_name == progname:
            return 2

        if current_name in dic:
            return dic[current_name]
        else:
            dic[current_name] = len(dic) + 3
            return dic[current_name]

    def render_text(self, outfd, data):
        if not self._config.PID:
            debug.error("You have to specify a process to dump. Use the option -p.\n")
        

        file_name = "pages-1.img"
        file_path = os.path.join(self._config.DUMP_DIR, file_name)
        
        progName = ""
        shmidDic = {}
        
        print "Creating pages file of PID: " + self._config.PID
        buildJson = True
        
        pagemap = open("pagemap-{0}.json".format(self._config.PID), "w")
        pagemapData = {"magic":"PAGEMAP", "entries":[{"pages_id":1}]}
        
        mmFile = open("mm-{0}.json".format(self._config.PID), "w")
        mmData = {"magic":"MM", "entries":[{"mm_start_code": 0,
                                            "mm_end_code":0,
                                            "mm_start_data":0,
                                            "mm_end_data":0,
                                            "mm_start_stack":0,
                                            "mm_start_brk":0,
                                            "mm_brk":0,
                                            "mm_arg_start":0,
                                            "mm_arg_end":0,
                                            "mm_env_start":0,
                                            "mm_env_end":0,
                                            "exe_file_id":0,
                                            "vmas":[],
                                            "dumpable":1
                                            }]}


        self.table_header(outfd, [("Start", "#018x"), ("End",   "#018x"), ("Number of Pages", "6"), ("File Path", "")])
        outfile = open(file_path, "wb")
        for task, vma in data:
            savedTask = task
            (fname, major, minor, ino, pgoff) = vma.info(task)
            if progName == "":
                progName = fname

            vmasData = {"start":"{0:#x}".format(vma.vm_start),
                        "end":"{0:#x}".format(vma.vm_end),
                        "pgoff":pgoff,
                        "shmid":self.getShmid(progName, fname, shmidDic),
                        "prot":"{0}".format(self.protText(str(vma.vm_flags))),
                        "flags":"{0}".format(self.flagsText(fname)),
                        "status":"{0}".format(self.statusText(fname)),
                        "fd":-1,
                        "fdflags":"0x0"
                        }
                        
            if fname == "[vdso]":
                mmData["entries"][0]["vmas"][len(mmData["entries"][0]["vmas"])-1]["status"] += " | VMA_AREA_VVAR"
                pagemapData["entries"][len(pagemapData["entries"])-1]["nr_pages"] += 2
                
            mmData["entries"][0]["vmas"].append(vmasData)

            if str(vma.vm_flags) != "---" and fname != "[vdso]" and ".cache" not in fname:
                npage = 0
                for page in self.read_addr_range(task, vma.vm_start, vma.vm_end):
                    outfile.write(page)
                    npage +=1
                pagemapData["entries"].append({"vaddr":"{0:#x}".format(vma.vm_start), "nr_pages":npage})
                self.table_row(outfd,vma.vm_start, vma.vm_end, npage, fname)
                
        
        #Generate VDSO 
#        for ln in open('/proc/self/maps'):
#            if "[vdso]" in ln:
#                start, end = [int(x,16) for x in ln.split()[0].split('-')]
#                CDLL("libc.so.6").write(outfile.fileno(), c_void_p(start), end-start)
#                break
                
        outfile.close()

        mm = savedTask.mm

        mmData["entries"][0]["mm_start_code"] = "{0:#x}".format(mm.start_code)
        mmData["entries"][0]["mm_end_code"] = "{0:#x}".format(mm.end_code)
        mmData["entries"][0]["mm_start_data"] = "{0:#x}".format(mm.start_data)
        mmData["entries"][0]["mm_end_data"] = "{0:#x}".format(mm.end_data)
        mmData["entries"][0]["mm_start_stack"] = "{0:#x}".format(mm.start_stack)
        mmData["entries"][0]["mm_start_brk"] = "{0:#x}".format(mm.start_brk)
        mmData["entries"][0]["mm_brk"] = "{0:#x}".format(mm.brk)
        mmData["entries"][0]["mm_arg_start"] = "{0:#x}".format(mm.arg_start)
        mmData["entries"][0]["mm_arg_end"] = "{0:#x}".format(mm.arg_end)
        mmData["entries"][0]["mm_env_start"] = "{0:#x}".format(mm.env_start)
        mmData["entries"][0]["mm_env_end"] = "{0:#x}".format(mm.env_end)

        print("Heap  Start: {0} End: {1}".format(hex(mm.start_brk), hex(mm.brk)))
        print("Args  Start: {0} End: {1}".format(hex(mm.arg_start), hex(mm.arg_end)))
        print("Env   Start: {0:#x} End: {1:#x}".format((mm.env_start), (mm.env_end)))
        print("Stack Start: {0:#x}".format(mm.start_stack))

        pagemap.write(json.dumps(pagemapData, indent=4, sort_keys=False))
        pagemap.close()

        mmFile.write(json.dumps(mmData, indent=4, sort_keys=False))
        mmFile.close()
