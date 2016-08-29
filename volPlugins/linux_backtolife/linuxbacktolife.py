import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.find_file as linux_find_file
import volatility.plugins.linux.dump_map as linux_dump_map
import volatility.plugins.linux_elf_dump.elfdump as linux_elf_dump
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import struct
import os
import json
from ctypes import *



#Plugin which generates different files in order to restore a process using CRIU
class linux_backtolife(linux_proc_maps.linux_proc_maps):
    """Generate images file for CRIU"""

    def __init__(self, config, *args, **kwargs):
        linux_proc_maps.linux_proc_maps.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = "./", help = 'Output directory', action = 'store', type = 'str')
    
    #Method for dumping a file to local disc extracting it from a memory dump
    def dumpFile(self, listF):
        listInode = []
        toFind = len(listF)
        print "ToFind: " + str(toFind)
        for (_, _, file_path, file_dentry)in linux_find_file.linux_find_file(self._config).walk_sbs():
            if file_path in listF:
                listInode.append(file_dentry.d_inode)
                toFind -= 1
                if toFind == 0:
                    break
        
        for a in listInode:
            print "{0:#x}".format(a)
    
    #Method for dumping elf file relative to the process
    def dumpElf(self, outfd):
        data = linux_elf_dump.linux_elf_dump(self._config).calculate()
        data = linux_elf_dump.linux_elf_dump(self._config).render_text(outfd, data)
    
    #Method for reading an address range in memory dump dividing in pages
    def read_addr_range_page(self, task, start, end):
        pagesize = 4096 
        proc_as = task.get_process_address_space()
        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize

    #Method for reading an address range in memory dump
    def read_addr_range(self, task, start, size):
        proc_as = task.get_process_address_space()
        segment = proc_as.zread(start, size)
        return segment
    
    #Method for generating sigactions
    def read_sigactions(self, task):
    
        sigacts = {"magic":"SIGACT", "entries":[]}
        
        handler = task.sighand
        action_vector = handler+8
        
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
            #Sarebbero 4 di flags ma ci sono altri 4 a 0
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
            sigacts["entries"].append(action_element)
            
            action_vector += 8
        
        return sigacts

    #Build pstree file for CRIU with info about process and his threads
    def buildPsTree(self, task):
        pstreeData = {"magic":"PSTREE", "entries":[{
                                                    "pid":int(str(task.pid)),
                                                    "ppid":0,
                                                    "pgid":int(str(task.pid)),
                                                    "sid":0
                                                    }]}
        threads = []
        for thread in task.threads():
            threads.append(int(str(thread.pid)))
            
            
        print type(threads[0])
        
        pstreeData["entries"][0]["threads"] = threads
        
        pstreeFile = open("pstree.json", "w")
        pstreeFile.write(json.dumps(pstreeData, indent=4))
        pstreeFile.close()

    #Generate string of PROT field starting from permission flags of a segment for MM file
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

    #Method for generating flags string for MM file
    def flagsText(self, name):
        flags = ""
        
        #Cache is SHARED
        if ".cache" in name:
            flags += "MAP_SHARED"
            return flags
        
        #Other Segment are PRIVATE
        flags += "MAP_PRIVATE"
        
        #If Segment is not relative to any file it's ANON
        if name == "" or "[" in name:
            flags += " | MAP_ANON"
        
        #STACK is always GROWSDOWN
        if name == "[stack]":
            flags += " | MAP_GROWSDOWN"

        return flags
        
    #Method that can generate status String for MM file
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
    
    #Method for generating shmid, it takes max fd id assign it to program, and assign ids to other files
    def getShmid(self, progname, current_name, dic, task):
        if current_name == "" or "[" in current_name:
            return 0

        if current_name == progname:
            maxFd = 0
            for filp, fd in task.lsof(): 
                #self.table_row(outfd, Address(task.obj_offset), str(task.comm), task.pid, fd, linux_common.get_path(task, filp))
                if fd > maxFd:
                    maxFd = fd
            
            dic[progname] = maxFd
            return maxFd

        if current_name in dic:
            return dic[current_name]
        else:
            dic[current_name] = len(dic) + dic[progname]
            return dic[current_name]


    #Method that perform all the operations
    def render_text(self, outfd, data):
        if not self._config.PID:
            debug.error("You have to specify a process to dump. Use the option -p.\n")
        

        file_name = "pages-1.img"
        file_path = os.path.join(self._config.DUMP_DIR, file_name)
        
        progName = ""
        shmidDic = {}
        procFiles = {} #Files used in process
        procFilesExtr = [] #Files that have to be extracted
        
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
                                            
        regfilesFile = open("procfiles.json".format(self._config.PID), "w")
        regfilesData = {"entries":[], "pid":self._config.PID}

	sigactsFile = open("sigacts-{0}.json".format(self._config.PID), "w")

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
                        "shmid":self.getShmid(progName, fname, shmidDic, savedTask),
                        "prot":"{0}".format(self.protText(str(vma.vm_flags))),
                        "flags":"{0}".format(self.flagsText(fname)),
                        "status":"{0}".format(self.statusText(fname)),
                        "fd":-1,
                        "fdflags":"0x0"
                        }
                        
            #If VDSO number of pages of predecessor node have to be incremented      
            if fname == "[vdso]":
                mmData["entries"][0]["vmas"][len(mmData["entries"][0]["vmas"])-1]["status"] += " | VMA_AREA_VVAR"
                pagemapData["entries"][len(pagemapData["entries"])-1]["nr_pages"] += 2
                
            mmData["entries"][0]["vmas"].append(vmasData)

            #if Inode != 0, it's a file which have to be linked
            if ino != 0 and fname not in procFiles:
                procFiles[fname] = True
                idF = vmasData["shmid"]
                typeF = "local"
                nameF = fname
                if fname == progName:
                    #ELF is extracted
                    typeF = "elf"
                    nameF = task.comm + ".dump"
                    
                    
                
                fileE = {"name":nameF, "id": idF, "type":typeF}
                regfilesData["entries"].append(fileE)

            #Shared Lib in exec mode not have to be dumped
            exLib = ".so" in fname and "x" in str(vma.vm_flags)

            #DUMP only what CRIU needs
            if str(vma.vm_flags) != "---" and fname != "[vdso]" and ".cache" not in fname and not exLib and "/lib/locale/" not in fname:
                npage = 0
                for page in self.read_addr_range_page(task, vma.vm_start, vma.vm_end):
                    outfile.write(page)
                    npage +=1
                pagemapData["entries"].append({"vaddr":"{0:#x}".format(vma.vm_start), "nr_pages":npage})
                self.table_row(outfd,vma.vm_start, vma.vm_end, npage, fname)
                
        outfile.close()

        mm = savedTask.mm
        
        #set Limit addresses for MM file
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
        mmData["entries"][0]["exe_file_id"] = shmidDic[progName]
        
        #Files used by process: TYPE = EXTRACTED
        for filp, fd in task.lsof():
            if fd > 2:
                fname = linux_common.get_path(task, filp)
                
                if "/" not in fname:
                    continue
                    
                typeF = "local" ##TODO
                idF = fd -1
                fileE = {"name":fname, "id": idF, "type":typeF}
                regfilesData["entries"].append(fileE)
                procFilesExtr.append(fname)
                 
        pagemap.write(json.dumps(pagemapData, indent=4, sort_keys=False))
        pagemap.close()

        mmFile.write(json.dumps(mmData, indent=4, sort_keys=False))
        mmFile.close()
        
        regfilesFile.write(json.dumps(regfilesData, indent=4, sort_keys=False))
        regfilesFile.close()
        
        print "Extracting Files: "
        print procFilesExtr 
        #self.dumpFile(procFilesExtr)
        self.buildPsTree(savedTask)
        self.dumpElf(outfd)
        
        sigactsData = self.read_sigactions(task)
        sigactsFile.write(json.dumps(sigactsData, indent=4, sort_keys=False))
        sigactsFile.close()

