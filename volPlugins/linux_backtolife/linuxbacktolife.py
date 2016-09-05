import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.find_file as linux_find_file
import volatility.plugins.linux.dump_map as linux_dump_map
import volatility.plugins.linux_elf_dump.elfdump as linux_elf_dump
import volatility.plugins.linux_dump_sock.linuxdumpsock as linux_dump_sock
import volatility.plugins.linux.info_regs as linux_info_regs
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
        if toFind == 0:
            print "\t0 files have to be extracted"
            return
        else: 
            print "\t" + str(toFind) + "files have to be extracted"
                
        for (_, _, file_path, file_dentry)in linux_find_file.linux_find_file(self._config).walk_sbs():
            if file_path in listF:
                listInode.append(file_dentry.d_inode)
                toFind -= 1
                if toFind == 0:
                    break
        
        for a in listInode:
            print "\t{0:#x}".format(a)
    
    #Method for dumping elf file relative to the process
    def dumpElf(self, outfd):
        data = linux_elf_dump.linux_elf_dump(self._config).calculate()
        data = linux_elf_dump.linux_elf_dump(self._config).render_text(outfd, data)
    
    def dumpSock(self, task):
        data = linux_dump_sock.linux_dump_sock(self._config).get_sock_info(task)
        inetFile = open("inetsk.json", "w")
        inetData = {"magic":"INETSK", 
                    "entries":[]}
        for key, value in data.iteritems():
            inetData["entries"].append(value)

        inetFile.write(json.dumps(inetData, indent=4, sort_keys=False))

    #Method for extracting registers values
    def readRegs(self, task):
        info_regs = linux_info_regs.linux_info_regs(self._config).calculate()
        
        extra_regs = {}
        float_regs = {}
        thread_core = {}
        pids = {}
        for thread in task.threads():
            name = thread.comm
            pids[name] = thread.pid
            jRegs = {"fs_base": "{0:#x}".format(thread.thread.fs),
                    "gs_base": "{0:#x}".format(thread.thread.gs),
                    "fs": "{0:#x}".format(thread.thread.fsindex),
                    "gs": "{0:#x}".format(thread.thread.gsindex),
                    "es": "{0:#x}".format(thread.thread.es),
                    "ds": "{0:#x}".format(thread.thread.ds)}
            extra_regs[name] = jRegs
            
            #Reading st_space from memory Byte by Byte
            addr = int(thread.thread.fpu.state.fxsave.__str__())+32
            st_space_vect = []
            for i in range(0, 32):
                reverse = []
                dataByte = self.read_addr_range(task, addr, 4)
                for c in dataByte:
                    reverse.insert(0, "{0:02x}".format(ord(c)))
                
                reverse.insert(0, "0x")
                value = ''.join(reverse)
                st_space_vect.append(int(value, 16))
                addr += 4
            
            #Reading xmm_space from memory Byte by Byte
            addr = int(thread.thread.fpu.state.fxsave.__str__()) + 160
            xmm_space_vect = []
            for i in range(0, 64):
                reverse = []
                dataByte = self.read_addr_range(task, addr, 4)
                for c in dataByte:
                    reverse.insert(0, "{0:02x}".format(ord(c)))
                
                reverse.insert(0, "0x")
                value = ''.join(reverse)
                xmm_space_vect.append(int(value, 16))
                addr += 4
            
            
            #Reading ymmh_space from memory Byte by Byte
            addr = int(thread.thread.fpu.state.xsave.ymmh.__str__())
            ymmh_space_vect = []
            for i in range(0, 64):
                reverse = []
                dataByte = self.read_addr_range(task, addr, 4)
                for c in dataByte:
                    reverse.insert(0, "{0:02x}".format(ord(c)))
                
                reverse.insert(0, "0x")
                value = ''.join(reverse)
                ymmh_space_vect.append(int(value, 16))
                addr += 4
                
            #Reading Thread_core structures
            threadCoreData = {
                                "futex_rla": 0,
                                "futex_rla_len": 0,
                                "sched_nice":0,
                                "sched_policy":0,
                                "sas":{"ss_sp":int(thread.sas_ss_sp), "ss_size":int(thread.sas_ss_size), "ss_flags":2}, #flags not found 
                                "signals_p":{},
                                "creds":{
                                            "uid":int(thread.cred.uid.val),
                                            "gid":int(thread.cred.gid.val),
                                            "euid":int(thread.cred.euid.val),
                                            "egid":int(thread.cred.egid.val),
                                            "suid":int(thread.cred.suid.val),
                                            "sgid":int(thread.cred.sgid.val),
                                            "fsuid":int(thread.cred.fsuid.val),
                                            "fsgid":int(thread.cred.fsgid.val),
                                            "cap_inh":[],
                                            "cap_prm":[],
                                            "cap_eff":[],
                                            "cap_bnd":[],
                                            "secbits":int(thread.cred.securebits),
                                            "groups":[0]
                                        }
                                }

            #Reading Caps
            addr = int(thread.cred.cap_inheritable.__str__())
            for i in range(0,2):
                reverse = []
                dataByte = self.read_addr_range(task, addr, 4)
                for c in dataByte:
                    reverse.insert(0, "{0:02x}".format(ord(c)))
                    
                reverse.insert(0, "0x")
                value = ''.join(reverse)
                threadCoreData["creds"]["cap_inh"].append(int(value, 16))
                addr+=4
                
            addr = int(thread.cred.cap_permitted.__str__())
            for i in range(0,2):
                reverse = []
                dataByte = self.read_addr_range(task, addr, 4)
                for c in dataByte:
                    reverse.insert(0, "{0:02x}".format(ord(c)))
                    
                reverse.insert(0, "0x")
                value = ''.join(reverse)
                threadCoreData["creds"]["cap_prm"].append(int(value, 16))
                addr+=4
                
            addr = int(thread.cred.cap_effective.__str__())
            for i in range(0,2):
                reverse = []
                dataByte = self.read_addr_range(task, addr, 4)
                for c in dataByte:
                    reverse.insert(0, "{0:02x}".format(ord(c)))
                    
                reverse.insert(0, "0x")
                value = ''.join(reverse)
                threadCoreData["creds"]["cap_eff"].append(int(value, 16))
                addr+=4

            addr = int(thread.cred.cap_bset.__str__())
            for i in range(0,2):
                reverse = []
                dataByte = self.read_addr_range(task, addr, 4)
                for c in dataByte:
                    reverse.insert(0, "{0:02x}".format(ord(c)))
                    
                reverse.insert(0, "0x")
                value = ''.join(reverse)
                threadCoreData["creds"]["cap_bnd"].append(int(value, 16))
                addr+=4

            thread_core[name] = threadCoreData

            fpregsData = {"fpregs":{"cwd":int(thread.thread.fpu.state.fxsave.cwd),
                                    "swd":int(thread.thread.fpu.state.fxsave.swd),
                                    "twd":int(thread.thread.fpu.state.fxsave.twd),
                                    "fop":int(thread.thread.fpu.state.fxsave.fop),
                                    "rip":int(thread.thread.fpu.state.fxsave.rip),
                                    "rdp":int(thread.thread.fpu.state.fxsave.rdp),
                                    "mxcsr":int(thread.thread.fpu.state.fxsave.mxcsr),
                                    "mxcsr_mask":int(thread.thread.fpu.state.fxsave.mxcsr_mask),
                                    "st_space":st_space_vect, #Bytes from memory
                                    "xmm_space":xmm_space_vect, #Bytes from memory
                                    "xsave":{
                                            "xstate_bv":int(thread.thread.fpu.state.xsave.xsave_hdr.xstate_bv),
                                            "ymmh_space":ymmh_space_vect #Bytes from memory
                                            }
                                    }
                        }
            float_regs[name] = fpregsData
        
        #Works only with 64bit registers
        for task, name, thread_regs in info_regs:
            for thread_name, regs in thread_regs:
                if regs != None:
                    print "\tWorking on thread: " + str(pids[thread_name])
                    fCore = open("core-{0}.json".format(int(str(pids[thread_name]))), "w")
                    regsData = {"gpregs": {
                                    "r15": "{0:#x}".format(regs["r15"]),
                                    "r14": "{0:#x}".format(regs["r14"]),
                                    "r13": "{0:#x}".format(regs["r13"]),
                                    "r12": "{0:#x}".format(regs["r12"]),
                                    "bp": "{0:#x}".format(regs["rbp"]),
                                    "bx": "{0:#x}".format(regs["rbx"]),
                                    "r11": "{0:#x}".format(regs["r11"]),
                                    "r10": "{0:#x}".format(regs["r10"]),
                                    "r9": "{0:#x}".format(regs["r9"]),
                                    "r8": "{0:#x}".format(regs["r8"]),
                                    "ax": "{0:#x}".format(regs["rax"]),
                                    "cx": "{0:#x}".format(regs["rcx"]),
                                    "dx": "{0:#x}".format(regs["rdx"]),
                                    "si": "{0:#x}".format(regs["rsi"]),
                                    "di": "{0:#x}".format(regs["rdi"]),
                                    "orig_ax": "{0:#x}".format(regs["unknown"]),
                                    "ip": "{0:#x}".format(regs["rip"]),
                                    "cs": "{0:#x}".format(regs["cs"]),
                                    "flags": "{0:#x}".format(regs["eflags"]),
                                    "sp": "{0:#x}".format(regs["rsp"]),
                                    "ss": "{0:#x}".format(regs["ss"]),
                                    "fs_base": extra_regs[thread_name]["fs_base"],
                                    "gs_base": extra_regs[thread_name]["gs_base"],
                                    "ds": extra_regs[thread_name]["ds"],
                                    "es": extra_regs[thread_name]["es"],
                                    "fs": extra_regs[thread_name]["fs"],
                                    "gs": extra_regs[thread_name]["gs"]
                                },
                                "fpregs": float_regs[thread_name]["fpregs"],
                                "clear_tid_addr": "0x0"
                    }
                    
                    
                    tcData = {
                                "task_state": int(task.state),
                                "exit_code": int(task.exit_code),
                                "personality": int(task.personality),
                                "flags": int(task.flags), #It's different
                                "blk_sigset": "0x0", #Temporary
                                "comm": task.comm.__str__(),
                                "timers": {
                                            "real":{
                                                    "isec":0,
                                                    "iusec":0,
                                                    "vsec":0,
                                                    "vusec":0
                                                    },
                                            "virt":{
                                                    "isec":0,
                                                    "iusec":0,
                                                    "vsec":0,
                                                    "vusec":0
                                                    },
                                            "prof":{
                                                    "isec":0,
                                                    "iusec":0,
                                                    "vsec":0,
                                                    "vusec":0
                                                    }
                                            },
                                "rlimits": {}, #Local
                                "cg_set": 1, #Temporary
                                "signals_s":{}, #Empty for Nano
                                "loginuid": int(task.loginuid.val),
                                "oom_score_adj": int(task.signal.oom_score_adj)
                                } 
                    
                    if int(task.state) != 1 and int(task.state) != 2 and int(task.state) != 3:
                        tcData["task_state"] = 1


                    fCoreData = {
                                "magic": "CORE",
                                "entries":[
                                            {
                                                "mtype": "X86_64",
                                                "thread_info":regsData,
                                                "tc": tcData,
                                                "thread_core": thread_core[thread_name]
                                            }
                                        ]
                                }


                    if int(str(task.pid)) != int(str(pids[thread_name])):
                        fCoreData["entries"][0].pop("tc", None)
                        fCoreData["entries"][0]["thread_core"]["blk_sigset"] = 0
                        


                    fCore.write(json.dumps(fCoreData, indent=4, sort_keys=False))
                    fCore.close()
               
               
               
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
    def read_sigactions(self, task, outfd):
    
        sigacts = {"magic":"SIGACT", "entries":[]}
        
        handler = task.sighand
        action_vector = handler+8
        
        self.table_header(outfd, [("Signal", "2"), ("Sigaction", "18"), ("Flags",   "10"), ("Restorer", "18"), ("Mask", "18")])

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
            sigacts["entries"].append(action_element)
            
            #Print results
            self.table_row(outfd,i, action, flags, restorer, mask)
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
        
        print "Creating pages file for process with PID: " + self._config.PID
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
        regfilesData = {"entries":[], "pid":self._config.PID, "threads":[]}
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

        #set Limit addresses for MM file
        print "Reading address ranges and setting limits"
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
        mmData["entries"][0]["exe_file_id"] = shmidDic[progName]
        
        #Reading Auxilary Vector
        print "Reading Auxiliary Vector"
        saved_auxv = []
        addr = int(mm.__str__()) + 320
        ymmh_space_vect = []
        for i in range(0, 38):
            reverse = []
            dataByte = self.read_addr_range(savedTask, addr, 8)
            for c in dataByte:
                reverse.insert(0, "{0:02x}".format(ord(c)))
            
            reverse.insert(0, "0x")
            value = ''.join(reverse)
            saved_auxv.append(int(value, 16))
            addr += 8

        mmData["entries"][0]["mm_saved_auxv"] = saved_auxv


        #Files used by process: TYPE = EXTRACTED
        for filp, fd in task.lsof():
            if fd > 2:
                fname = linux_common.get_path(task, filp)
                
                if "/" not in fname:
                    continue
                    
                typeF = "extracted" ##TODO
                idF = fd -1
                fileE = {"name":fname, "id": idF, "type":typeF}
                regfilesData["entries"].append(fileE)
                procFilesExtr.append(fname)
                 

        
        print "Extracting Files: " 
        self.dumpFile(procFilesExtr)

        print "Building PsTree"
        self.buildPsTree(savedTask)

        for thread in savedTask.threads():
            regfilesData["threads"].append(int(str(thread.pid)))

        print "Searching registers values and threads states"
        self.readRegs(savedTask)

        print "Searching Signal Handler and sigactions"
        sigactsData = self.read_sigactions(task, outfd)

        print "Writing Files"
        sigactsFile.write(json.dumps(sigactsData, indent=4, sort_keys=False))
        sigactsFile.close()

        pagemap.write(json.dumps(pagemapData, indent=4, sort_keys=False))
        pagemap.close()

        mmFile.write(json.dumps(mmData, indent=4, sort_keys=False))
        mmFile.close()
        
        regfilesFile.write(json.dumps(regfilesData, indent=4, sort_keys=False))
        regfilesFile.close()

        print "Dumping Sockets"
        self.dumpSock(savedTask)

        print "Dumping ELF file"
        self.dumpElf(outfd)

