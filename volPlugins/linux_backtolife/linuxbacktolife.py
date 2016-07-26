
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.proc_maps as linux_proc_maps
import volatility.plugins.linux.dump_map as linux_dump_map
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import os
import json
class linux_backtolife(linux_proc_maps.linux_proc_maps):
    """Generate pages file for CRIU"""

    def __init__(self, config, *args, **kwargs):
        linux_proc_maps.linux_proc_maps.__init__(self, config, *args, **kwargs)
        self._config.add_option('DUMP-DIR', short_option = 'D', default = "./", help = 'Output directory', action = 'store', type = 'str')
        self._config.add_option('BUILD_JSON', short_option = 'j', default = None, help = 'Output json file with memory map', action = 'store', type = 'str') 
    
    def read_addr_range(self, task, start, end):
        pagesize = 4096 
        proc_as = task.get_process_address_space()
        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize


    def render_text(self, outfd, data):
        if not self._config.PID:
            debug.error("You have to specify a process to dump. Use the option -p.\n")
        

        file_name = "task.{0}.vma".format(self._config.PID)
        file_path = os.path.join(self._config.DUMP_DIR, file_name)
        buildJson = False
        print "Creating pages file of PID: " + self._config.PID
        jsonFile = None
        jsonData = None
        if self._config.BUILD_JSON:
            buildJson = True
            jsonFile = open(self._config.BUILD_JSON, "w")
            jsonData = {"magic":"PAGEMAP", "entries":[{"pages_id":1}]}
        self.table_header(outfd, [("Start", "#018x"), ("End",   "#018x"), ("Number of Pages", "6"), ("File Path", "")])

        outfile = open(file_path, "wb")
        for task, vma in data:
            (fname, major, minor, ino, pgoff) = vma.info(task)
            if str(vma.vm_flags) != "---" and fname != "[vdso]" and ".cache" not in fname:
                npage = 0
                for page in self.read_addr_range(task, vma.vm_start, vma.vm_end):
                    outfile.write(page)
                    npage +=1
                if buildJson:
                    jsonData["entries"].append({"vaddr":"{0:#x}".format(vma.vm_start), "nr_pages":npage})
                self.table_row(outfd,vma.vm_start, vma.vm_end, npage, fname)
        outfile.close()

        if buildJson:
            jsonFile.write(json.dumps(jsonData, indent=4))
            jsonFile.close()
