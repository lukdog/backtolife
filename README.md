# User Manual
The output of this thesis is a pool of file which can be used for resurrecting processes starting from a memory dump. In this section it will be explained how these files have to be used for reaching the purpose. Specifically there are two different categories of files, the first contains the scripts and volatility plugins for the resurrection, the second includes tools for development and continue the research.

## Environment setup

In order to build the environment it is necessary to start from a physical or virtual machine running a Linux operating system. During the development of this thesis, a *Kali Linux 2.0* with kernel version *4.0* and a *Debian Jessie* with kernel *3.16* were used and deeply tested. When the operating system is setted up, needed tools can be installed on the system. This manual explains how to set up the environment on a *Kali* system, but for other distributions steps are very similar.

In order to perform the resurrection process both **CRIU** and **Volatility** have to be installed on the machine, they can be downloaded from their official repositories, and installed through following steps. Firstly dependences have to be installed with the right version, therefore packages sources have to be correctly setted on the system to be sure to get access to all available versions of each package.

```bash
#Setting up packages repository

>> echo "deb http://old.kali.org/kali sana main non-free contrib" >> /etc/apt/sources.list

>> echo "deb-src http://old.kali.org/kali sana main non-free contrib" >> /etc/apt/sources.list

>> apt-get update

>> apt-get upgrade
```

Regarding **CRIU**, the version *2.5* should be installed in order to guarantee the compatibility with **backtolife plugins**. In newer version images file format could change, and it is possible that generated images do not work. This version needs a particular set of packages, and with the following command they will be installed on the machine at the same version used for development of this project. If on the system there are installed newer versions of target packages, they will be downgraded.

```bash
# Installing dependencies

>> apt-get install -y --allow-downgrades \
	build-essential \
	libprotobuf-dev=2.6.1-1 \
	libprotobuf-c1=1.0.2-1 \
	libprotobuf-c-dev=1.0.2-1 \
	protobuf-c-compiler=1.0.2-1 \
	protobuf-compiler=2.6.1-1 \
	python-protobuf=2.6.1-1 \
	libnet1-dev=1.1.6+dfsg-3 \
	pkg-config=0.28-1 \
	libnl-3-200=3.2.24-2 \
	libnl-3-dev=3.2.24-2 \
	python-ipaddr=2.1.11-2 \
	libcap2=1:2.24-8 \
	libcap-dev=1:2.24-8 \
	libaio1=0.3.110-1 \
	libaio-dev=0.3.110-1 \
	python-yaml=3.11-2
```

When all packages are successfully installed, it is possible to proceed installing **CRIU**.

```bash
# In root (/) directory
# Download of CRIU sources in version 2.5

>> wget https://github.com/xemul/criu/archive/v2.5.tar.gz

# Sources extraction
>> tar zxvf v2.5.tar.gz

# Moving in CRIU directory and compiling it
>> cd /criu-2.5 && make
```

At the end of the procedure, **CRIU** and its companion tool **crit** will be compiled and available on the machine. Then, it is possible to move on the *Volatility Framework* configuration. It is all written in **python** and specifically, it requires the version *2.7*. In the thesis development the version *2.6* of this framework was used and tested but all version should be supported.

```Bash
# Installing python and other dependencies
>> apt-get install -y \
	dwarfdump \
	pcregrep \
	libpcre++-dev \
	python-dev \
	python-crypto=2.6.1-5+b2 \
	python-distorm3=3.3-1kali2

# Download of Volatility on root directory and sources extraction
>> wget https://github.com/volatilityfoundation/volatility/archive/2.6.tar.gz
>> tar zxvf 2.6.tar.gz

# Main volatility script has to be executable
>> chmod +x /volatility-2.6/vol.py
```

When both tools are configured on the analysis machine, it is necessary to configure the **$PATH** environment variable in order to use all the previously installed tool from every path. It can be done for example with the following command:

```bash
# Configuring PATH
>> echo "PATH=$PATH:/volatility-2.6:/criu-2.5/criu:/criu-2.5/crit" >> ~/.bashrc

# Setting alias for vol.py script.
>> echo "alias volatility=\"vol.py\"" >> ~/.bashrc
```

Then a community volatility plugin has to be downloaded from a *github* repository, it is needed for extracting the **ELF** file of the target process from a memory dump. This particular plugin needs a **bash** global variable called **LD_BIND_NOW** which has to be setted to the value *1*. It is necessary for permitting the execution of the extracted **ELF** file as declared by the author of the **ElfDump** plugin. The plugin can be configured as follows:

```bash
# Cloning the repository
>> git clone https://github.com/ecanzonieri/ElfDump

# Installing plugin inside volatility directory
>> mv ElfDump/linux_elf_dump /volatility-2.6/volatility/plugins/

# Setting global variable
>> echo "LD_BIND_NOW=1" >> ~/.bashrc
```

When all tools are setted up, it is possible to proceed with configuration of *BackToLife tools*. These tools can be downloaded directly from the *github* repository. They require two python packages, also **volatility** plugins have to be inserted in the right installation folder, in the path **volatility/plugins**. It is possible to configure these tools using the following commands:

```bash
# Installing dependencies
>> apt-get install -y \
	python-psutil \
	python-pygraphviz \

# Download of source code
>> wget https://github.com/lukdog/backtolife/archive/v2.0.tar.gz

# Extracting it in root directory
>> tar zxvf v2.0.tar.gz

# Setting PATH variable for using backtolife tools
>> echo "PATH=$PATH:/backtolife-2.0" >> ~/.bashrc

# Installing developed volatility plugins
>> mv /backtolife-2.0/volPlugins/* /volatility-2.6/volatility/plugins
```

When all is setted up, it is possible to check if all is correctly configured running following commands:

```bash
# Check volatility installation
>> volatility --info | grep linux

# It is important to check if installed plugin are included in the output of previous command

# Check criu installation
>> criu --version
```

## How to perform a resurrection

When the setup of plugins is completed, the volatility profile of the target machine have to be generated and moved in **volatility/plugins/overlay/linux**. For the generation of the target profile, the modified **module.c** file has to be used in order to generate all needed VTYpes, it can be found in **BackToLife/linux_module**. 

```bash
# Moving modified module in right folder
>> cp /backtolife-2.0/linux_module/module.c /volatility/tools/linux

# Compiling module file
>> cd /volatility/tools/linux && make

# Generating the profile
>> zip /volatility/volatility/plugins/overlays/linux/kali.zip /volatility/tools/linux/module.dwarf /boot/System.map-4.0.0-generic 
```

Previous command can be run on the development machine, but it is important to remember that each profile is related to a particular operating system or kernel version. Profiles have to be generated on target machine or on a identical installation.

When all is setted up, it is possible to perform the resurrection of a process through a simple sequence of commands:

```bash
# Target process identification
>> volatility --profile=[profile_name] -f [dump_file] linux_pslist | grep [target_process]

# Process extraction
>> volatility --profile=[profile_name] -f [dump_file] linux_backtolife -p [PID]

# Image files generation
>> prepareMachine.sh

# Process resurrection
>> criu restore [params]
```

At the end of the last command the process should be restored and it is possible to interact with it using the command line. Another possibility is to use the **BackToLife.sh** instead of directly calling **CRIU** for the restoring phase. This script accepts the same parameters of **CRIU** but perform the restoration of the process in a new terminal window, it supports only **gnome-based** operating systems. Sometimes the process which have to be restored makes use of libraries not present on the analyst's machine. In this situation, the **prepareMachine.sh** script will fail and the restoration can not be performed. It is possible to solve the problem installing the right version of the target libraries listed in the **procfiles.json** file. Desired libraries can be installed, setting the right package repository and using the following commands:

```bash
# Checking if desired version is in the setted repository
>> apt-cache policy [package_name]

# Installing desired version
>> apt-get install [package_name]=version
```

## Development tools
This category of tools includes all scripts developed for this research. In order to use all of them, the **BackToLife** path has to be included in the environment variable **$PATH**. Most of them can be easily launched for understanding what parameters are needed, and in this section the most useful will be explained. Development tools could be divided in groups based on the context of use. Main scripts were written for searching patterns, or working on a raw file, for example in a memory dump or a section of it.

* **findBytes.py**: searches all occurrences of a sequence of bytes in hexadecimal format in a raw file, the output is a list of addresses where the pattern is found. It receives in input the raw file and the sequence of bytes.
* **pageSeparator.py**: splits a raw file in many pages raw file with the size of a page. It receives as parameter the raw file.
* **compareBinary.sh**: compares two different binary files printing the differences.

Other scripts were written for working faster with **CRIU** file images.

* **convertImgJson.sh**: it has not parameters and it is able to covert all images from binary to **json** format using **crit**.
* **diffCriu.sh**: it takes as parameter two different paths containing two **CRIU** checkpoint converted in **json** format. It prints all differences of the two checkpoint.
* **findPatternCrit.sh**: searches for a pattern in all **json** image files in the current directory.
