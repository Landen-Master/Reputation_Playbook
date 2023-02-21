# Reputation_Playbook
 This program queries multiple reputation vendors for given IP addresses, domains, and files, and generates a succinct report of information from each
## User Guide

This program is written in Python and currently uses the requests library alongside VirusTotal and IBM X-Force's APIs.

### Getting started
To start, you will need to create a text file, **keys.txt**. This may be named however you choose, however it will contain contain the following, each on its own separate line:
1. A VirusTotal API key
2. An IBM X-Force API key
3. The password of the cooresponding IBM X-Force API key

For guides to get API keys, see [VirusTotal](https://support.virustotal.com/hc/en-us/articles/115002100149-API) and [IBM X-Force](https://api.xforce.ibmcloud.com/doc/) guides.

### Running the program
To run the program, run the **main.py** file. When prompted, ***enter the full absolute path of your file, including the .txt file extension***. Alternatively, if the file is in the current directory, only the file name is used.

**Example:** A file named keys.txt in the Users folder: ***C:\Users\keys.txt***\
**Example:** A file within the directory of the project named data.txt: ***data.txt***

Once the keys are verified, enter any IPv4 address, domain name, or MD5, SHA-1, or SHA-256 file hash to obtain quick reports from different reputation vendors.

## For Future Developers

**main.py** - Main class that executes the program. Holds methods for key reading and verification, VirusTotal queries, IBM queries, and printing reports.

**keys.txt** - Information needed to run the program, including a VirusTotal API key, IBM X-Force API key, and password of the cooresponding IBM X-Force API key.
