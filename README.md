# BackdoorPE
A Proof of Concept (PoC) backdoor injection tool developed to play around with various ideas and concepts. It takes a host Windows executable, or Portable Executable (PE), and injects a target PE along with the necessary modifications to silently gain execution. The output is a payload directory with the parent folder of the host executable with the same contents as the original except for the backdoored executable.

BackdoorPE was developed alongside the Banter RAT (https://github.com/tserafin/Banter) with the end goal of injecting a legitimate Windows binary and stealthily gaining control of a target machine.

Key concepts investigated:
 - Backdooring of a legitimate PE to silently run an additional PE
 - Antivirus (AV) evasion and stealthing
 - Windows Position-independent shellcode
 - Automation of backdooring procedure

Currently the backdooring procedure is tightly coupled with the specific host PE used for testing. As such any other PE's intended for injection will have to adhere to a similar layout. The specific host PE used contains the following sections:
 - .text    <--- Where the execution hook and shellcode will be injected
 - .rdata
 - .data
 - .rsrc    <--- Where the target PE/backdoor will be injected

Backdooring procedure:
 - Modify host PE header:
   - Expand size of image in the optional header
   - Make .text writable (?)
   - Expand .rsrc section to accomodate backdoor
     - Modify raw data size (including 4k padding)
     - Modifiy virtual size
 - Inject backdoor into expanded .rsrc section and pad out with null-bytes to reach appropriate raw data size
 - Hook execution to shellcode location and back, ensuring that overwritten instructions are still run
 - Inject shellcode

Possible future work:
 - Expand support for host PE's with different section layouts
 - Adding functionality to automatically detect code caves and space for the backdoor, improving automation
 - Improving AV evasion
   - More subtle PE header modifications
   - Encryption/Compression/Stealthing of backdoor, alternative methods of storing backdoor
   - Encryption/Compression/Stealthing of shellcode
 - Improving/adding alternative persistence methods