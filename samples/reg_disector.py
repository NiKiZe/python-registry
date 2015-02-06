#!/usr/bin/python
# -*- coding: utf-8 -*-

#    This file is part of python-registry.
#    It dumps the raw reg file and explain each value that is known
#    This helps understand and check regfiles,
#    as well as find unsupported features
#
#   Copyright 2015 Christian Nilsson <nikize@gmail.com>
#   Parts from hexdump claiming Public Domain
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from __future__ import print_function
from __future__ import unicode_literals

import sys
from hexdump import Hexdump

from Registry import RegistryParse

class Disector(RegistryParse.REGFBlock):
    """
    Parsing of file as a Windows Registry file.
    """
    def __init__(self, filelikeobject):
        """
        Constructor.
        Arguments:
        - `filelikeobject`: A file-like object with a .read() method.
              If a Python string is passed, it is interpreted as a filename,
              and the corresponding file is opened.
        """
        try:
            self._buf = filelikeobject.read()
        except AttributeError:
            with open(filelikeobject, "rb") as f:
                self._buf = f.read()
        self._buflen = len(self._buf)

        super(Disector, self).__init__(self._buf, 0, False)

    def disect(self):
        self.hexdump = Hexdump()
        self.lastexplanation=''

        offset = 0
        last = -1
        length = 0x4

        lasthbin = -1
        lastcell = -1
        lastcellfree = True
        nextcell = -1
        lastrecord = None

        nknamelen = -1
        vknamelen = -1
        sksize = -1

        while last < offset:
            left = self._buflen - offset
            
            length = 4
            dwd = 0 if left < length else self.unpack_dword(offset)
            d=''

            #depending on offset this have a multitude of different outputs.
            if offset==0:
                d = '0x%08x  regf file magic identifier' % (dwd)
            elif offset==0x4 or offset==0x8:
                d = 'Sequence %i : %i' % (offset/0x4, dwd)
            elif offset==0xC:
                length = 8
                dwd = 0 if left < length else self.unpack_qword(offset)
                d = '0x%016x Timestamp %s' % (dwd, RegistryParse.parse_windows_timestamp(dwd))

            elif offset==0x14:
                d = 'Major (1): %i' % (dwd)
            elif offset==0x18:
                d = 'Minor (3): %i' % (dwd)
            elif offset==0x1C:
                d = 'Type? (0): %i' % (dwd)
            elif offset==0x20:
                d = 'Format? (1): %i' % (dwd)

            elif offset==0x24:
                d = '0x%08x  Pointer to first key record' % (dwd)
            elif offset==0x28:
                #d = '0x%08x  Size of the data-blocks (Filesize-4kb) or Pointer to start of last hbin in file %i' % (dwd, dwd)
                d = '0x%08x  Pointer to start of last hbin in file %i' % (dwd, dwd)

            elif offset==0x2C:
                d = 'Unknown ? Always 1: %i' % (dwd)

            elif offset==0x30:
                length = 64
                d = 'Hivename  %s' % (self.hive_name())

            elif offset==0x70: # utf16le guid?
                length = 0x18c # 0x50 #.. 0x18c takes all until checksum.
                #d = 'GUID : %i %s' % (length, self.unpack_string(offset, length).decode("utf-16le").rstrip("\x00"))
                d = 'Log of last update or just stack?, ex: GUID seen : %i' % (length)


                #filename is _not_ terminated with 0xffffffff
            elif offset==0x1f0:
                pass
            elif offset==0x1fc:
                d = '0x%08x  CRC XOR of above including this expected result 0x0' % dwd

            elif offset % 0x1000 == 0x0 and dwd == 0x6e696268:
                lasthbin = offset
                d = '0x%08x  hbin block magic identifier @%i' % (dwd, offset)
            elif lasthbin>0 and offset-lasthbin == 0x4:
                d = '0x%08x  bins distance from first bin %i' % (dwd, dwd)
            elif lasthbin>0 and offset-lasthbin == 0x8:
                d = '0x%08x  this bins size %i (a multip of 4k)' % (dwd, dwd)
            elif lasthbin>0 and offset-lasthbin == 0xc:
                length = 8
                d = '0x%08x  Unknown %i' % (dwd, dwd)
            elif lasthbin>0 and offset-lasthbin == 0x14:
                length = 8
                dwd = 0 if left < length else self.unpack_qword(offset)
                #only on first hbin in file?
                d = '0x%016x Timestamp %s' % (dwd, RegistryParse.parse_windows_timestamp(dwd))

            elif lasthbin>0 and offset-lasthbin == 0x1c:
                d = '0x%08x  Offset to next bin %i (same as @x8?)' % (dwd, dwd)

            elif (lasthbin>0 and offset-lasthbin == 0x20) or offset==nextcell:
                lastcell = offset
                dwd = 0 if left < length else self.unpack_int(offset)
                # Cell length (including these 4 bytes)
                # Negative if allocated, positive if free. If a cell becomes unallocated and
                # is adjacent to another unallocated cell, they are merged by having
                # the earlier cell?s length extended.
                lastcellfree = dwd>0
                d = '0x%08x  ' % dwd
                if lastcellfree:
                    size = dwd
                    d += 'FREE  '
                    length = size # for now ignore all data inbetween
                else:
                    size = -dwd
                nextcell = offset + size
                d += 'HBIN Cell size %i next @ 0x%08x' % (size, nextcell)

            elif lastcell>0 and offset-lastcell == 0x4:
                length = 2
                lastrecord = self.unpack_string(offset, length)
                d = 'cell/record type %s magic number' % (list(lastrecord))

            elif offset < nextcell:
                # fix the offset from id, just in case.
                recpos = offset-lastcell-0x4
                if lastcell>0 and offset-lastcell == 0x6:
                    dwd = self.unpack_word(offset)
                    length = 2
                elif offset % 16 == 0:
                    if nextcell>0 and nextcell <= offset+16:
                        length = nextcell - offset
                    else:
                        length = 16

                id_ = lastrecord
                if id_ == b"nk":
                    if recpos == 0x2:
                        length = 2
                        dwd = self.unpack_word(offset)
                        d = '0x%04x  Flags %i' % (dwd, dwd)
                    elif recpos == 0x4:
                        length = 8
                        dwd = 0 if left < length else self.unpack_qword(offset)
                        d = '0x%016x Timestamp %s' % (dwd, RegistryParse.parse_windows_timestamp(dwd))
                    elif recpos == 0xc:
                        length = 4
                        d = '0x%08x  Unknown %i' % (dwd, dwd)
                    elif recpos == 0x10:
                        length = 4
                        d = '0x%08x  Parent NK Offset %i ???? @ 0x%08x' % (dwd, dwd, offset-dwd)
                    elif recpos == 0x14:
                        length = 4
                        d = '0x%08x  Number of subkeys (stable) %i' % (dwd, dwd)
                    elif recpos == 0x18:
                        length = 4
                        d = '0x%08x  Number of subkeys (volatile) %i' % (dwd, dwd)
                    elif recpos == 0x1c:
                        length = 4
                        d = '0x%08x  Offset to subkey-list (stable) %i' % (dwd, dwd)
                    elif recpos == 0x20:
                        length = 4
                        d = '0x%08x  Offset to subkey-list (volatile) %i' % (dwd, dwd)
                    elif recpos == 0x24:
                        length = 4
                        d = '0x%08x  Number of values %i' % (dwd, dwd)
                    elif recpos == 0x28:
                        length = 4
                        d = '0x%08x  Offset to value-list %i' % (dwd, dwd)
                    elif recpos == 0x2c:
                        length = 4
                        d = '0x%08x  Offset to SK record %i' % (dwd, dwd)
                    elif recpos == 0x30:
                        length = 4
                        d = '0x%08x  Offset to class name %i' % (dwd, dwd)
                    elif recpos == 0x34:
                        length = 4
                        d = '0x%08x  Max no bytes in subkey name (unconfirmed) %i' % (dwd, dwd)
                    elif recpos == 0x38:
                        length = 4
                        d = '0x%08x  Max subkey class name length (unconfirmed) %i' % (dwd, dwd)
                    elif recpos == 0x3c:
                        length = 4
                        d = '0x%08x  Max no bytes in value name (unconfirmed) %i' % (dwd, dwd)
                    elif recpos == 0x40:
                        length = 4
                        d = '0x%08x  Max value data size (unconfirmed) %i' % (dwd, dwd)
                    elif recpos == 0x44:
                        length = 4
                        d = '0x%08x  Unknown or run-time index %i' % (dwd, dwd)
                    elif recpos == 0x48:
                        length = 2
                        dwd = self.unpack_word(offset)
                        nknamelen = dwd
                        d = '0x%04x  Key Name Length %i' % (dwd, dwd)
                    elif recpos == 0x4a:
                        length = 2
                        dwd = self.unpack_word(offset)
                        d = '0x%04x  Class Name Length %i' % (dwd, dwd)
                    elif recpos == 0x4c and nknamelen > 0:
                        length = nknamelen
                        #length = nextcell - nknamelen
                        dwd = self.unpack_string(offset, length).decode("windows-1252")
                        if nextcell-(offset+length) < 16:
                            length=nextcell-offset
                        if not offset+length == nextcell:
                            print("Invalid NK name len %i expected %i to be %i" % (nknamelen, offset+nknamelen, nextcell))
                        d = 'The Name %s +%i' % (list(dwd), nextcell-(offset+nknamelen))


                elif id_ == b"vk":
                    if recpos == 0x2:
                        length = 2
                        dwd = self.unpack_word(offset)
                        vknamelen=dwd
                        # if 0 len then default
                        d = '0x%04x  Value name length %i' % (dwd, dwd)
                    elif recpos == 0x4:
                        length = 4
                        vkdatalen=dwd
                        if vkdatalen > 0x80000000:
                            vkdatalen -= 0x80000000
                        d = '0x%08x  Data length %i' % (dwd, vkdatalen)
                    elif recpos == 0x8:
                        length = 4
                        vkdataof=dwd
                        # this is data if enum = 4 = Dword
                        d = '0x%08x  Data Offset %i' % (dwd, dwd)
                    elif recpos == 0xc:
                        length = 4
                        d = '0x%08x  Type Enum %i' % (dwd, dwd)
                    elif recpos == 0x10:
                        length = 2
                        dwd = self.unpack_word(offset)
                        # if bit 0 is set then it is ascii
                        d = '0x%04x  Flags %i' % (dwd, dwd)
                    elif recpos == 0x12:
                        length = 2
                        dwd = self.unpack_word(offset)
                        d = '0x%08x  Unknown %i' % (dwd, dwd)
                    elif recpos == 0x14 and vknamelen > 0:
                        length = vknamelen
                        #length = nextcell - vknamelen
                        dwd = self.unpack_string(offset, length)
                        if nextcell-(offset+length) < 16:
                            length=nextcell-offset
                        if not offset+length == nextcell:
                            print("Invalid VK name len %i expected %i to be %i" % (vknamelen, offset+vknamelen, nextcell))
                        d = 'The Name %s +%i' % (list(dwd), nextcell-(offset+vknamelen))


                elif id_ == b"lf":
                    if recpos == 0x2:
                        length = 2
                        dwd = self.unpack_word(offset)
                        d = '0x%04x  Number of elements %i' % (dwd, dwd)
                        nextrec = recpos+length
                    #Note below is repeated for each element
                    elif recpos == nextrec:
                        length = 4
                        d = '0x%08x  Offset to NK record %i' % (dwd, dwd)
                    elif recpos == nextrec + 0x4:
                        length = 4
                        d = '0x%08x  Hash value %i' % (dwd, dwd)
                        nextrec = recpos+length
                elif id_ == b"lh":
                    if recpos == 0x2:
                        length = 2
                        dwd = self.unpack_word(offset)
                        d = '0x%04x  Number of elements %i' % (dwd, dwd)
                    #Note below is repeated for each element
                    elif recpos == 0x4:
                        length = 4
                        d = '0x%08x  Offset to NK record %i' % (dwd, dwd)
                    elif recpos == 0x8:
                        length = 4
                        d = '0x%08x  Hash value %i' % (dwd, dwd)


                elif id_ == b"li":
                    if recpos == 0x2:
                        length = 2
                        dwd = self.unpack_word(offset)
                        d = '0x%04x  Number of elements %i' % (dwd, dwd)
                    elif recpos == 0x4:
                        length = 4
                        d = '0x%08x  Offset to subkey %i' % (dwd, dwd)

                elif id_ == b"ri":
                    if recpos == 0x2:
                        length = 2
                        dwd = self.unpack_word(offset)
                        d = '0x%04x  Number of elements %i' % (dwd, dwd)
                    elif recpos == 0x4:
                        length = 4
                        d = '0x%08x  Offset to subkey-list %i' % (dwd, dwd)


                elif id_ == b"sk":
                    if recpos == 0x2:
                        length = 2
                        dwd = self.unpack_word(offset)
                        d = '0x%04x  Unknown %i' % (dwd, dwd)
                    elif recpos == 0x4:
                        length = 4
                        d = '0x%08x  Offset to previous SK record %i' % (dwd, dwd)
                    elif recpos == 0x8:
                        length = 4
                        d = '0x%08x  Offset to next SK record %i' % (dwd, dwd)
                    elif recpos == 0xc:
                        length = 4
                        d = '0x%08x  Reference count %i' % (dwd, dwd)
                    elif recpos == 0x10:
                        length = 4
                        dwd = self.unpack_word(offset)
                        sksize = dwd
                        d = '0x%04x  Size of security descriptor %i' % (dwd, dwd)
                    elif recpos == 0x14 and sksize > 0:
                        # todo windows Sec Desc
                        length = sksize
                        #length = nextcell - sksize
                        if nextcell-(offset+length) < 16:
                            length=nextcell-offset
                        if not offset+length == nextcell:
                            print("Invalid SK desc size %i expected %i to be %i" % (sksize, offset+sksize, nextcell))
                        d = 'Security descriptor of size %i +%i' % (sksize, nextcell-(offset+sksize))

                elif id_ == b"db":
                    pass
                    #d= DBRecord(self._buf, self.data_offset(), self)
                else:
                    pass
                    #d= DataRecord(self._buf, self.data_offset(), self)

            elif offset % 16 == 8:
                length = 8
            elif offset % 8 == 4:
                length = 4
            elif offset % 4 == 2:
                length = 2
            elif offset % 2 == 1:
                length = 1

            #Default 16 offset, but prevent blocking of nextcell
            elif offset % 16 == 0:
                if nextcell>0 and nextcell <= offset+16:
                    length = nextcell - offset
                else:
                    length = 16

            else:
                d = '0x%08x   %i' % (dwd, dwd)
            self.hprint(offset, length, '  %s' % (d))
            last = offset
            if 0 < left:
                offset += length

        print('%08x' % self._buflen)

    def hprint(self, offset, length, explanation = ''):
       if len(explanation)>0 and not self.lastexplanation==explanation:
           self.hexdump.lastline=''
           self.lastexplanation=explanation
       for line in self.hexdump.gen(self.unpack_binary(offset, length), offset):
           # only show explanation for first line TODO make it smarter
           print(line + explanation)
           explanation=''


def usage():
    return "  USAGE:\n\t%s  <Registry Hive file>" % (sys.argv[0])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(usage())
        sys.exit(-1)

    f = open(sys.argv[1])
 
    disector = Disector(f)
    disector.disect()
    