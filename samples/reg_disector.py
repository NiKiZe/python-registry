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
                d = '0x%08x  hbin block magic identifier @%i' % (dwd, offset)
            elif offset % 0x1000 == 0x4:
                d = '0x%08x  bins distance from first bin %i' % (dwd, dwd)
            elif offset % 0x1000 == 0x8:
                d = '0x%08x  this bins size %i (a multip of 4k)' % (dwd, dwd)
            elif offset % 0x1000 == 0xc:
                length = 8
                d = '0x%08x  Unknown %i' % (dwd, dwd)
            elif offset % 0x1000 == 0x14:
                length = 8
                dwd = 0 if left < length else self.unpack_qword(offset)
                d = '0x%016x Timestamp %s' % (dwd, RegistryParse.parse_windows_timestamp(dwd))

            elif offset % 0x1000 == 0x1c:
                d = '0x%08x  Offset to next bin %i (same as @x8?)' % (dwd, dwd)

            elif offset>=0x2 and offset % 16 == 0:
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
    