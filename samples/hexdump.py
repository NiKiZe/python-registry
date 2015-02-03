#!/usr/bin/python
# -*- coding: utf-8 -*-

#   Python implementation of canonical hexdump based on
#   https://bitbucket.org/techtonik/hexdump v3.1 / 3.2
#   Public Domain by Anatoly Techtonik <techtonik@gmail.com> 
#   Modifications in 2015 by Christian Nilsson <nikize@gmail.com>
#

# TODO create
from __future__ import print_function

import sys, binascii

# Python 3 Bool constant
PY3K = sys.version_info >= (3, 0)

def chunks(seq, size):
  '''Generator that cuts sequence (bytes, memoryview, etc.)
     into chunks of given size. If `seq` length is not multiply
     of `size`, the lengh of the last chunk returned will be
     less than requested.

     >>> list( chunks([1,2,3,4,5,6,7], 3) )
     [[1, 2, 3], [4, 5, 6], [7]]
  '''
  d, m = divmod(len(seq), size)
  for i in range(d):
    yield seq[i*size:(i+1)*size]
  if m:
    yield seq[d*size:]

def dump(binary, size=2, sep=' '):
  '''
  Convert binary data (bytes in Python 3 and str in
  Python 2) to hex string like '00 de ad be ef'.
  `size` argument specifies length of text chunks
  and `sep` sets chunk separator.
  '''
  hexstr = binascii.hexlify(binary)
  if PY3K:
    hexstr = hexstr.decode('ascii')
  return sep.join(chunks(hexstr, size))

def linegen(dataoffset, dumpstr, d):
  ind = dataoffset%16
  # if overflow, use 0 indentation, TODO fix lines instead
  if len(d)+ind > 16:
    ind=0
  line = ' '*(ind*3)
  if ind>=8:
    line += ' '
  line += dumpstr[:8*3]
  if len(d) > 8:  # insert separator if needed
    line += ' ' + dumpstr[8*3:]
  # calculate indentation, which may be different for the last line
  rind = len(d)+ind
  pad = 2
  if rind < 16:
    pad += 3*(16 - rind)
  if rind <= 8:
    pad += 1
  line += ' '*pad

  line += ' '*(ind)
  line += '|'
  for byte in d:
    # printable ASCII range 0x20 to 0x7E
    if not PY3K:
      byte = ord(byte)
    if 0x20 <= byte <= 0x7E:
      line += chr(byte)
    else:
      line += '.'
  line += '|'
  line += ' '*(16-ind-len(d))
  #TODO use str.format instead to fixed width
  return line

def formatline(dataoffset, addr, dumpstr, d):
  return '%08x  %s' % (dataoffset + addr*16, linegen(dataoffset, dumpstr, d))

class Hexdump(object):
  """
  hexdump -C output, main function is gen.
  reset lastline if not a continuation.
  """
  def __init__(self):
    self.lastline = ''
    self.samelinecount = 0

  def gen(self, data, dataoffset=0):
    '''
    Generator that produces strings:

    '00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|'
    dataoffset as added to the displayed address, data should be trimmed accordingly
    '''
    # TODO implement dataoffset and length, displayed data should be padded acording to offset
    generator = chunks(data, 16)
    for addr, d in enumerate(generator):
      dumpstr = dump(d)

      if dumpstr == self.lastline:
        # if this is the first same line as last star it
        self.samelinecount += 1
        if self.samelinecount == 1:
          yield '*'
        if self.samelinecount >= 1:
          continue
      else:
        self.samelinecount = 0
        self.lastline = dumpstr

      yield formatline(dataoffset, addr, dumpstr, d)

  def end(self, data, dataoffset=0):
    # End with last line if it was not shown above
    # TODO display addr of file end instead, just like hexdump -C
    generator = chunks(data, 16)
    for addr, d in enumerate(generator):
      dumpstr = dump(d)

    if generator and self.samelinecount >= 1:
      yield formatline(dataoffset, addr, dumpstr, d)

def usage():
  return "  USAGE:\n\t%s  <file>" % (sys.argv[0])

if __name__ == '__main__':
  if len(sys.argv) != 2:
    print(usage())
    sys.exit(-1)

  f = open(sys.argv[1])
  buf = f.read()
  hdump = Hexdump()
  for line in hdump.gen(buf):
    print(line)
