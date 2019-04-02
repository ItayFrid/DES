'''
Itay Fridman - 305360653
'''
import itertools
import functools
ENCRYPT=1
DECRYPT=0
class Des:
  def __init__(self):
    ''' initialization of constants '''
    # Initial Permutation
    self.IP = [ 58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7 ]
    # IP^(-1) - Last Permutation
    self.LP = [ 40, 8, 48, 16, 56, 24, 64, 32, 
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25 ]
    # Substitution tables from 48b to 32b
    self.s = [
      [ [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13] ],

      [ [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9] ],

      [ [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12] ],

      [ [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14] ],

      [ [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3] ],

      [ [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13] ],

      [ [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12] ],

      [ [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11] ]
    ]
    # Expansion table from 32b to 48b
    self.E = [ 32, 1, 2, 3, 4, 5,
                4, 5, 6, 7, 8, 9,
                8, 9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32, 1 ]
    # Initial Key Permutation
    self.CP = [57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4 ]
    # Permutation key for ki+1
    self.CP2 = [14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40,
                51, 45, 33, 48, 44, 49, 39, 56,
                34, 53, 46, 42, 50, 36, 29, 32 ]
    # Permutation after each s box
    self.P = [16, 7, 20, 21, 29, 12, 28, 17,
              1, 15, 23, 26, 5, 18, 31, 10,
              2, 8, 24, 14, 32, 27, 3, 9,
              19, 13, 30, 6, 22, 11, 4, 25 ]
    self.SHIFT = [1,1,1]
    self.password = None
    self.text = None
    self.keys = []
  
  def nsplit(self,s, n):
    ''' splits the list to multiple lists of size n'''
    return [s[k:k+n] for k in range(0, len(s), n)]

  def binvalue(self,val, bitsize):
    ''' return the binary value as a string  with the size of bitsize'''
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise "binary value larger than the expected size"
    while len(binval) < bitsize:
        binval = "0"+binval
    return binval

  def bit_array_to_string(self,array):
    ''' from bit list to string '''
    res = ''.join([chr(int(y,2)) for y in [''.join([str(x) for x in b]) for b in self.nsplit(array,8)]])
    return res

  def string_to_bit_array(self,text):
    ''' from string to bit '''
    array = []
    for char in text:
        binval = self.binvalue(char, 8)
        array.extend([int(x) for x in list(binval)])
    return array

  def substitute(self, d_e):
    ''' subtitute values using the s boxes '''
    subblocks = self.nsplit(d_e, 6)
    result = []
    for i in range(len(subblocks)):
      block = subblocks[i]
      row = int(str(block[0])+str(block[5]),2)
      column = int(''.join([str(x) for x in block[1:][:-1]]),2)
      val = self.s[i][row][column]
      bin = self.binvalue(val, 4)
      result += [int(x) for x in bin]
    return result

  def permut(self, block, table):
    ''' permut the block by the table '''
    return [block[x-1] for x in table]

  def expand(self, block, table):
    ''' expand the block by the table '''
    return [block[x-1] for x in table]

  def xor(self, t1, t2):
    ''' Apply t1 XOR t2 '''
    return [x^y for x,y in zip(t1,t2)]

  def generatekeys(self):
    ''' generate the keys '''
    self.keys = []
    key = self.string_to_bit_array(self.password)
    key = self.permut(key, self.CP)
    g, d = self.nsplit(key, 28)
    for i in range(3):
      g, d = self.shift(g, d, self.SHIFT[i])
      tmp = g + d
      self.keys.append(self.permut(tmp, self.CP2)) 
  
  def shift(self, g, d, n):
    ''' shift list '''
    return g[n:] + g[:n], d[n:] + d[:n]

  def encrypt(self, key, text):
    return self.run(key, text, ENCRYPT)
    
  def decrypt(self, key, text):
    return self.run(key, text, DECRYPT)

  def run(self, key, text, action=ENCRYPT):
    ''' Encrypt / Decrypt the text/cipher '''
    self.password = key
    self.text = text

    self.generatekeys()
    text_blocks = self.nsplit(self.text, 8)
    result = []
    for block in text_blocks:
        block = self.string_to_bit_array(block)
        block = self.permut(block,self.IP)
        g, d = self.nsplit(block, 32) 
        tmp = None
        for i in range(3):
          d_e = self.expand(d, self.E)
          if action == ENCRYPT:
            tmp = self.xor(self.keys[i], d_e)
          else:
            tmp = self.xor(self.keys[2-i], d_e)
          tmp = self.substitute(tmp)
          tmp = self.permut(tmp, self.P)
          tmp = self.xor(g, tmp)
          g = d
          d = tmp
        result += self.permut(d+g, self.LP)
    final_res = self.bit_array_to_string(result)
    return final_res

string_to_hex = lambda string:"".join([hex(ord(char))[2:].zfill(2) for char in string])

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    return functools.reduce(lambda x,y:x+y, lst)

def crack(length):
  lst = []
  chars = "abcdefghijklmnopqrstuvwxyz"
  des = Des()
  text = "nonsense"
  cipher = "d8164228f290cbaf"
  i=1
  for item in itertools.product(chars, repeat=length):
    print("try {}".format(i))
    i +=1
    key = "".join(item)
    testCipher = des.encrypt(key,text)
    hexCipher = toHex(testCipher)
    if(cipher == hexCipher):
      print(key)
      return key

key = crack(8)