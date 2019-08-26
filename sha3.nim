type
   SHA3* = object
      hash: array[25, uint64]
      buffer: array[168, uint8]
      buffer_idx: int
      max_idx: int
      rounds: int
      delim: uint8
      hash_size: int
   Kangaroo12* = object
      outer: SHA3
      inner: SHA3
      key: cstring
      key_size: int
      chunks: uint64
      current: uint64

   SHA3_HASH* = enum
      SHA3_224 = 224,
      SHA3_256 = 256,
      SHA3_384 = 384,
      SHA3_512 = 512
   SHA3_SHAKE* = enum
      SHA3_SHAKE128 = 128,
      SHA3_SHAKE256 = 256

const
   RC = [
      0x0000000000000001'u64, 0x0000000000008082'u64,
      0x800000000000808a'u64, 0x8000000080008000'u64,
      0x000000000000808b'u64, 0x0000000080000001'u64,
      0x8000000080008081'u64, 0x8000000000008009'u64,
      0x000000000000008a'u64, 0x0000000000000088'u64,
      0x0000000080008009'u64, 0x000000008000000a'u64,
      0x000000008000808b'u64, 0x800000000000008b'u64,
      0x8000000000008089'u64, 0x8000000000008003'u64,
      0x8000000000008002'u64, 0x8000000000000080'u64,
      0x000000000000800a'u64, 0x800000008000000a'u64,
      0x8000000080008081'u64, 0x8000000000008080'u64,
      0x0000000080000001'u64, 0x8000000080008008'u64 ]
   ROTC = [
       1,  3,  6, 10, 15, 21, 28, 36,
      45, 55,  2, 14, 27, 41, 56,  8,
      25, 43, 62, 18, 39, 61, 20, 44 ]
   PIL = [
      10,  7, 11, 17, 18,  3,  5, 16,
       8, 21, 24,  4, 15, 23, 19, 13,
      12,  2, 20, 14, 22,  9,  6,  1 ]

proc rol64(x: uint64, n: int): uint64 {.inline.} =
   result = (x shl n) or (x shr (64 - n))

proc right_encode(n: uint64): seq[uint8] =
   var z = n
   result = @[]
   var i: uint8 = 0
   while (z > 0'u64):
      result.insert(uint8(`mod`(z, 256)), 0)
      inc(i)
      z = `div`(z, 256)
   result.add(i)

proc thera(h: var array[25, uint64]) {.inline.} =
   var
      a, b: array[5, uint64]
   for i in 0..<5:
      a[i] = h[i] xor h[i + 5] xor h[i + 10] xor
             h[i + 15] xor h[i + 20]
   b[0] = rol64(a[1], 1) xor a[4]
   b[1] = rol64(a[2], 1) xor a[0]
   b[2] = rol64(a[3], 1) xor a[1]
   b[3] = rol64(a[4], 1) xor a[2]
   b[4] = rol64(a[0], 1) xor a[3]
   for i in 0..<5:
      h[i]      = h[i]      xor b[i]
      h[i + 5]  = h[i + 5]  xor b[i]
      h[i + 10] = h[i + 10] xor b[i]
      h[i + 15] = h[i + 15] xor b[i]
      h[i + 20] = h[i + 20] xor b[i]

proc rho_pi(h: var array[25, uint64]) {.inline.} =
   var a, b: uint64
   a = h[1]
   for i in 0..<24:
      b = h[PIL[i]]
      h[PIL[i]] = rol64(a, ROTC[i])
      a = b

proc chi(h: var array[25, uint64]) {.inline.} =
   var a, b: uint64
   for i in countup(0, 20, 5):
      a = h[i]
      b = h[i + 1]
      h[i]     = h[i]     xor not(b) and h[i + 2]
      h[i + 1] = h[i + 1] xor not(h[i + 2]) and h[i + 3]
      h[i + 2] = h[i + 2] xor not(h[i + 3]) and h[i + 4]
      h[i + 3] = h[i + 3] xor not(h[i + 4]) and a
      h[i + 4] = h[i + 4] xor not(a) and b

proc xor_buffer(c: var SHA3) {.inline.} =
   for i in 0..<c.max_idx div 8:
      c.hash[i] = c.hash[i] xor
                  cast[ptr uint64](addr(c.buffer[i*8]))[]

proc keccakf(c: var SHA3) =
   var y = 0
   if (c.rounds == 12): y = c.rounds
   for i in 0..<c.rounds:
      thera(c.hash)
      rho_pi(c.hash)
      chi(c.hash)
      c.hash[0] = c.hash[0] xor RC[i+y]
   c.buffer_idx = 0

proc sha3_update*(c: var SHA3, data: cstring|string|seq|uint8,
                  data_size: int) =
   for i in 0..<data_size:
      when data is cstring or data is string:
         c.buffer[c.buffer_idx] = ord(data[i])
      elif data is seq:
         c.buffer[c.buffer_idx] = data[i]
      else:
         c.buffer[c.buffer_idx] = data
      inc(c.buffer_idx)
      if (c.buffer_idx >= c.max_idx):
         xor_buffer(c)
         keccakf(c)

template sha3_init*(c: var SHA3, hash: typed, size: int = 0) =
   let rate = ord(hash) div 8
   if (size == 0):
      c.hash_size = rate
   else:
      c.hash_size = size
   if (hash is SHA3_HASH):
      assert(c.hash_size >= 1 and c.hash_size <= rate)
   c.rounds = 24
   c.max_idx = 200 - 2 * rate
   if (hash is SHA3_SHAKE):
      c.delim = 31
   else:
      c.delim = 6

proc sha3_final*(c: var SHA3): seq[uint8] =
   result = @[]
   c.buffer[c.buffer_idx] = c.delim
   inc(c.buffer_idx)
   for i in c.buffer_idx..<c.max_idx: c.buffer[i] = 0
   c.buffer[c.max_idx - 1] = c.buffer[c.max_idx - 1] xor 128
   xor_buffer(c)
   keccakf(c)
   while (c.hash_size > 0):
      let block_size = min(c.hash_size, c.max_idx)
      for i in 0..<block_size:
         result.add(cast[uint8]((c.hash[i div 8] shr
                    (8 * (i and 7)) and 0xFF)))
      dec(c.hash_size, block_size)
      if (c.hash_size > 0): keccakf(c)
   zeroMem(addr(c), sizeof(c))

proc sha3_init*(c: var Kangaroo12, size: int,
                key: cstring = nil, key_size: int = 0) =
   sha3_init(c.outer, SHA3_SHAKE128, size)
   sha3_init(c.inner, SHA3_SHAKE128, 32)
   c.outer.rounds = 12
   # c.outer.delim in sha3_final()
   c.inner.rounds = 12
   c.inner.delim = 11
   c.key = key
   c.key_size = key_size

proc sha3_update*(c: var Kangaroo12, data: cstring|string|seq|uint8,
                  data_size: int) =
   let P = @[3'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8]
   for i in 0..<data_size:
      if (c.current == 8192):
         if (c.chunks == 0):
            sha3_update(c.outer, P, 8)
         else:
            sha3_update(c.outer, sha3_final(c.inner), 32)
            sha3_init(c.inner, SHA3_SHAKE128, 32)
            c.inner.rounds = 12
            c.inner.delim = 11
         c.current = 0
         inc(c.chunks)

      if (c.chunks == 0):
         when data is cstring or data is string:
            sha3_update(c.outer, ($data[i]).cstring, 1)
         elif data is seq:
            sha3_update(c.outer, data[i], 1)
         else:
            sha3_update(c.outer, data, 1)
      else:
         when data is cstring or data is string:
            sha3_update(c.inner, ($data[i]).cstring, 1)
         elif data is seq:
            sha3_update(c.inner, data[i], 1)
         else:
            sha3_update(c.inner, data, 1)

      inc(c.current)

proc sha3_final*(c: var Kangaroo12): seq[uint8] =
   let P = @[255'u8, 255'u8]
   var R: seq[uint8]
   result = @[]

   sha3_update(c, c.key, c.key_size)
   R = right_encode(uint64(c.key_size))
   sha3_update(c, R, len(R))

   if (c.chunks == 0):
      c.outer.delim = 7
   else:
      sha3_update(c.outer, sha3_final(c.inner), 32)
      R = right_encode(c.chunks)
      sha3_update(c.outer, R, len(R))
      sha3_update(c.outer, P, 2)
      c.outer.delim = 6
   result = sha3_final(c.outer)
   zeroMem(addr(c), sizeof(c))

proc `$`*(d: seq[uint8]): string =
  const digits = "0123456789abcdef"
  result = ""
  for i in 0..high(d):
    add(result, digits[(d[i] shr 4) and 0xF])
    add(result, digits[d[i] and 0xF])

template getSHA3*(h: typed, s: string, hash_size: int = 0): string =
   var ctx: SHA3
   sha3_init(ctx, h, hash_size)
   sha3_update(ctx, s, len(s))
   $sha3_final(ctx)

proc getSHA3*(s: string, hash_size: int = 0): string =
   var ctx: Kangaroo12
   sha3_init(ctx, hash_size)
   sha3_update(ctx, s, len(s))
   $sha3_final(ctx)

when isMainModule:
   import strutils

   var
      ktx: Kangaroo12
      f: File
      splt: seq[string]
      Aaa: cstring

   proc hex2str(s: string): string =
      result = ""
      for i in countup(0, high(s), 2):
         add(result, chr(parseHexInt(s[i] & s[i+1])))
   f = open("kangaroo-K12.rsp", fmRead)
   while true:
      try:
         sha3_init(ktx, 16, "abc", 3)
         splt = split(f.readLine(), ':')
         Aaa = cstring(repeatStr(parseInt(splt[0]), "abc"))
         for i in 0..high(Aaa):
            sha3_update(ktx, ($Aaa[i]).cstring, 1)
         assert($sha3_final(ktx) == toLowerAscii(splt[1]))
      except IOError: break
   close(f)
   assert(getSHA3("a", 16) == "9ead6b5332e658d12672d3ab0de17f12")
   assert(getSHA3(nil, 16) == "1ac2d450fc3b4205d19da7bfca1b3751")
   assert(getSHA3("abc", 4) == "ab174f32")
   assert(getSHA3("The quick brown fox jumps over the lazy dog") == "b4f249b4f77c58df170aa4d1723db112")

   var ctx: SHA3

   sha3_init(ctx, SHA3_224)
   assert("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7" ==
           $sha3_final(ctx))
   sha3_init(ctx, SHA3_256)
   assert("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" ==
           $sha3_final(ctx))
   sha3_init(ctx, SHA3_384)
   assert("0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004" ==
           $sha3_final(ctx))
   sha3_init(ctx, SHA3_512)
   assert("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" ==
           $sha3_final(ctx))
   sha3_init(ctx, SHA3_SHAKE128)
   assert("7f9c2ba4e88f827d616045507605853e" ==
           $sha3_final(ctx))
   sha3_init(ctx, SHA3_SHAKE256)
   assert("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" ==
           $sha3_final(ctx))

   sha3_init(ctx, SHA3_224, 4)
   sha3_update(ctx, "a", 1)
   sha3_update(ctx, "b", 1)
   sha3_update(ctx, "c", 1)
   assert(getSHA3(SHA3_224, "abc", 4) == $sha3_final(ctx))
   sha3_init(ctx, SHA3_256, 4)
   sha3_update(ctx, "a", 1)
   sha3_update(ctx, "b", 1)
   sha3_update(ctx, "c", 1)
   assert(getSHA3(SHA3_256, "abc", 4) == $sha3_final(ctx))
   sha3_init(ctx, SHA3_384, 4)
   sha3_update(ctx, "a", 1)
   sha3_update(ctx, "b", 1)
   sha3_update(ctx, "c", 1)
   assert(getSHA3(SHA3_384, "abc", 4) == $sha3_final(ctx))
   sha3_init(ctx, SHA3_512, 4)
   sha3_update(ctx, "a", 1)
   sha3_update(ctx, "b", 1)
   sha3_update(ctx, "c", 1)
   assert(getSHA3(SHA3_512, "abc", 4) == $sha3_final(ctx))
   assert("f4202e3c5852f9182a0430fd8144f0a7" ==
          getSHA3(SHA3_SHAKE128, "The quick brown fox jumps over the lazy dog"))
   assert("853f4538be0db9621a6cea659a06c110" ==
          getSHA3(SHA3_SHAKE128, "The quick brown fox jumps over the lazy dof"))
   assert("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b9" ==
          getSHA3(SHA3_SHAKE128, "abc", 222))

   var
      data, hash: string
      tst = newSeq[tuple[h: SHA3_HASH, f: string]]()
      shake = newSeq[tuple[h: SHA3_SHAKE, f:string]]()
   tst.add((h:SHA3_224, f:"SHA3_224ShortMsg.rsp"))
   tst.add((h:SHA3_224, f:"SHA3_224LongMsg.rsp"))
   tst.add((h:SHA3_256, f:"SHA3_256ShortMsg.rsp"))
   tst.add((h:SHA3_256, f:"SHA3_256LongMsg.rsp"))
   tst.add((h:SHA3_384, f:"SHA3_384ShortMsg.rsp"))
   tst.add((h:SHA3_384, f:"SHA3_384LongMsg.rsp"))
   tst.add((h:SHA3_512, f:"SHA3_512ShortMsg.rsp"))
   tst.add((h:SHA3_512, f:"SHA3_512LongMsg.rsp"))
   shake.add((h:SHA3_SHAKE128, f:"SHAKE128ShortMsg.rsp"))
   shake.add((h:SHA3_SHAKE128, f:"SHAKE128LongMsg.rsp"))
   shake.add((h:SHA3_SHAKE256, f:"SHAKE256ShortMsg.rsp"))
   shake.add((h:SHA3_SHAKE256, f:"SHAKE256LongMsg.rsp"))
   for t in tst:
      f = open(t[1], fmRead)
      while true:
         try:
            discard f.readLine()
            data = f.readLine()
            data = hex2str(data[6..^0])
            hash = f.readLine()
            hash = hash[5..^0]
            assert(getSHA3(t[0], data) == hash)
            sha3_init(ctx, t[0])
            for i in 0..high(data):
               sha3_update(ctx, ($data[i]).cstring, 1)
            assert($sha3_final(ctx) == hash)
            discard f.readLine()
         except IOError: break
      close(f)
   for t in shake:
      f = open(t[1], fmRead)
      while true:
         try:
            discard f.readLine()
            data = f.readLine()
            data = hex2str(data[6..^0])
            hash = f.readLine()
            hash = hash[9..^0]
            assert(getSHA3(t[0], data) == hash)
            sha3_init(ctx, t[0])
            for i in 0..high(data):
               sha3_update(ctx, ($data[i]).cstring, 1)
            assert($sha3_final(ctx) == hash)
            discard f.readLine()
         except IOError: break
      close(f)
   echo "ok"

