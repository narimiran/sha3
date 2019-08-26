SHA3 library. Two ways:
```nim
import sha3

var ctx: SHA3

sha3_init(ctx, SHA3_224, 4)
sha3_update(ctx, "a", 1)
sha3_update(ctx, "b", 1)
sha3_update(ctx, "c", 1)
assert(getSHA3(SHA3_224, "abc", 4) == $sha3_final(ctx))
```
Enum type for implemention: SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHA3_SHAKE128, SHA3_SHAKE256.


Since version "0.6" there is *KangarooTwelve* implementation:
```nim
import sha3

var ktx: Kangaroo12

sha3_init(ktx, 8, "keykey", 6)
sha3_update(ktx, "Mike", 4)
assert($sha3_final(ktx) == "285f85b139eb449b")
assert(getSHA3("Kangaroo12 is fast", 5) == "d793340e68")
```

Tests over vectors are included.
