use v6;
BEGIN { @*INC.unshift: './lib'; }

use Test;

plan 43;

use Sum::SHA;
ok 1,'We use Sum::SHA and we are still alive';

# fmt('%x') seems to have its limitations at present.
sub hexify ($i is copy) {
    join('',reverse (gather while $i { take ($i +& 0xffffffffffffffff).fmt('%x'); $i +>= 64; }));
}

class SHA1t does Sum::SHA1 does Sum::Marshal::Raw { };
my SHA1t $s .= new();
ok $s.WHAT === SHA1t, 'We create a SHA1 class and object';

is SHA1t.new().finalize(Buf.new()),
   0xda39a3ee5e6b4b0d3255bfef95601890afd80709,
   "SHA1 of an empty buffer is correct.";
is SHA1t.new().finalize(Buf.new(97)),
   0x86f7e437faa5a7fce15d1ddcb9eaeaea377667b8,
   "SHA1 of a 1-byte buffer is correct.";
is SHA1t.new().finalize(Buf.new(97 xx 55)),
   0xc1c8bbdc22796e28c0e15163d20899b65621d65a,
   "SHA1 of a 55-byte buffer is correct.";
is SHA1t.new().finalize(Buf.new(97 xx 56)),
   0xc2db330f6083854c99d4b5bfb6e8f29f201be699,
   "SHA1 of a 56-byte buffer is correct.";
is SHA1t.new().finalize(Buf.new(97 xx 64)),
   0x0098ba824b5c16427bd7a1122a5a442a25ec644d,
   "SHA1 of a 64-byte buffer is correct.";

todo "need to find 3rd party app that sums %8 != 0 bitfields", 6;
is SHA1t.new().finalize(Buf.new(),True),
   0x00, #TODO
   "SHA1 of a 1-bit buffer is correct.";
is SHA1t.new().finalize(Buf.new(),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA1 of a 7-bit buffer is correct.";
is SHA1t.new().finalize(Buf.new(97),True),
   0x00, #TODO
   "SHA1 of a 9-bit buffer is correct.";
is SHA1t.new().finalize(Buf.new(0x31 xx 55),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA1 of a 447-bit buffer is correct.";
is SHA1t.new().finalize(Buf.new(0x31 xx 56),False),
   0x00, #TODO
   "SHA1 of a 449-bit buffer is correct.";
is SHA1t.new().finalize(Buf.new(0x31 xx 63),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA1 of a 511-bit buffer is correct.";

class SHA0t does Sum::SHA1[:insecure_sha0_obselete] does Sum::Marshal::Raw { };
is SHA0t.new().finalize(Buf.new(97 xx 55)),
   0x0ff59f7cb9afc10d7abcdc9ab8c00e0e7b02034f,
   "obselete SHA0 tweak of SHA1 works.";

class SHA256t does Sum::SHA2[ :columns(256) ] does Sum::Marshal::Raw { };
my SHA256t $s2 .= new();
ok $s2.WHAT === SHA256t, 'We create a SHA2 (SHA-256) class and object';

is SHA256t.new().finalize(Buf.new()),
   0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,
   "SHA-256 of an empty buffer is correct.";
is SHA256t.new().finalize(Buf.new(97)),
   0xca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb,
   "SHA-256 of a 1-byte buffer is correct.";
is SHA256t.new().finalize(Buf.new(97 xx 55)),
   0x9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318,
   "SHA-256 of a 55-byte buffer is correct.";
is SHA256t.new().finalize(Buf.new(97 xx 56)),
   0xb35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a,
   "SHA-256 of a 56-byte buffer is correct.";
is SHA256t.new().finalize(Buf.new(97 xx 64)),
   0xffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb,
   "SHA-256 of a 64-byte buffer is correct.";

todo "need to find 3rd party app that sums %8 != 0 bitfields", 6;
is SHA256t.new().finalize(Buf.new(),True),
   0x00, #TODO
   "SHA-256 of a 1-bit buffer is correct.";
is SHA256t.new().finalize(Buf.new(),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA-256 of a 7-bit buffer is correct.";
is SHA256t.new().finalize(Buf.new(97),True),
   0x00, #TODO
   "SHA-256 of a 9-bit buffer is correct.";
is SHA256t.new().finalize(Buf.new(0x31 xx 55),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA-256 of a 447-bit buffer is correct.";
is SHA256t.new().finalize(Buf.new(0x31 xx 56),False),
   0x00, #TODO
   "SHA-256 of a 449-bit buffer is correct.";
is SHA256t.new().finalize(Buf.new(0x31 xx 63),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA-256 of a 511-bit buffer is correct.";

class SHA224t does Sum::SHA2[ :columns(224) ] does Sum::Marshal::Raw { };
my SHA224t $s3 .= new();
ok $s3.WHAT === SHA224t, 'We create a SHA2 (SHA-224) class and object';
is SHA224t.new().finalize(Buf.new(97 xx 55)),
   0xfb0bd626a70c28541dfa781bb5cc4d7d7f56622a58f01a0b1ddd646f,
   "SHA-224 expected result is correct.";

class SHA512t does Sum::SHA2[ :columns(512) ] does Sum::Marshal::Raw { };
my SHA512t $s4 .= new();
ok $s4.WHAT === SHA512t, 'We create a SHA2 (SHA-512) class and object';

is SHA512t.new().finalize(Buf.new()),
   0xcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e,
   "SHA-512 of an empty buffer is correct.";
is SHA512t.new().finalize(Buf.new(97)),
   0x1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75,
   "SHA-512 of a 1-byte buffer is correct.";
is SHA512t.new().finalize(Buf.new(97 xx 111)),
   0xfa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2,
   "SHA-512 of a 111-byte buffer is correct.";
is SHA512t.new().finalize(Buf.new(97 xx 112)),
   0xc01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca,
   "SHA-512 of a 112-byte buffer is correct.";
is SHA512t.new().finalize(Buf.new(97 xx 128)),
   0xb73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321,
   "SHA-512 of a 128-byte buffer is correct.";

todo "need to find 3rd party app that sums %8 != 0 bitfields", 6;
is SHA512t.new().finalize(Buf.new(),True),
   0x00, #TODO
   "SHA-512 of a 1-bit buffer is correct.";
is SHA512t.new().finalize(Buf.new(),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA-512 of a 7-bit buffer is correct.";
is SHA512t.new().finalize(Buf.new(97),True),
   0x00, #TODO
   "SHA-512 of a 9-bit buffer is correct.";
is SHA512t.new().finalize(Buf.new(0x31 xx 111),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA-512 of a 895-bit buffer is correct.";
is SHA512t.new().finalize(Buf.new(0x31 xx 112),False),
   0x00, #TODO
   "SHA-512 of a 896-bit buffer is correct.";
is SHA512t.new().finalize(Buf.new(0x31 xx 127),True,False,True,False,True,False,False),
   0x00, #TODO
   "SHA-512 of a 1023-bit buffer is correct.";

class SHA384t does Sum::SHA2[ :columns(384) ] does Sum::Marshal::Raw { };
my SHA384t $s5 .= new();
ok $s5.WHAT === SHA384t, 'We create a SHA2 (SHA-384) class and object';

is SHA384t.new().finalize(Buf.new(97 xx 111)),
   0x3c37955051cb5c3026f94d551d5b5e2ac38d572ae4e07172085fed81f8466b8f90dc23a8ffcdea0b8d8e58e8fdacc80a,
   "SHA-384 expected result is correct.";

# Now grab the code in the synopsis from the POD and make sure it runs.
# This is currently complete hackery but might improve when pod support does.
# And also an outputs_ok Test.pm function that redirects $*OUT might be nice.
class sayer {
    has $.accum is rw = "";
    method print (*@s) { $.accum ~= [~] @s }
}
my sayer $p .= new();
{ temp $*OUT = $p; eval $Sum::SHA::Doc::synopsis; }
is $p.accum, $Sum::SHA::Doc::synopsis.comb(/<.after \#\s> (<.ws> <.xdigit>+)+/).join("\n") ~ "\n", 'Code in manpage synopsis actually works';
