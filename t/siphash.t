use v6;
BEGIN { @*INC.unshift: './lib'; }

use Test;

plan 70;

use Sum::SipHash;
ok(1,'We use Sum::SipHash and we are still alive');

class S does SipHash does Sum::Marshal::Method[:atype(Str),:method<ords>] { }
my S $s .= new(:key(0x000102030405060708090a0b0c0d0e0f));
is $s.size, 64, "SipHash.size works";
my $h = $s.finalize("Please to checksum this text");
is $h, 0x5cabf2fe9143a691, "SipHash (StrOrds) computes expected value";
$h = $s.finalize(".");
is $h, 0x4fe6afaef85fbad6, "append after finalization and get expected value";
is $s.partials("......"), (0xf3009ba116623fd5, 0xb28753d8b488ae38, 0xfedd16cd7a81b334, 0x17241487941ee6da, 0xdc73124438fcb94d, 0x4c80530e3ead0ad7), "partials yields expected values across a w boundary";
is $s.Buf.values, (0x4c,0x80,0x53,0x0e,0x3e,0xad,0x0a,0xd7), "Buf method works";

# Now grab the code in the synopsis from the POD and make sure it runs.
# This is currently complete hackery but might improve when pod support does.
# And also an outputs_ok Test.pm function that redirects $*OUT might be nice.
class sayer {
    has $.accum is rw = "";
    method print (*@s) { $.accum ~= [~] @s }
}
my sayer $p .= new();
#{ temp $*OUT = $p; EVAL $Sum::SipHash::Doc::synopsis; }
#is $p.accum, $Sum::SipHash::Doc::synopsis.comb(/<.after \#\s> (<.ws> <.xdigit>+)+/).join("\n") ~ "\n", 'Code in manpage synopsis actually works';

# These test vectors appear in Aumussen reference C implentation

my @refvecs = (
0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
0xcf2794e0277187b7, 0x18765564cd99a68d, 0xcbc9466e58fee3ce, 0xab0200f58b01d137,
0x93f5f5799a932462, 0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
0x751e8fbc860ee5fb, 0x14ea5627c0843d90, 0xf723ca908e7af2ee, 0xa129ca6149be45e5,
0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794, 0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd,
0xbed65cf21aa2ee98, 0xd0f2cbb02e3b67c7, 0x93536795e3a33e88, 0xa80c038ccd5ccec8,
0xb8ad50c6f649af94, 0xbce192de8a85b8ea, 0x17d835b85bbb15f3, 0x2f2e6163076bcfad,
0xde4daaaca71dc9a5, 0xa6a2506687956571, 0xad87a3535c49ef28, 0x32d892fad841c342,
0x7127512f72f27cce, 0xa7f32346f95978e3, 0x12e0b01abb051238, 0x15e034d40fa197ae,
0x314dffbe0815a3b4, 0x027990f029623981, 0xcadcd4e59ef40c4d, 0x9abfd8766a33735c,
0x0e3ea96b5304a7d0, 0xad0c42d6fc585992, 0x187306c89bc215a9, 0xd4a60abcf3792b95,
0xf935451de4f21df2, 0xa9538f0419755787, 0xdb9acddff56ca510, 0xd06c98cd5c0975eb,
0xe612a3cb9ecba951, 0xc766e62cfcadaf96, 0xee64435a9752fe72, 0xa192d576b245165a,
0x0a8787bf8ecb74b2, 0x81b3e73d20b49b6f, 0x7fa8220ba3b2ecea, 0x245731c13ca42499,
0xb78dbfaf3a8d83bd, 0xea1ad565322a1a0b, 0x60e61c23a3795013, 0x6606d7e446282b93,
0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3, 0xe51b38608ef25f57, 0x958a324ceb064572
);

for @refvecs.kv -> $n, $vec {
    $s .= new(:key(0x000102030405060708090a0b0c0d0e0f));
    is $s.finalize(0..$n-1).base(16), $vec.base(16),
        "Reference vector #$n matches"
}
