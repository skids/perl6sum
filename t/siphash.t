use v6;
BEGIN { @*INC.unshift: './lib'; }

use Test;

plan 7;

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
{ temp $*OUT = $p; eval $Sum::SipHash::Doc::synopsis; }
is $p.accum, $Sum::SipHash::Doc::synopsis.comb(/<.after \#\s> (<.ws> <.xdigit>+)+/).join("\n") ~ "\n", 'Code in manpage synopsis actually works';
