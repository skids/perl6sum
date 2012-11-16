=begin pod

=head1 NAME

Sum::MD

=head1 SYNOPSIS

    use Sum::MD;

    class myMD5 does Sum::MD5 does Sum::Marshal::Raw { }
    my myMD5 $a .= new();
    $a.finalize("123456789".encode('ascii')).say;
        # 50479014739749459024317001064922631435

    # Usage is basically the same for MD4, MD4ext, RIPEMD128,
    # RIPEMD160, RIPEMD256 and RIPEMD320.

=end pod

# This is a bit of a hack.  We want the test suite to be able to try to
# run the code in the synopsis.  When pod is more functional maybe this
# will become more maintainable.  In the meantime, if you edit anything
# above, take care to adjust the sections here.

$Sum::MD::Doc::synopsis = $=pod[0].content[3..4]>>.content.Str;

=begin pod

=head1 DESCRIPTION

    Using C<Sum::MD> defines roles for generating types of C<Sum> that
    calculate the MD series of message digests (MD2, MD4, MD5, and MD6.)
    Note that all but the latter are considered deprecated for new
    applications, and insecure in some current applications.

    These sums require a small but significant memory profile while not
    finalized, so care must be taken when huge numbers of concurrent
    instances are used.

    NOTE: This implementation is unaudited and is for experimental
    use only.  When audits will be performed will depend on the maturation
    of individual Perl6 implementations, and should be considered
    on an implementation-by-implementation basis.

=end pod

=begin pod

=head1 ROLES

=head2 role Sum::MD4 [ :$mod8 = False ] does Sum

    The C<Sum::MD4> parametric role is used to create a type of C<Sum>
    that calculates an MD4 message digest.

    The resulting C<Sum> expects blocks as addends.  Currently, that
    means a Buf with 64 elements.  Passing a shorter Buf may be done
    once, before or during finalization.  Such a short Buf may optionally
    be followed by up to 7 bits (currently, Bool) if the message does
    not end on a byte boundary.  Attempts to provide more blocks after
    passing a short block will result in an C<X::Sum::Final>.

    C<Sum::Marshal::Block> roles may be mixed in to allow for accumulation
    of smaller addends and to split large messages into blocks.

    If the C<:mod8> flag is provided, then the resulting C<Sum> will
    only be able to handle messages that end on a byte boundary.
    The S<Sum> will no longer accept up to seven bit addends after a
    short block.  You probably do want to specify this flag unless you
    actually need to process bitfields of lengths that are not modulo 8.
    This may speed up the pure Perl6 implementation slightly, and since
    most third party high-speed hash libraries cannot handle raw bit
    data, it will be necessary to provide this flag to enable use
    of some of these libraries in the future (presently not implemented.)

=end pod

use Sum;

role Sum::MD4_5 [ :$alg where { * eqv [|] <MD5 MD4 MD4ext> } = "MD5",
                  :$mod8 = False ] does Sum {
    has $!o is rw = 0;
    has $!final is rw;
    has @!w is rw;     # "Parsed" message gets bound here.
    has @!s is rw;     # Current hash state.  H in specification.

    # MD5 table of constants (a.k.a. T[1..64] in RFC1321)
    my @t = (Int(4294967296 * .sin.abs) for 1..64);

    method size () {
        given $alg {
            when "MD4"|
                 "MD5"|
                 "RIPEMD-128" { 128 }
            when "MD4ext"     { 256 }
            when "RIPEMD-256" { 256 }
            when "RIPEMD-160" { 160 }
            when "RIPEMD-320" { 320 }
            default           { Inf }
        }
    }

    submethod BUILD () {
        @!s = (0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476);
        if $alg eqv "MD4ext" {
            @!s.push(0x33221100,0x77665544,0xbbaa9988,0xffeeddcc);
        }
        if $alg eqv ("RIPEMD-160"|"RIPEMD-320") {
            @!s.push(0xc3d2e1f0);
        }
	if $alg eqv ("RIPEMD-256"|"RIPEMD-320") {
            @!s.push(@!s.map({
                (0xf0f0f0f0 +& ($_ +< 4)) +|
                (0x0f0f0f0f +& ($_ +> 4)) }));
        }
        $!final = False;
    }

    # A moment of silence for the pixies that die every time something
    # like this gets written in an HLL.
    my sub rol ($v, Int $count where { -1 < * < 32 }) {
        my $tmp = ($v +< $count) +& 0xffffffff;
        $tmp +|= (($v +& 0xffffffff) +> (32 - $count));
	$tmp;
    }

    method md4_round1_step ($data, $shift) {
        my $a := @!s[0];
        my $b := @!s[1];
        my $c := @!s[2];
        my $d := @!s[3];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol(($a + $data + (($b +& $c) +| ((+^$b) +& $d))), $shift));
    }

    method md4_ext_round1_step ($data, $shift) {
        my $a := @!s[4];
        my $b := @!s[5];
        my $c := @!s[6];
        my $d := @!s[7];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol(($a + $data + (($b +& $c) +| ((+^$b) +& $d))), $shift));
    }

    method md4_round2_step ($data, $shift) {
        my $a := @!s[0];
        my $b := @!s[1];
        my $c := @!s[2];
        my $d := @!s[3];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol(($a + $data + 0x5a827999 +
                 ([+|] (($b,$b,$c) Z+& ($c,$d,$d)))), $shift));
    }

    method md4_ext_round2_step ($data, $shift) {
        my $a := @!s[4];
        my $b := @!s[5];
        my $c := @!s[6];
        my $d := @!s[7];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol(($a + $data + 0x50a28be6 +
                 ([+|] (($b,$b,$c) Z+& ($c,$d,$d)))), $shift));
    }

    method md4_round3_step ($data, $shift) {
        my $a := @!s[0];
        my $b := @!s[1];
        my $c := @!s[2];
        my $d := @!s[3];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol(($a + $data + 0x6ed9eba1 + ([+^] $b, $c, $d)), $shift));
    }

    method md4_ext_round3_step ($data, $shift) {
        my $a := @!s[4];
        my $b := @!s[5];
        my $c := @!s[6];
        my $d := @!s[7];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol(($a + $data + 0x5c4dd124 + ([+^] $b, $c, $d)), $shift));
    }

    method md5_round1_step ($data, $idx, $shift) {
        my $a := @!s[0];
        my $b := @!s[1];
        my $c := @!s[2];
        my $d := @!s[3];
        ($a,$d,$c,$b) = ($d, $c, $b, 0xffffffff +& (
             $b + rol(($a + @t[$idx] + $data +
                      (($b +& $c) +| (+^$b +& $d))), $shift)));
    }

    method md5_round2_step ($data, $idx, $shift) {
        my $a := @!s[0];
        my $b := @!s[1];
        my $c := @!s[2];
        my $d := @!s[3];
        ($a,$d,$c,$b) = ($d, $c, $b, 0xffffffff +& (
             $b + rol(($a + @t[$idx] + $data +
                      (($b +& $d) +| (+^$d +& $c))), $shift)));
    }

    method md5_round3_step ($data, $idx, $shift) {
        my $a := @!s[0];
        my $b := @!s[1];
        my $c := @!s[2];
        my $d := @!s[3];
        ($a,$d,$c,$b) = ($d, $c, $b, 0xffffffff +& (
             $b + rol(($a + $data + @t[$idx] + ([+^] $b, $c, $d)), $shift)));
    }

    method md5_round4_step ($data, $idx, $shift) {
        my $a := @!s[0];
        my $b := @!s[1];
        my $c := @!s[2];
        my $d := @!s[3];
        ($a,$d,$c,$b) = ($d, $c, $b, 0xffffffff +& (
          $b + rol(($a + $data + @t[$idx] + ($c +^ (+^$d +| $b))), $shift)));
    }

    method ripe_f1_5 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        my $e := @!s[$lr + 4];
        ($a,$e,$d,$c,$b) = ($e, $d, rol($c,10), $b, 0xffffffff +&
             ($e + rol($a + $k + $data + ([+^] $b, $c, $d), $shift)));
    }

    method ripe_f1_4 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol($a + $k + $data + ([+^] $b, $c, $d), $shift));
    }

    method ripe_f2_5 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        my $e := @!s[$lr + 4];
        ($a,$e,$d,$c,$b) = ($e, $d, rol($c,10), $b, 0xffffffff +&
             ($e + rol($a + $k + $data + (($b +& $c) +| (+^$b +& $d)),
                       $shift)));
    }

    method ripe_f2_4 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol($a + $k + $data + (($b +& $c) +| (+^$b +& $d)), $shift));
    }

    method ripe_f3_5 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        my $e := @!s[$lr + 4];
        ($a,$e,$d,$c,$b) = ($e, $d, rol($c,10), $b, 0xffffffff +&
             ($e + rol($a + $k + $data + ((+^$c +| $b) +^ $d), $shift)));
    }

    method ripe_f3_4 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol($a + $k + $data + ((+^$c +| $b) +^ $d), $shift));
    }

    method ripe_f4_5 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        my $e := @!s[$lr + 4];
        ($a,$e,$d,$c,$b) = ($e, $d, rol($c,10), $b, 0xffffffff +&
             ($e + rol($a + $k + $data + (($b +& $d) +| (+^$d +& $c)),
                       $shift)));
    }

    method ripe_f4_4 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        ($a,$d,$c,$b) = ($d, $c, $b,
             rol($a + $k + $data + (($b +& $d) +| (+^$d +& $c)), $shift));
    }

    method ripe_f5_5 ($lr, $data, $k, $shift) {
        my $a := @!s[$lr + 0];
        my $b := @!s[$lr + 1];
        my $c := @!s[$lr + 2];
        my $d := @!s[$lr + 3];
        my $e := @!s[$lr + 4];
        ($a,$e,$d,$c,$b) = ($e, $d, rol($c,10), $b, 0xffffffff +&
             ($e + rol($a + $k + $data + ($b +^ (+^$d +| $c)), $shift)));
    }

    method md4_comp () {
        my @s = @!s[];
        for (^16) Z (3,7,11,19) xx 4 {
            self.md4_round1_step(@!w[$^idx],$^shift);
	    self.md4_ext_round1_step(@!w[$^idx],$^shift)
                if $alg eqv "MD4ext";
        }
        for (0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15) Z (3,5,9,13) xx 4 {
            self.md4_round2_step(@!w[$^idx],$^shift);
            self.md4_ext_round2_step(@!w[$^idx],$^shift)
                if $alg eqv "MD4ext";
        }
        for (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) Z (3,9,11,15) xx 4 {
            self.md4_round3_step(@!w[$^idx],$^shift);
            self.md4_ext_round3_step(@!w[$^idx],$^shift)
                if $alg eqv "MD4ext";
        }
        @!s >>+=<< @s;
        @!s >>+&=>> 0xffffffff; # Should go away with sized types
        @!s[0,4] = @!s[4,0] if $alg eqv "MD4ext";
    }

    method md5_comp () {
        my @s = @!s[];
        for (^16) Z (^16) Z (7,12,17,22) xx 4 {
            self.md5_round1_step(@!w[$^didx], $^idx, $^shift);
        }
        for (1,6,11,0,5,10,15,4,9,14,3,8,13,2,7,12)
            Z (16..^32) Z (5,9,14,20) xx 4 {
            self.md5_round2_step(@!w[$^didx], $^idx, $^shift);
        }
        for (5,8,11,14,1,4,7,10,13,0,3,6,9,12,15,2)
            Z (32..^48) Z (4,11,16,23) xx 4 {
            self.md5_round3_step(@!w[$^didx], $^idx, $^shift);
        }
        for (0,7,14,5,12,3,10,1,8,15,6,13,4,11,2,9)
            Z (48..^64) Z (6,10,15,21) xx 4 {
            self.md5_round4_step(@!w[$^didx], $^idx, $^shift);
        }
        @!s >>+=<< @s;
        @!s >>+&=>> 0xffffffff; # Should go away with sized types
    }

    # RIPEMD constants
    my @lperms = [^16], { [ (7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8)[$_[]] ] }
        ... *[0]  == 4;
    my @rperms = [(9 * $_ + 5) % 16 for ^16], { [ @lperms[1][$_[]] ] }
        ... *[0]  == 12;
    my @kl = (0,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e);
    my @kr = (0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0);

    # These shifts appear in the spec, but are not used in the
    # example code, which seems to be what is used in other
    # implementations.  They may be leftover from the original
    # RIPEMD proposal, superseded by RIPEMD-128.
    # my @lr_shifts =
    #     [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8],
    #     [12,13,11,15,6,9,9,7,12,15,11,13,7,8,7,7],
    #     [13,15,14,11,7,7,6,8,13,14,13,12,5,5,6,9],
    #     [14,11,12,14,8,6,5,5,15,12,15,14,9,9,8,6],
    #     [15,12,13,13,9,5,8,6,14,11,12,11,8,6,5,5];

    my @lshifts =
        [ 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8 ],
        [ 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12 ],
        [ 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5 ],
        [ 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12 ],
        [ 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 ];
    my @rshifts =
        [ 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6 ],
        [ 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11 ],
        [ 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5 ],
        [ 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8 ],
        [ 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 ];

    method ripe5_comp {

        my @s = @!s[];
        @!s.push(@s) if $alg eqv "RIPEMD-160";

        for @lperms[0] Z @lshifts[0] {
            self.ripe_f1_5(0,@!w[$^didx],@kl[0],$^shift);
        }
        for @rperms[0] Z @rshifts[0] {
            self.ripe_f5_5(5,@!w[$^didx],@kr[0],$^shift);
        }
        @!s[1,6] = @!s[6,1] if $alg eqv "RIPEMD-320";
        for @lperms[1] Z @lshifts[1] {
            self.ripe_f2_5(0,@!w[$^didx],@kl[1],$^shift);
        }
        for @rperms[1] Z @rshifts[1] {
            self.ripe_f4_5(5,@!w[$^didx],@kr[1],$^shift);
        }
        @!s[3,8] = @!s[8,3] if $alg eqv "RIPEMD-320";
        for @lperms[2] Z @lshifts[2] {
            self.ripe_f3_5(0,@!w[$^didx],@kl[2],$^shift);
        }
        for @rperms[2] Z @rshifts[2] {
            self.ripe_f3_5(5,@!w[$^didx],@kr[2],$^shift);
        }
        @!s[0,5] = @!s[5,0] if $alg eqv "RIPEMD-320";
        for @lperms[3] Z @lshifts[3] {
            self.ripe_f4_5(0,@!w[$^didx],@kl[3],$^shift);
        }
        for @rperms[3] Z @rshifts[3] {
            self.ripe_f2_5(5,@!w[$^didx],@kr[3],$^shift);
        }
        @!s[2,7] = @!s[7,2] if $alg eqv "RIPEMD-320";
        for @lperms[4] Z @lshifts[4] {
            self.ripe_f5_5(0,@!w[$^didx],@kl[4],$^shift);
        }
        for @rperms[4] Z @rshifts[4] {
            self.ripe_f1_5(5,@!w[$^didx],@kr[4],$^shift);
        }
        @!s[4,9] = @!s[9,4] if $alg eqv "RIPEMD-320";
        if $alg eqv "RIPEMD-160" {
            @!s = @s[1,2,3,4,0] Z+ @!s[2,3,4,0,1] Z+ @!s[8,9,5,6,7];
        }
        else {
            @!s = @!s Z+ @s;
        }
        @!s = 0xffffffff X+& @!s;
    }

    method ripe4_comp {

        my @s = @!s[];
        @!s.push(@s) if $alg eqv "RIPEMD-128";

        for @lperms[0] Z @lshifts[0] {
            self.ripe_f1_4(0,@!w[$^didx],@kl[0],$^shift);
        }
        for @rperms[0] Z @rshifts[0] {
            self.ripe_f4_4(4,@!w[$^didx],@kr[0],$^shift);
        }
        @!s[0,4] = @!s[4,0] if $alg eqv "RIPEMD-256";
        for @lperms[1] Z @lshifts[1] {
            self.ripe_f2_4(0,@!w[$^didx],@kl[1],$^shift);
        }
        for @rperms[1] Z @rshifts[1] {
            self.ripe_f3_4(4,@!w[$^didx],@kr[1],$^shift);
        }
        @!s[1,5] = @!s[5,1] if $alg eqv "RIPEMD-256";
        for @lperms[2] Z @lshifts[2] {
            self.ripe_f3_4(0,@!w[$^didx],@kl[2],$^shift);
        }
        for @rperms[2] Z @rshifts[2] {
            self.ripe_f2_4(4,@!w[$^didx],@kr[2],$^shift);
        }
        @!s[2,6] = @!s[6,2] if $alg eqv "RIPEMD-256";
        for @lperms[3] Z @lshifts[3] {
            self.ripe_f4_4(0,@!w[$^didx],@kl[3],$^shift);
        }
        for @rperms[3] Z @rshifts[3] {
            self.ripe_f1_4(4,@!w[$^didx],@kr[4],$^shift);
        }
        @!s[3,7] = @!s[7,3] if $alg eqv "RIPEMD-256";
        if $alg eqv "RIPEMD-128" {
            @!s = @s[1,2,3,0] Z+ @!s[2,3,0,1] Z+ @!s[7,4,5,6];
        }
        else {
            @!s = @!s Z+ @s;
        }
        @!s = 0xffffffff X+& @!s;
    }

    # TODO: when role trusts work for private attributes, these first three
    # candidates can be made generic across a main role and the above
    # conglomeration of functions and constant split up into proper subroles.
    multi method do_add (*@addends) {
        sink for (@addends) { self.add($_) }
    }
    multi method do_add ($addend) {
        # TODO: Typed failure here?
        die("Marshalling error.  Addends must be Buf with 0..64 bytes.");
    }
    multi method do_add (Buf $block where { -1 < .elems < 64 },
                         Bool $b7?, Bool $b6?, Bool $b5?, Bool $b4?,
                         Bool $b3?, Bool $b2?, Bool $b1?) {
        my $bits = 0;
        my $byte = 0;

#        $block.gist.say;

        # Count how many stray bits we have and build them into a byte
        ( $byte +|= +$_ +< (7 - $bits++) )
            if .defined for ($b7,$b6,$b5,$b4,$b3,$b2,$b1);

        # Update the count of the total number of bits sent.
        $!o += $block.elems * 8 + $bits;
        $!o +&= 0xffffffffffffffff;

        # Check if buffer, bits, the added 1 bit, and the length fit in block
        if $block.elems * 8 + $bits + 1 + 64 < 513 { # Yes

            # Note 1 +< (7 - $bits) just happily also DTRT when !$bits
            self.add(Buf.new($block[],$byte +| 1 +< (7 - $bits),
                     0 xx (55 - $block.elems),
                     (255 X+& ($!o X+> (0,8,16,24,32,40,48,56)))));
            $!o -= 512; # undo what the other multimethod did.
        }
        else { # No

            # So break it into two blocks.
            self.add(Buf.new($block[],$byte +| 1 +< (7 - $bits),
                     0 xx (63 - $block.elems)));
            $!o -= 512;  # undo what the other multimethod did.
            self.add(Buf.new(0 xx 56,
                     (255 X+& ($!o X+> (0,8,16,24,32,40,48,56)))));
            $!o -= 512; # undo what the other multimethod did.
        }
        $!final = True;
    }
    multi method do_add (Buf $block where { .elems == 64 }) {

        # We now have a complete block to crunch.

#        $block.gist.say;

        # Explode the message block into a scratchpad

        # First 16 uint32's are a straight copy of the data.
        # When endianness matches and with native types,
        # this would boil down to a simple memcpy.
        my @m = (:256[ $block[ reverse($_ ..^ $_+4) ] ]
                 for 0,{$^idx + 4} ...^ 64);

	@!w := @m;
        self.md4_comp if $alg eqv ("MD4"|"MD4ext");
        self.md5_comp if $alg eqv "MD5";
        self.ripe4_comp if $alg eqv ("RIPEMD-128"|"RIPEMD-256");
        self.ripe5_comp if $alg eqv ("RIPEMD-160"|"RIPEMD-320");

        # Update the size in bits.
        $!o += 512;  # spec permits this to wrap for large messages
        $!o +&= 0xffffffffffffffff; # Should go away with sized types
    };
    method add (*@addends) { self.do_add(|@addends) }

    method finalize(*@addends) {
        given self.push(@addends) {
            return $_ unless $_.exception.WHAT ~~ X::Sum::Push::Usage;
        }

        self.add(self.drain) if self.^can("drain");

        self.add(Buf.new()) unless $!final;

        :256[ 255 X+& (@!s[] X+> (0,8,16,24)) ]
    }
    method Numeric () { self.finalize };
    method buf8 () {
        self.finalize;
        Buf.new(255 X+& (@!s[] X+> (0,8,16,24)));
    }
    method Buf () { self.buf8 }
}

role Sum::MD4       does Sum::MD4_5[ :alg<MD4> ]        { }
role Sum::MD4ext    does Sum::MD4_5[ :alg<MD4ext> ]     { }
role Sum::MD5       does Sum::MD4_5[ :alg<MD5> ]        { }
role Sum::RIPEMD128 does Sum::MD4_5[ :alg<RIPEMD-128> ] { }
role Sum::RIPEMD160 does Sum::MD4_5[ :alg<RIPEMD-160> ] { }
role Sum::RIPEMD256 does Sum::MD4_5[ :alg<RIPEMD-256> ] { }
role Sum::RIPEMD320 does Sum::MD4_5[ :alg<RIPEMD-320> ] { }

=begin pod

=head1 AUTHOR

    Written by Brian S. Julin

=head1 COPYRIGHT

    Copyright (c) 2012 Brian S. Julin. All rights reserved.  This program is
    free software; you can redistribute it and/or modify it under the terms
    of the Perl Artistic License 2.0.

=head1 REFERENCES

=head1 SEE ALSO

    C<Sum::(pm3)>

=end pod

