=begin pod

=head1 NAME

Sum::SHA

=head1 SYNOPSIS

    use Sum::SHA;

    class mySHA1 does Sum::SHA1 does Sum::Marshal::Raw { }
    my mySHA1 $a .= new();
    $a.finalize("123456789".encode('ascii')).say;
        # 1414485752856024225500297739715962456813268251713

    # SHA-224
    class mySHA2 does Sum::SHA2[:columns(224)] does Sum::Marshal::Raw { }
    my mySHA2 $b .= new();
    $b.finalize("123456789".encode('ascii')).say;
        # 16349067602210014067037177823623301242625642097093531536712287864097

    # When dealing with obselete systems that use SHA0
    class mySHA0 does Sum::SHA1[:insecure_sha0_obselete]
        does Sum::Marshal::Raw { }
    my mySHA0 $c .= new();
    $c.finalize("123456789".encode('ascii')).say;
        # 1371362676478658660830737973868471486175721482632


=end pod

# This is a bit of a hack.  We want the test suite to be able to try to
# run the code in the synopsis.  When pod is more functional maybe this
# will become more maintainable.  In the meantime, if you edit anything
# above, take care to adjust the sections here.

$Sum::SHA::Doc::synopsis = $=pod[0].content[3..6]>>.content.Str;

=begin pod

=head1 DESCRIPTION

    Using C<Sum::SHA> defines roles for generating types of C<Sum> that
    calculate the widely used SHA1 and SHA2 cryptographic hash functions.
    It is also possible to calculate legacy SHA0 checksums, which are
    obselete and not cryptographically secure.

    SHA sums can be computationally intense.  They also require a small
    but significant memory profile while not finalized, so care must be
    taken when huge numbers of concurrent instances are used.

    NOTE: This implementation is unaudited and is for experimental
    use only.  When audits will be performed will depend on the maturation
    of individual Perl6 implementations, and should be considered
    on an implementation-by-implementation basis.

=end pod

=begin pod

=head1 ROLES

=head2 role Sum::SHA1 [ :$insecure_sha0_old = False, :$mod8 = False ] does Sum

    The C<Sum::SHA1> parametric role is used to create a type of C<Sum>
    that calculates a SHA1 message digest.

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

role Sum::SHA1 [ :$insecure_sha0_obselete = False, :$mod8 = False ] does Sum {

    has $!o is rw = 0;
    has $!final is rw;
    has @!w is rw;     # "Parsed" message gets bound here.
    has @!s is rw;     # Current hash state.  H in specification.

    submethod BUILD () {
        @!s = (0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0);
        $!final = False;
    }

    method comp () {

        my ($a,$b,$c,$d,$e) = @!s[];

        for ((0x5A827999,{ $b +& $c +| (+^$b) +& $d }).item xx 20,
             (0x6ED9EBA1,{ $b +^ $c +^ $d }).item xx 20,
             (0x8F1BBCDC,{ $b +& $c +| $b +& $d +| $c +& $d }).item xx 20,
             (0xCA62C1D6,{ $b +^ $c +^ $d }).item xx 20).kv
            -> $i,($k,$f) {

            ($b,$c,$d,$e,$a) =
                ($a, rol($b,30), $c, $d,
                 0xffffffff +& (rol($a,5) + $f() + $e + $k + @!w[$i]));

        }

        @!s[] = 0xffffffff X+& (@!s[] >>+<< (0xffffffff X+& ($a,$b,$c,$d,$e)));
    }

    # A moment of silence for the pixies that die every time something
    # like this gets written in an HLL.
    my sub rol ($v, Int $count where { -1 < * < 32 }) {
        my $tmp = ($v +< $count) +& 0xffffffff;
        $tmp +|= (($v +& 0xffffffff) +> (32 - $count));
	$tmp;
    }

    # TODO: when role trusts work for private attributes, these first three
    # candidates can be made generic across the main roles.
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

        # Count how many stray bits we have and build them into a byte
        ( $byte +|= +$_ +< (7 - $bits++) )
            if .defined for ($b7,$b6,$b5,$b4,$b3,$b2,$b1);

        # Update the count of the total number of bits sent.
        $!o += $block.elems * 8 + $bits;
        # See note in .finalize.
        $!o +&= 0x1ffffffffffffffff if ($!o >  0x1ffffffffffffffff);

        # Check if buffer, bits, the added 1 bit, and the length fit in a block
        if $block.elems * 8 + $bits + 1 + 64 < 513 { # Yes

            # Note 1 +< (7 - $bits) just happily also DTRT when !$bits
            self.add(Buf.new($block[],$byte +| 1 +< (7 - $bits),
                     0 xx (55 - $block.elems),
                     (255 X+& ($!o X+> (56,48,40,32,24,16,8,0)))));
            $!o -= 512; # undo what the other multimethod did.
        }
        else { # No

            # So break it into two blocks.
            self.add(Buf.new($block[],$byte +| 1 +< (7 - $bits),
                     0 xx (63 - $block.elems)));
            $!o -= 512;  # undo what the other multimethod did.
            self.add(Buf.new(0 xx 56,
                     (255 X+& ($!o X+> (56,48,40,32,24,16,8,0)))));
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
        my @m = (:256[ $block[ $_ ..^ $_+4 ] ] for 0,4,{$^idx + 4} ...^ 64);

        # Fill the rest of the scratchpad with permutations.
        @m.push(rol(([+^] @m[* <<-<< (3,8,14,16)]),+!$insecure_sha0_obselete))
            for 16..^80;

	@!w := @m;
        self.comp;

        # Update the size in bits.
        $!o += 512;
        # See note in .finalize.
        $!o +&= 0x1ffffffffffffffff if ($!o >  0x1ffffffffffffffff);
    };
    method add (*@addends) { self.do_add(|@addends) }

    method finalize(*@addends) {
        self.push(@addends);

        self.add(Buf.new()) unless $!final;

	# Whether or not allowing $!o to wrap is cryptographically
        # wise, the specification does limit the length of messages
        # by writ.  Above we let the values wrap at a bit above the
        # limit.  This means one can continue to push addends into
        # a sum that is destined to fail, but if you've let them
        # push that many addends, you probably have bigger problems.
	return fail(X::Sum::Spill.new()) if $!o > 0xffffffffffffffff;

        # This does not work yet on 32-bit machines
        # :4294967296[@!s[]];
        [+|] (@!s[] »+<« (32 X* (4,3,2,1,0)));
    }
    method Numeric () { self.finalize };
    method buf8 () {
        Buf.new(255 X+& (@!s[] X+> (24,16,8,0)));
    }
    method Buf () { self.buf8 }
}

=begin pod

=head2 role Sum::SHA2 [ :$columns = 256, :$mod8 = False ] does Sum

    The C<Sum::SHA2> parametric role is used to create a type of C<Sum>
    that calculates a SHA2 message digest.

    The C<$columns> parameter selects the SHA2 hash variant, and may
    be 224, 256, 384, or 512, yielding SHA-224, SHA-256, SHA-384, or
    SHA-512 respectively.

    The resulting C<Sum> expects blocks as addends.  Currently, that
    means a Buf with 64 elements (128 when C<$columns> is 384 or 512).
    Passing a shorter Buf may be done once, before or during finalization.
    Such a short Buf may optionally be followed by up to 7 bits (currently,
    Bool) if the message does not end on a byte boundary.  Attempts to
    provide more blocks after passing a short block will result in an
    C<X::Sum::Final>.

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

role Sum::SHA2 [ :$columns where { * == (224|256|384|512) } = 256,
                 :$mod8 = False ]
     does Sum {

    has $!o is rw = 0;
    has $!final is rw;
    has @!w is rw;     # "Parsed" message gets bound here.
    has @!s is rw;     # Current hash state.  H in specification.

    my $rwidth = ($columns > 256) ?? 64 !! 32;
    my $rmask = (1 +< $rwidth) - 1; # Hopefully will go away with native types
    my $bbytes = ($columns > 256) ?? 128 !! 64;
    my $lbits = ($columns > 256) ?? 128 !! 64;

    my @k =
 (0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
  0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
  0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
  0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
  0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
  0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
  0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
  0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
  0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
  0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
  0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
  0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
  0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
  0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817)
  »+>» (64 - $rwidth);

    submethod BUILD () {
        @!s =
            (given $columns {
                 when 224 { (0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
                             0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4)}
	         when 256 { (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)}
                 when 384 { (0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                             0x9159015a3070dd17, 0x152fecd8f70e5939,
                             0x67332667ffc00b31, 0x8eb44a8768581511,
                             0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4) }
                 when 512 { (0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                             0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                             0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                             0x1f83d9abfb41bd6b, 0x5be0cd19137e2179) }
             });
        $!final = False;
    }

    # A moment of silence for the pixies that die every time something
    # like this gets written in an HLL.
    my sub infix:<ror> ($v, Int $count where { -1 < * < $rwidth }) {
        my $tmp = ($v +& $rmask) +> $count;
        $tmp +|= ($v +< ($rwidth - $count)) +& $rmask;
	$tmp;
    }

    method comp () {

        my ($a,$b,$c,$d,$e,$f,$g,$h) = @!s[];

        if ($bbytes == 64) {
            for ^64 -> $i {
                # We'll mask this below
                my $t1 = [+] $h, @k[$i], @!w[$i],
                             ($g +^ ($e +& ($f +^ $g))),
                             ([+^] ($e Xror (6,11,25)));
                # We'll mask this below
                my $t2 = [+] ([+^] ($a Xror (2,13,22))),
                             ([+^] (($a,$a,$b) >>+&<< ($b,$c,$c)));

                ($a,$b,$c,$d,$e,$f,$g,$h) =
                    $rmask +& ($t1 + $t2), $a, $b, $c,
                    $rmask +& ($d + $t1), $e, $f, $g;
            }
        }
        else {
            for ^80 -> $i {
                # We'll mask this below
                my $t1 = [+] $h, @k[$i], @!w[$i],
                             ($g +^ ($e +& ($f +^ $g))),
                             ([+^] ($e Xror (14,18,41)));

                # We'll mask this below
                my $t2 = [+] ([+^] ($a Xror (28,34,39))),
                             ([+^] (($a,$a,$b) >>+&<< ($b,$c,$c)));

                ($a,$b,$c,$d,$e,$f,$g,$h) =
                    $rmask +& ($t1 + $t2), $a, $b, $c,
                    $rmask +& ($d + $t1), $e, $f, $g;
            }
        }

        # merge the new state
        @!s[] = $rmask X+& (@!s[] >>+<< ($rmask X+& ($a,$b,$c,$d,$e,$f,$g,$h)));

    }

    multi method do_add (*@addends) {
        sink for (@addends) { self.add($_) }
    }
    multi method do_add ($addend) {
        # TODO: Typed failure here?
        die("Marshalling error.  Addends must be Buf with 0..$bbytes bytes.");
    }
    multi method do_add (Buf $block where { -1 < .elems < $bbytes },
                         Bool $b7?, Bool $b6?, Bool $b5?, Bool $b4?,
                         Bool $b3?, Bool $b2?, Bool $b1?) {
        my $bits = 0;
        my $byte = 0;

        # Count how many stray bits we have and build them into a byte
        ( $byte +|= +$_ +< (7 - $bits++) )
            if .defined for ($b7,$b6,$b5,$b4,$b3,$b2,$b1);

        # Update the count of the total number of bits sent.
        $!o += $block.elems * 8 + $bits;
        if ($columns > 256) {
            $!o +&= 0x1ffffffffffffffffffffffffffffffff
                if $!o > 0x1ffffffffffffffffffffffffffffffff;
        }
        else {
            $!o +&= 0x1ffffffffffffffff
                if $!o > 0x1ffffffffffffffff;
        }

        # Check if buffer, bits, the added 1 bit, and the length fit in a block
        if $block.elems * 8 + $bits + 1 + $lbits < $bbytes * 8 + 1 { # Yes

            # Note 1 +< (7 - $bits) just happily also DTRT when !$bits
            self.add(Buf.new($block[],$byte +| 1 +< (7 - $bits),
                     0 xx (($bbytes - $lbits/8 - 1) - $block.elems),
                     (255 X+& ($!o X+> reverse(8 X* (0..^($lbits/8)))))));
            $!o -= $bbytes * 8; # undo what the other multimethod did.
        }
        else { # No

            # So break it into two blocks.
            self.add(Buf.new($block[],$byte +| 1 +< (7 - $bits),
                     0 xx ($bbytes - $block.elems - 1)));
            $!o -= $bbytes * 8;  # undo what the other multimethod did.
            self.add(Buf.new(0 xx ($bbytes - $lbits/8),
                     (255 X+& ($!o X+> reverse(8 X* (0..^($lbits/8)))))));
            $!o -= $bbytes * 8; # undo what the other multimethod did.
        }
        $!final = True;
    }
    multi method do_add (Buf $block where { .elems == $bbytes }) {

        # We now have a complete block to crunch.

#        $block.gist.say;

        # Explode the message block into a scratchpad

        my @m;

        if ($bbytes == 64) {
            # First 16 uint32's are a straight copy of the data.
            # When endianness matches and with native types,
            # this would boil down to a simple memcpy.
            @m = (:256[ $block[ $_ ..^ $_+4 ] ] for 0,{$^idx + 4} ...^ 64);

            # Fill the rest of the scratchpad with permutations.
            @m.push($rmask +& (
                [+] @m[*-16,*-7],
                    ([+^] ((@m[*-15] Xror (7,18)),  @m[*-15] +> 3 )),
                    ([+^] ((@m[*-2]  Xror (17,19)), @m[*-2]  +> 10))
                )) for 16..^64;
        }
        else {
            # First 16 uint64's are a straight copy of the data.
            # When endianness matches and with native types,
            # this would boil down to a simple memcpy.
            @m = (:256[ $block[ $_ ..^ $_+8 ] ] for 0,{$^idx + 8} ...^ 128);

            # Fill the rest of the scratchpad with permutations.
            @m.push($rmask +& (
                [+] @m[*-7,*-16],
                    ([+^] ((@m[*-15] Xror (1,8)),  @m[*-15] +> 7 )),
                    ([+^] ((@m[*-2]  Xror (19,61)),@m[*-2]  +> 6))
                )) for 16..^80;
        }

	@!w := @m;
        self.comp;

        # Update the size in bits.
        $!o += $bbytes * 8;
        if ($columns > 256) {
            $!o +&= 0x1ffffffffffffffffffffffffffffffff
                if $!o > 0x1ffffffffffffffffffffffffffffffff;
        }
        else {
            $!o +&= 0x1ffffffffffffffff
                if $!o > 0x1ffffffffffffffff;
        }
    };
    method add (*@addends) { self.do_add(|@addends) }

    method finalize(*@addends) {
        self.push(@addends);

        self.add(Buf.new()) unless $!final;

	# Whether or not allowing $!o to wrap is cryptographically
        # harmless, the specification does limit the length of
        # messages by writ.  Above we let the values wrap at a bit above
        # the limit.  This means one can continue to push addends into
        # a sum that is destined to fail, but if you've let them push
        # that many addends, you probably have bigger problems.
	return fail(X::Sum::Spill.new())
            if $!o > 0xffffffffffffffffffffffffffffffff or
                $columns < 257 and $!o > 0xffffffffffffffff;

        given $columns {

            # These don't work yet
            # when 224 { :4294967296[@!s[^7]] }
            # when 256 { :4294967296[@!s[]]   }
            # when 384 { :18446744073709551616[@!s[^6]] }
            # when 512 { :18446744073709551616[@!s[]] }
            when 224 { [+|] (@!s[0..6] »+<« (32 X* (6,5,4,3,2,1,0)))   }
            when 256 { [+|] (@!s[]     »+<« (32 X* (7,6,5,4,3,2,1,0))) }
            when 384 { [+|] (@!s[0..5] »+<« (64 X* (5,4,3,2,1,0)))     }
            when 512 { [+|] (@!s[]     »+<« (64 X* (7,6,5,4,3,2,1,0))) }
        }
    }
    method Numeric () { self.finalize };
    method buf8 () {
        Buf.new(255 X+&
                   (given $columns {
                        when 224 { (@!s[0..6] X+> (8 X* (3,2,1,0)))         }
                        when 256 { (@!s[]     X+> (8 X* (3,2,1,0)))         }
                        when 384 { (@!s[0..5] X+> (8 X* (7,6,5,4,3,2,1,0))) }
                        when 512 { (@!s[]     X+> (8 X* (7,6,5,4,3,2,1,0))) }
                    })
        );
    }
    method Buf () { self.buf8 }
}


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
