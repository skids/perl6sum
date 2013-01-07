=begin pod

=head1 NAME

Sum::SipHash

=head1 SYNOPSIS

    use Sum::SipHash;

    class SipHash_2_4 does SipHash does Sum::Marshal::Raw { }
    my SipHash_2_4 $a .= new(:key(0x000102030405060708090a0b0c0d0e0f));
    $a.finalize(0..0xe).fmt('%x').say; # a129ca6149be45e5

=end pod

# This is a bit of a hack.  We want the test suite to be able to try to
# run the code in the synopsis.  When pod is more functional maybe this
# will become more maintainable.  In the meantime, if you edit anything
# above, take care to adjust the sections here.

# Disabling this for now until .pir files properly serialize pod
#$Sum::SipHash::Doc::synopsis = $=pod[0].content[4].content.Str;

=begin pod

=head1 DESCRIPTION

    C<Sum::SipHash> defines a parameterized role for generating types
    of C<Sum> that calculate variants of SipHash.  SipHash is a hash
    code which was developed to be efficient enough for general use,
    including use in live data structures, while remaining resistant
    to denial-of-service attacks that rely on finding hash collisions.
    It is not intended for use in strong cryptography.

=head1 ROLES

=head2 role Sum::SipHash [ :$c = 2, :$d = 4, :$defkey = 0 ] does Sum

    The C<Sum::SipHash> parametric role is used to create a type of C<Sum>
    that calculates a variant of SipHash.

    The C<:defkey> parameter provides an integer key value that will be
    applied to all instances which do not specify their own.  See the
    documentation below for C<.new>'s C<:key> parameter.

    The C<:c> parameter specifies the number of SipRounds performed
    during a "compression" (which happens about once per eight bytes of
    data) and the C<:d> parameter specifies the number of rounds used
    when the C<Sum> is C<.finalize>d.  Together they determine the
    strength of the hash: increasing either parameter yields more
    resistance to collision analysis, but will increase the computational
    cost.  By default, the role calculates SipHash-2-4, which is the
    standard's notation for C<:c(2), :d(4)>.  This is the suggested
    variant for general use.  When extra collision resistance is desired,
    the specification suggests using the "conservative" SipHash-4-8.

    The number of addends may be determined on the fly, and in this
    implementation, finalization is performed without altering internal
    state, so the C<Sum::Partial> role may be mixed.

=end pod

use Sum;

role SipHash [ Int :$c = 2, Int :$d = 4, Int :$defkey = 0 ] does Sum::Partial {

    my Buf $keyfrob = "somepseudorandomlygeneratedbytes".encode("ascii");

    has Int $!k0 is rw   = 0;
    has Int $!k1 is rw   = 0;
    has Int $!v0 is rw   = 0;
    has Int $!v1 is rw   = 0;
    has Int $!v2 is rw   = 0;
    has Int $!v3 is rw   = 0;
    has Int $!b is rw    = 0;
    has Int $!left is rw = 0;

=begin pod

=head2 METHODS

=head3 method new(:$key?)

    There is an internal well-known seed built into the SipHash
    specification.  The least significant 128 bits of an integer key
    may be used to alter this seed.

    The constructor allows an individual instance to use its own seed
    by providing a C<:key> argument.  An individual class may supply
    a default key which will be used if the C<:key> argument is omitted
    from the constructor.

    The class-provided key will not be used at all if C<:key> is provided.
    As such, two instances of different C<Sum::SipHash> classes which
    differ only in the class's C<:defkey> will always generate the same
    results if the instances use the same C<:key> argument.

    As such, explicitly specifying C<:key(0)> always uses the naked
    well-known seed, which is more likely to have been analyzed by
    potential adversaries.  Classes which do not provide a default key
    (or which explicity set C<:defkey(0)>) will create instances that
    use the naked seed if they do not specify C<:key>.

    The process of modifying the seed is resilient against accidentally
    zeroing the seed, so any other value can be safely chosen.

=end pod

    # There is not actually a custom constructor, it is just docced as-if

    submethod BUILD (:$key is copy = $defkey) {
        $key = Int($key);

        # The K constants must be a little-endian encoding of the key.
        $!k1 = :256[ 255 X+& ($key X+> 0,8...^64)    ];
        $!k0 = :256[ 255 X+& ($key X+> 64,72...^128) ];

        # The internal key also uses a little-endian representation.
        $!v0 = $!k0 +^ :256[$keyfrob[^8]];
        $!v1 = $!k1 +^ :256[$keyfrob[8..^16]];
        $!v2 = $!k0 +^ :256[$keyfrob[16..^24]];
        $!v3 = $!k1 +^ :256[$keyfrob[24..^32]];
    }

#    has Int $.size = 64; should work, but doesn't during multirole mixin
    method size ( --> int ) { 64 };

    my sub rol (Int $v is rw, int $count) {
        my $tmp = (($v +& (0xffffffffffffffff +> $count)) +< $count);
        $tmp +|= ($v +> (64 - $count));
	$v = $tmp;
    }

    my sub SipRound (Int $v0 is rw, Int $v1 is rw,
                     Int $v2 is rw, Int $v3 is rw) {
        $v0 += $v1; $v0 +&= 0xffffffffffffffff;
        $v2 += $v3; $v2 +&= 0xffffffffffffffff;
        rol($v1, 13);  rol($v3, 16);
        $v1 +^= $v0; $v3 +^= $v2;
        rol($v0, 32);

        $v2 += $v1; $v2 +&= 0xffffffffffffffff;
        $v0 += $v3; $v0 +&= 0xffffffffffffffff;
        rol($v1, 17);  rol($v3, 21);
        $v1 +^= $v2; $v3 +^= $v0;
        rol($v2, 32);
    }

    my sub compression (Int $w, Int $v0 is rw, Int $v1 is rw,
                                Int $v2 is rw, Int $v3 is rw) {
        $v3 +^= $w;
        SipRound($v0, $v1, $v2, $v3) for ^$c;
        $v0 +^= $w;
    }

=begin pod

=head3 multi method add(uint8(Any) *@addends)

    The C<.add> method expects a list of single byte addends.  It is
    generally not used directly by applications.

    A C<Sum::Marshal::*> role must be mixed into the class, and some
    such roles may also be used to properly process wider or narrower
    addends as appropriate to the application through the C<.push>
    method.

    NOTE: Currently no sized native type support is available, so rather than
    being coerced to C<uint8>, addends are coerced to C<Int> and 8 lsb are
    used.  This behavior should be stable, barring any surprises in the
    semantics of C<uint8>'s coercion operation.  Any future cut-through
    optimizations for wider low-level types will be done behind the scenes
    and presented as C<Sum::Marshal> mixins.

=end pod

    method add (*@addends) {
        for (@addends) -> $a is copy {
            $a = Int($a) +& 255;

            my $pos = $!b;
            $!b++;

            $!left +|= ($a +< (8 * ($pos % 8)));
            unless ($!b % 8) {
                compression($!left, $!v0, $!v1, $!v2, $!v3);
                $!left = 0;
	    }
        }
    };

    method pos () { $!b };

    method elems () { $!b };

    method finalize(*@addends) {
        self.push(@addends);

        my ($v0, $v1, $v2, $v3) = $!v0, $!v1, $!v2, $!v3;

        compression($!left +| (($!b +& 255) +< 56),$v0,$v1,$v2,$v3);

        $v2 +^= 0xff;

        SipRound($v0, $v1, $v2, $v3) for ^$d;

        [+^] $v0, $v1, $v2, $v3;
    }
    method Numeric () { self.finalize };
    method buf8 () {
        Buf.new(255 X+& (self.finalize X+> (56,48,40,32,24,16,8,0)));
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

    "SipHash: a fast short-input PRF" Aumasson/Bernstein NAGRA document
    ID b9a943a805fbfc6fde808af9fc0ecdfa

=head1 SEE ALSO

    C<Sum::(pm3)>

=end pod
