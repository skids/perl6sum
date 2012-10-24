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

$Sum::SipHash::Doc::synopsis = $=pod[0].content[4].content.Str;

=begin pod

=head1 DESCRIPTION

    Using C<Sum::SipHash> defines a parameterized role for generating
    types of C<Sum> that calculate variants of a hash code which was
    developed to be efficient enough for general use, while remaining
    resistant to denial-of-service attacks that rely on finding hash
    collisions.  It is not intended for use in strong cryptography.

=head1 ROLES

=head2 role Sum::SipHash [ :$c = 2, :$d = 4, :$defkey = 0 ] does Sum

    The C<Sum::SipHash> parametric role is used to create a type of C<Sum>
    that calculates a variant of SipHash.  By default, it calculates
    SipHash-2-4, which is the suggested variant for general use.

    The resulting C<Sum> expects values that will numerically coerce to
    single byte addends.  A C<Sum::Marshal::*> role must be mixed into
    the class, and some such roles may also be used to properly process
    wider or narrower addends as appropriate to the application.

    The C<$c> parameter specifies the number of SipRounds performed
    during a "compression" (which happens about once per eight bytes of
    data) and the C<$d> parameter specifies the number of rounds used
    when the C<Sum> is C<.finalize>d.  Together they determine the
    strength of the hash: increasing either parameter yields more
    resistance to collision analysis, but will increase the computational
    cost.

    The number of addends may be determined on the fly, and in this
    implementation, finalization is performed without altering internal
    state, so the C<Sum::Partial> role may be mixed in when progressive
    hashing of a growing datum is desired.

    The C<$defkey> parameter defines a seed value that will be applied
    to all instances which do not specify their own.  There is an internal
    well-known seed built into the SipHash.  Up to 128 bits of an integer
    value will be used to alter this seed if provided.

=head2 METHODS

=head3 method new(:$key?)

    The constructor allows an individual instance to use its own seed,
    as described above.  The class may supply a default seed if the
    C<$key> argument is omitted from the constructor.  The class-provided
    seed will not be used at all if the seed is provided through this
    parameter, and as such, two instances of classes with compatible
    parameters will always generate the same results if they provide the
    same seed, even if their parent classes specified different seeds.

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

use Sum;

role SipHash [ :$c = 2, :$d = 4, Int :$defkey = 0 ] does Sum {

    my Buf $keyfrob = "somepseudorandomlygeneratedbytes".encode("ascii");

    has $!k0 is rw;
    has $!k1 is rw;
    has $!v0 is rw;
    has $!v1 is rw;
    has $!v2 is rw;
    has $!v3 is rw;
    has $!b is rw = 0;
    has $!left is rw = 0;

    method new (:$key is copy = 0) {
        $key ||= $defkey;
	my $res = self.bless(*,:$key);
    }
    submethod BUILD (:$key is copy) {

	$!k0 = $!k1 = $!v0 = $!v1 = $!v2 = $!v3 = 0;

        # The K constants must be a little-endian encoding of the key.
	for (0..7) {
           $!k1 +<= 8;
	   $!k1 +|= $key +& 255;
	   $key +>= 8;
	}
	for (0..7) {
           $!k0 +<= 8;
	   $!k0 +|= $key +& 255;
	   $key +>= 8;
	}
        # The internal key is also a little-endian representation.
        $!v0 = [+|] $keyfrob[0..^8] »+<« [56,48,40,32,24,16,8,0];
        $!v1 = [+|] $keyfrob[8..^16] »+<« [56,48,40,32,24,16,8,0];
        $!v2 = [+|] $keyfrob[16..^24] »+<« [56,48,40,32,24,16,8,0];
        $!v3 = [+|] $keyfrob[24..^32] »+<« [56,48,40,32,24,16,8,0];
	$!v0 +^= $!k0;
	$!v1 +^= $!k1;
	$!v2 +^= $!k0;
	$!v3 +^= $!k1;
    }

    my sub rol ($v is rw, $count) {
        my $tmp = (($v +& (0xffffffffffffffff +> $count)) +< $count);
        $tmp +|= ($v +> (64 - $count));
	$v = $tmp;
    }

    my sub SipRound ($w, $v0 is rw, $v1 is rw, $v2 is rw, $v3 is rw) {
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

    my sub compression ($w, $v0 is rw, $v1 is rw, $v2 is rw, $v3 is rw) {
        $v3 +^= $w;
        SipRound($w, $v0, $v1, $v2, $v3) for ^$c;
        $v0 +^= $w;
    }

    method add (*@addends) {
        for (@addends) -> $a {
            my $pos = $!b;
            $!b++;

            $!left +|= (($a +& 255) +< (8 * ($pos % 8)));
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

        my $left = $!left;
        my $v0 = $!v0;
        my $v1 = $!v1;
        my $v2 = $!v2;
        my $v3 = $!v3;

        $left +|= (($!b +& 255) +< 56);

        compression($left,$v0,$v1,$v2,$v3);

        $v2 +^= 0xff;

        SipRound($left, $v0, $v1, $v2, $v3) for ^$d;

        [+^] ($v0, $v1, $v2, $v3);
    }
    method Numeric () { self.finalize };
    method buf8 () {
        Buf.new(255 X+& (self.finalize X+> (56,48,40,32,24,16,8,0)));
    }
    method Buf () { self.buf8 }
}
