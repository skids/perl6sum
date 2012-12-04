
=begin pod

=head1 NAME

Sum::MDPad

=head1 SYNOPSIS

    use Sum::MDPad;

    role mySum does Sum::MDPad[:blocksize(1024)] does Sum::Marshal::Raw {...}

=head1 DESCRIPTION

    Support code for common Merkle-Damgård-compliant padding schemes

=end pod

=begin pod

=head1 ROLES

=head2 role Sum::MDPad [ :$blocksize, :$lengthtype, :$overflow, :@firstpad ]
            does Sum {

    The C<Sum::MDPad> parametric role defines an interface and shared
    code which is useful for types of C<Sum> which use prevalent variations
    of Merkle-Damgård-compliant padding.  This is a system for breaking
    to-be-hashed messages up into blocks.  It defines a format used in
    the last blocks, which contain the remainder of the message, a
    pad marker, padding, and a message length field.

    The role parameter C<:blocksize> sets the size of message blocks in
    bits.  The C<:firstpad> parameter specifies a bit pattern appended
    to the message before zero-padding.  Currently this must be an Array
    of Bool values, and defaults to C<[True]>, which causes one set bit
    to be appended before padding the unused portion of the last block
    with clear bits.

    The C<:lengthtype> and C<:overflow> parameters control the format
    and behavior of the length counter and are described with the relevant
    methods below.

=end pod

use Sum;

role Sum::MDPad [ int :$blocksize where { not $_ % 8 } = 512, :$lengthtype where { $_ eqv one("uint64_be","uint64_le") } = "uint64_be", Bool :$overflow = True, :@firstpad = [True] ] does Sum {

    my $bbytes = $blocksize/8;
    my @lenshifts = (
        given $lengthtype {
            when "uint64_le" { (0,8...^64) }
            when "uint64_be" { (56,48...0) }
            # TODO: other widths of counter, as needed
        }
    );

=begin pod

=head2 method pos

    The C<Sum::MDPad> role handles the C<.pos> method, keeping track of how
    many bits of message have been provided to the sum.  The C<:lengthtype>
    role parameter determines how it is stored in the padding.  Until sized
    unsigned types are available, it should be set to the string "uint64_be"
    or the string "uint64_le" to specify storage in big-endian or
    little-endian format, respectively.  These are currently the only two
    supported formats.

    The C<:overflow> role attribute specifies whether the sum should fail
    if a message larger than the C<:lengthtype> can express is provided,
    or simply truncate higher bits off the length counter when storing it
    in the final block.  The default is C<True>, the latter, which is
    relatively benign with large counter sizes.  The option is mainly provided
    for strict specification compliance, and will rarely be relevant in
    common usage scenarios.

=end pod

    has Int $!o is rw = 0;
    method pos () { $!o };

=begin pod

=head2 method elems

    The C<Sum::MDPad> role handles the C<.elems> method, which also
    has units of bits.  Immediately after a sum is created, but before
    supplying addends, this method may be used as an lvalue to set an
    expected (nonzero) size for the message.  The behavior in this case
    is as described in the C<Sum> base interface.

    If not set explicitly, this method simply returns the same value as
    the C<.pos> method.

=end pod

#    The lvalue behavior may be used in the future to allow optional
#    length-bearing message prefixes when the message length is presaged,
#    as there are proposals floating around about doing that.  Using it
#    now for convenience purposes should be forward compatible; prepending
#    such a prefix should be made to require an additional role parameter,
#    rather than having it happen automatically when lvalue access is used.

    has Int $!expect is rw = 0;
    method elems () is rw {
        my $f := self;
        Proxy.new(
            FETCH => { $!expect ?? $!expect !! $!o },
            STORE => -> $self, $v {
                if ($!o) {
                    Failure.new(X::AdHoc.new(:payload("Cannot presage length after providing addends.")))
                }
                else {
                    $!expect = $v
                }
            }
        );
    }

=begin pod

=head2 method pos_block_inc

    The C<!pos_block_inc> method should be called by the C<.add>
    multi-candidate which handles complete blocks, in order to update
    the message bit count.  This will be a private method which only
    composers may use, but is currently public (C<.pos_block_inc>).

    It automatically handles finagling the count on the last blocks,
    so from the composer's side it should simply be called once for
    each full block processed.  It also automatically handles checking
    for extra addends pushed to a finalized sum, and for length
    violations when C<.elems> has been explicity set to a nonzero value.
    As such any failures returned should abort the sum and be returned
    directly.

=end pod

    has Bool $!ignore_block_inc is rw = False;
    has Bool $.final is rw = False;
    method pos_block_inc () {
        fail(X::Sum::Final.new()) if $.final;
        return if $!ignore_block_inc;
        unless ($overflow) {
            # TODO use :lengthtype
            fail(X::Sum::Spill.new()) if $!o > 0xffffffffffffffff - $blocksize
        }
        fail(X::Sum::Spill.new()) if $!expect and $!o + $blocksize > $!expect;
        $!o += $blocksize;
        return;
    }

=begin pod

=head2 multi method add

    The C<Sum::MDPad> role provides multi candidates for the C<.add>
    method which handle erroneous addends, missing addends, and short
    blocks.  The algorithm-specific code which mixes in C<Sum::MDPad>
    need only provide a single additional candidate which processes
    one complete block of message.

    The resulting C<Sum> expects single blocks as addends.  Currently,
    that means a C<Buf> with C<blocksize/8> elements.  Passing a shorter
    C<Buf> with C<0..^blocksize/8> elements may be done once, before or
    during finalization.  Such a short C<Buf> may optionally be followed
    by up to 7 bits (currently, 7 xx Bool) if the message does not end on a
    byte boundary.  Attempts to provide more blocks after passing a short
    block will result in an C<X::Sum::Final>.

    Note that C<.add> does not handle slurpy argument lists, and when
    using C<Sum::Marshal::Raw>, one call to C<.push> should be made per
    block.  Slurpy lists may be C<.push>ed if C<Sum::Marshal::Block> roles
    are mixed instead.

    As an interim workaround, these multi candidates are currently
    named C<.do_add> instead, and so should be the provided candidate.

=end pod

    multi method do_add ($addend) {
        fail(X::Sum::Marshal.new(:addend($addend.WHAT.^name)))
    }
    multi method do_add () { }
    multi method do_add (Buf $block where { -1 < .elems < $bbytes },
                         Bool $b7?, Bool $b6?, Bool $b5?, Bool $b4?,
                         Bool $b3?, Bool $b2?, Bool $b1?) {

        fail(X::Sum::Final.new()) if $.final;
        my @bcat = ();
        @bcat.push($_) if .defined for ($b7,$b6,$b5,$b4,$b3,$b2,$b1);
        my int $bits = @bcat.elems;
        @bcat.push(@firstpad);
        @bcat.push(False) while +@bcat % 8;
        my @bytes = (gather while +@bcat { take :2[@bcat.splice(0,8)] });

        my int $inc = $block.elems * 8 + $bits;
        unless ($overflow) {
            # TODO: use :lengthtype
            fail(X::Sum::Spill.new()) if $!o > 0xffffffffffffffff - $inc
        }
        if ($!expect) {
            fail(X::Sum::Spill.new()) if $!o + $inc > $!expect;
            fail(X::Sum::Missing.new()) if $!expect < $!o + $inc;
        }
        $!o += $inc;

        # We took care of the length increment already.
        $!ignore_block_inc = True;

        my $padbytes = ($bbytes*2 - $block.elems - +@bytes - +@lenshifts);
        $padbytes -= $bbytes if $padbytes >= $bbytes;

        my @vals = ($block[], @bytes, 0 xx $padbytes,
                    (255 X+& ($!o X+> (flat @lenshifts))));
        self.add(Buf.new(@vals[^$bbytes]));
        self.add(Buf.new(@vals[$bbytes .. *-1])) if +@vals > $bbytes;

        $.final = True;
    }
    # Workaround for multis not satisfying prototypes in composed roles
    method add (*@addends) { self.do_add(|@addends) }

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

