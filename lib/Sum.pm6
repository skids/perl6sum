

class X::Sum::Push::Usage is Exception {
    method message {
        "Sums do not retain previous addends, so "
        ~ "push does cannot return a useful value."
    }
}

class X::Sum::Final is Exception {
    method message {
        "Attempt to add more addends onto a finalized/finalizable Sum."
    }
}

class X::Sum::Missing is Exception {
    method message {
        "Attempt to finalize a Sum before all addends provided."
    }
}

class X::Sum::Spill is Exception {
    method message {
        "Maximum number of addends exceeded."
    }
}

class X::Sum::Recourse is Exception {
    method message {
        "No acceptable recourse found.  Verify third-party library support."
    }
}

# Take care editing the pod here.  See below, and the t/sum.t test file.

=begin pod

=head1 NAME

    Sum::

=head1 SYNOPSIS

    use Sum;

    # Define a very simple Sum class that just adds normally
    class MySum does Sum does Sum::Partial does Sum::Marshal::StrOrds {
        has $.accum is rw = 0;
        method finalize (*@addends) {
            self.push(@addends);
            $.accum;
        }
        method Numeric () { self.finalize };
        method add (*@addends) {
            $.accum += [+] @addends;
        };
    }
    my MySum $s .= new();

    $s.push(3);
    $s.push(4);
    say $s.finalize;                     # 7
    $s.push(5);
    say $s.finalize;                     # 12

    # It can be used to tap a feed
    my @a <== $s <== (1,2);
    say @a;                              # 1 2
    say $s.finalize;                     # 15

    # Since it does Sum::Partial, one can generate partials as a List
    $s.partials(1,1,2,1).say;            # 16 17 19 20

    # Since it does Sum::Marshal::StrOrds, Str addends are exploded
    # into multiple character ordinals.
    'abc'.ords.say;                      # 97 98 99
    $s.partials(1,'abc',1).say;          # 21 118 216 315 316

=end pod

# This is a bit of a hack.  We want the test suite to be able to try to
# run the code in the synopsis.  When pod is more functional maybe this
# will become more maintainable.  In the meantime, if you edit anything
# above, take care to adjust the sections here.

$Sum::Doc::synopsis = $=pod[0].content[4..8]>>.content.Str;

=begin pod

=head1 DESCRIPTION

    This set of modules defines roles and classes for calculating checksums,
    hash values, and other types of sums.

=head1 ROLES AND METHODS

=head2 role Sum

    The C<Sum> roll defines the core interface required for classes
    implementing various checksums and hashes.  It is generally not
    used directly, as it is pre-mixed into many other base roles in
    the C<Sum::> namespace.

    In addition to choosing a base C<Sum> role, classes should also
    mix in a C<Sum::Marshal> role which defines any special processing
    for slurpy lists of addends.  These are often not pre-mixed into
    derived roles, as the type of marshalling desired varies from
    application to application.

=end pod

role Sum {

=begin pod
=head3 method finalize (*@addends)

    The C<.finalize> method returns the final result of a C<Sum> after enough
    addends have been provided.  If it is invoked before enough addends have
    been provided, it returns an C<X::Sum::Missing> failure.

    Some types of C<Sum> may throw away any interim state on finalization.
    In this case, any further attempt to provide more addends to the C<Sum>
    will return an C<X::Sum::Final> failure.

    Any addends provided in the C<@addends> list will be provided to the
    C<Sum> through its C<.push> method before finalization.  As such,
    this method can be used to produce a final value from addends in a
    single call:

        C<$checksum = MySum.new.finalize(1,3,5,7,9);>

    A C<Sum> will generally provide coercion methods, such as C<.Numeric>,
    which is often simply aliases for C<.finalize()>.  Which coercion methods
    are available may vary across different types of C<Sum>.  In particular,
    sums will provide a C<.buf8> coercion method if their results are always
    expressed in bytes, and a C<.buf1> coercion method if their results
    may contain a number of bits that does not pack evenly into bytes.  For
    convenience the latter may also provide a C<.buf8> method.  The C<.Buf>
    coercion method will eventually return one of the above results as
    natural to the type of C<Sum>, but given that C<buf8> and C<buf1> are
    not implemented in the language core yet, all such methods return a
    C<Buf> at this time.  As such, explicit use of the C<.buf8> and C<.buf1>
    methods is advised in the interim.

=end pod

    method finalize (*@addends) { ... }  # Provided by class or role

=begin pod

=head3 method elems ()

    Some types of C<Sum> keep track of the total number of addends.  If not,
    this method will return an B<unthrown> C<X::Method::NotFound>.

    Otherwise, this method behaves similarly to the C<.elems> method
    of C<List> and C<Array>, and may even be an lvalue attribute for some types
    of C<Sum>.  Note, however, that only some types of C<Sum> support random
    access of addends, and most of those will only support write-once access
    to addends.

    Note also that unlike C<Array>, pushing to a C<Sum> pushes to the
    addend at the C<.pos> index, which is not necessarily the same as
    C<.elems>.

    When C<.elems> is an lvalue method and is explicity assigned to, the
    C<Sum> may not be finalized until addends at all indices have been
    provided, either through assignment, through a default value, or by
    pushing addends to the sum until C<.pos == .elems>.  This also applies
    when the type of C<Sum> has a fixed value for C<.elems>.

    Some types of C<Sum> may only support assigning to C<.elems> before
    the first addend is provided.

=end pod

    # Soften the exception for missing .elems method
    method elems () {
        fail(X::Method::NotFound.new(:method<elems>,:typename(self.^name)))
    }

=begin pod

=head3 method pos ()

    Most types of C<Sum> allow addends to be provided progressively, such
    that large lists of addends acquired from asyncronous or lazy sources
    may be efficiently processed.  Many C<Sums> will keep track of the
    index at which the next provided addend would be placed, but not all
    algorithms require maintaining this state.  For the few that do not,
    this method may return an B<unthrown> C<X::Method::NotFound>.

    Otherwise, this method returns the next index at which a provided
    addend will be placed.  Note that C<.pos> may in some cases be modulo.

    The C<.pos> method may also produce an lvalue when a C<Sum> supports
    random or streaming access, e.g. a rolling hash.  Some types of C<Sum>
    may only support assigning to C<.pos> before any addends have been
    supplied.

=end pod

    # Soften the exception for missing .pos
    method pos () {
        fail(X::Method::NotFound.new(:method<pos>,:typename(self.^name)))
    }

=begin pod

=head3

    method push (*@addends --> Failure)

    Provide the values in C<@addends> to a C<Sum> starting with the addend
    at index C<.pos> and proceeding to subsequent indices.  C<.pos> is
    incremented as appropriate, as is C<.elems> in the case of dynamically
    sized types of C<Sum>.

    This method is also called when the C<Sum> is used as a feed tap.

    The values are "added" to the internal state of the C<Sum>.  A
    finalization step is usualy not performed, but might be, depending on
    the type of C<Sum>.

    The C<@addends> list may be eagerly evaluated, or not, depending on
    the exact type of C<Sum>.  Some types of C<Sum> only allow calling this
    method once, and some types of C<Sum> may place restrictions on the
    number or types of addends provided.

    The return value is always a C<Failure>.  Usually this will be an
    C<X::Sum::Push::Usage> which merely guards against naive use expecting
    C<Array.push> semantics.  An C<X::Sum::Missing> may be returned
    if a required number of addends is not met and the Sum cannot be
    resumed.  An C<X::Sum::Final> may be returned if the Sum is considered
    to have all its addends and may not accept more.

    The C<.push> method is usually provided by mixing in C<Sum::Marshal>
    roles, which define how addends lists are pre-processed.

=head3 method add (*addends)

    The C<.add> method implements the raw arithmetic of the C<Sum>.
    It is usually not called directly, but rather is called as
    a back-end to the C<.push> method. Classes must implement
    or mix in this method.  It is expected to handle returning
    C<X::Sum::Missing> and C<X::Sum::Final> if needed.  Any
    Failure returned will be passed through to the caller of
    wrapping methods such as C<.push> or C<.finalize>.

=end pod

    method add (*@addends) { ... }

    # The specs mention a .clear method when feeds are involved
    # but do not elaborate.
    #
    # Until we know when and how that will be called, we trap it.
    method clear (|parms) {
        die(".clear called and we don't know what it does yet.")
    }
}

=begin pod

=head2 role Sum::Partial

    The C<Sum::Partial> role is used to designate types of C<Sum>
    which may produce partial results at any addend index.

=end pod

role Sum::Partial {

=begin pod

=head3 method partials (*@addends --> List)

    The C<.partials> method acts the same as C<.push>, but returns
    a C<List> of the partial sums that result after finalizing the
    C<Sum> immediately after each element of C<@addends> is provided.
    It may be mixed into most progressively implemented C<Sum> roles.

    Note that the finalization step for some types of C<Sum> may be
    computationally expensive.

    This method may promulgate C<Failure>s that occur during
    marshalling addends or adding them to the C<Sum>, by returning
    them instead of the expected results.

=end pod

    method partials (*@addends --> List) {
        flat self.marshal(|@addends).map: {
            last($^addend) if $addend ~~ Failure;
            given self.add($addend) {
                when Failure { last $_ };
            }
            self.finalize;
        }
    }
}

=begin pod

=head2 role Sum::Marshal::Raw

    The C<Sum::Marshal::Raw> role is used by classes that value efficiency
    over dwimmery.  A class with this role mixed in never processes
    single arguments as though they may contain more than one addend.
    The class will be less convenient to use as a result.  However,
    there may be less overhead involved, and it may result in easier
    code audits.

=end pod

role Sum::Marshal::Raw {

    method push (*@addends --> Failure) {
        # Pass the whole list to the class's add method, unprocessed.
        sink self.add(@addends).grep({$_.WHAT ~~ Failure }).map: { return $_ };
        Failure.new(X::Sum::Push::Usage.new());
    };

    multi method marshal (*@addends) { for @addends { $_ }};

}

=begin pod

=head2 role Sum::Marshal::Cooked

    The C<Sum::Marshal::Cooked> role is used by other C<Sum::Marshal>
    roles which provide dwimmery to addends.  It is usually not
    mixed in directly.  A class using a role that mixes
    C<Sum::Marshal::Cooked> will multi-dispatch each argument provided
    to the C<Sum> separately, such that arguments of different
    types may be processed, and perhaps even broken down into multiple
    addends.

=end pod

role Sum::Marshal::Cooked {

    multi method marshal ( $addend ) { $addend }
    multi method marshal (*@addends) {
        for @addends { self.marshal($_) }
    }

    method push (*@addends --> Failure) {
        sink self.marshal(|@addends).map: {
            return $^addend if $addend ~~ Failure;
            given self.add($addend) {
                when Failure { return $_ };
            }
        };
        Failure.new(X::Sum::Push::Usage.new());
    }

#    method whole () { True; }

}

=begin pod

=head2 role Sum::Marshal::StrOrds does Sum::Marshal::Cooked

    The C<Sum::Marshal::StrOrds> role will explode any provided C<Str>
    arguments into multiple addends by calling C<.ords> on the string.

    Other types of provided arguments will not be processed normally,
    unless additional C<Sum::Marshal> roles are mixed.

    One should exercise care as to the current encoding pragma
    or contents of provided strings when using this role.

=end pod

role Sum::Marshal::StrOrds does Sum::Marshal::Cooked {
    multi method marshal (Str $addend) { $addend.ords }
}

=begin pod

=head2 role Sum::Marshal::BufValues does Sum::Marshal::Cooked

    The C<Sum::Marshal::BufValues> role will explode any provided C<Buf>
    arguments into multiple addends by calling C<.values> on the buffer.

    Other types of provided arguments will not be processed normally,
    unless additional C<Sum::Marshal> roles are mixed.

    One should excercise care as to the current encoding pragma
    or contents of provided strings when using this role.

=end pod

role Sum::Marshal::BufValues does Sum::Marshal::Cooked {
    multi method marshal (Str $addend) { $addend.values }
}

=begin pod

=head2 role Sum::Marshal::Bits [ :$accept = Int, :$coerce = Int,
                                 :$bits = 8, :$reflect = False ]
            does Sum::Marshal::Cooked

    The C<Sum::Marshal::Bits> role will explode any argument of the type
    C<$accept> into bit values (currently we use Bools) after coercing
    the argument into the type C<$coerce>.  The parameter C<$bits>
    determines how many of the least significant bits of the result
    will be used to generate bit values, and hence the number of addends
    generated.  Bits outside this range are ignored silently
    (one could use type checking to get runtime errors by appropriately
    choosing and/or constraining types.)

    If C<:reflect> is provided, the bit values are emitted least
    significant bit first.

    Other types of provided arguments will not be processed normally,
    unless additional C<Sum::Marshal> roles are mixed.

=end pod

role Sum::Marshal::Bits [ ::AT :$accept = (Int), ::CT :$coerce = (Int),
                          :$bits = 8, :$reflect = False ]
     does Sum::Marshal::Cooked {

    multi method marshal (AT $addend) {
        ?<<($reflect ?? ((CT($addend) <<+><< [0 ..^ $bits]) >>+&>> 1)
                     !! ((CT($addend) <<+><< ($bits <<-<< [0^..$bits])) >>+&>> 1));
    }

}

=begin pod

=head2 role Sum::Marshal::Pack [ :$width = 8 ]
            does Sum::Marshal::Cooked

    The C<Sum::Marshal::Pack> role is a base role.  One must also compose
    one or more C<Sum::Marshal::Pack::*> roles to use it.  These roles are
    used in situations where a C<Sum> works on addends of a certain width,
    but fragments of addends may be provided separately.  The fragments
    will be bitwise concatinated until a whole addend of C<$width> bits
    is available, and the whole addend will then be added to the C<Sum>.

    Any leftover bits will be kept to combine with further fragments.

    Classes which use this role should call the C<.whole> method when
    asked to finalize a C<Sum>, and return an unthrown C<X::Sum::Missing>
    when this method does not return a true value.

    Note that the C<pack> function may be used to pre-pack values,
    which can then be supplied to a less complicated type of C<Sum>.
    This will often be a better choice than using this role.  The
    C<Sum::Marshal::Packed> role is meant for use when the amount of
    data involved is too large and eclectic to create C<Buf>s holding
    the addends.

=end pod

role Sum::Marshal::Pack [ :$width = 8 ] {
    has $.bitpos is rw = $width;
    has $.packed is rw = 0;
    has $.width = $width;
    has $.violation is rw = False;
    method whole () { $.bitpos == $width and not $.violation }

    multi method marshal (*@addends) {
        for @addends { self.marshal($_) }
    }

    multi method marshal ($addend) {
	unless self.whole {
            $.violation = True;
            return fail(X::Sum::Missing.new());
        }
        $addend;
    }

    method push (*@addends --> Failure) {
        sink self.marshal(|@addends).map: {
            return $^addend if $addend ~~ Failure;
            given self.add($addend) {
                when Failure { return $_ };
            }
        };
        Failure.new(X::Sum::Push::Usage.new());
    }
}

=begin pod

=head2 role Sum::Marshal::Pack::Bits [ :$accept = Bool, :$coerce = Bool ]

    The C<Sum::Marshal::Pack::Bits> role packs bits into addends of a
    width defined by a C<Sum::Marshal::Pack> role, which must be composed
    along with this role.

    Any addend of the type specified by C<$accept> will be coerced into
    the type specified by C<$coerce>.  The truth value of the result will
    be used to determine whether the corresponding bit will be set or
    whether it will remain clear.

    This role may be combined with other C<Sum::Marshal::Pack::*> roles,
    such that these other addends may be bitwise concatenated along with
    single bit values.  Any type of addend that is not handled by one
    such role may only be added after a whole number of addends has been
    supplied, or the C<Sum> will become invalid and attempts to finalize
    or provide more addends will return an C<X::Sum::Missing>.

=end pod

role Sum::Marshal::Pack::Bits[ ::AT :$accept = (Bool), ::CT :$coerce = (Bool) ]
     does Sum::Marshal::Pack[] {

    multi method marshal (AT $addend) {
        $.bitpos--;
        $.packed +|= 1 +< +$.bitpos if (CT($addend));
        unless $.bitpos {
            my $packed = $.packed;
	    $.packed = 0;
            $.bitpos = $.width;
            return $packed;
        }
        return;
    }
}
