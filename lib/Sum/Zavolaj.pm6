module Sum::Zavolaj;

# Most if not all of this file should eventually disappear as Zavolaj
# becomes more capable.

our $up;

# How big a machine sized int is.  Initialize to a Failure.
#our $sizeof_int = fail('Zavolaj sizeof detection failed');
# but fail() seems broken when dealing with multiple compilation units so...
our $sizeof_int = Failure.new(X::AdHoc.new(:payload("Zavolaj sizeof detection failed")));

# What is our endianness.  Initialize to a Failure.
#our $reverse_endian = fail('Zavolaj endian detection failed');
# but fail() seems broken when dealing with multiple compilation units so...
our $reverse_endian = Failure.new(X::AdHoc.new(:payload("Zavolaj endian detection failed")));

# The shifts that result from the endianness
our $shifts = Failure.new(X::AdHoc.new(:payload("Zavolaj shifts not defined")));

$up = try {
    use NativeCall;

    my @test := CArray[int].new();

    # The CArray[int] class is our most usable class for buffers
    # and modular arithmetic.  But it is signed, and of unknown
    # size and endianness.  Figure out the latter two.

    @test[0] = 2147483648;
    if @test[0] == -2147483648 {
        $sizeof_int = 4;
    }
    else {
        @test[0] = 9223372036854775808;
        $sizeof_int = 8 if @test[0] == -9223372036854775808;
    }
    +$sizeof_int; # To throw any Failure

    # Why 'libicuuc'?  The answer is that 'libc' won't work due to
    # path issues on multiarch, and just using 'is native()' seems
    # to cause spurious segv problems.  Since libc is already linked
    # the actual libname does not seem to matter as long as it is findable.
    my sub mc(CArray[int], Str is encoded('utf8'), int)
        returns int is native('libicuuc')
        is symbol('memcpy') { * }
    my $strbuf = $sizeof_int == 4 ?? "0123" !! "01234567";
    my $res = mc(@test, $strbuf, $sizeof_int);
    +$res; # To throw any Failure
    if ($sizeof_int == 4) {
        if (@test[0].fmt('%x') eq "30313233") {
            $reverse_endian = False;
        }
        if (@test[0].fmt('%x') eq "33323130") {
            $reverse_endian = True;
        }
    }
    if ($sizeof_int == 8) {
        if (@test[0].fmt('%x') eq "3031323334353637") {
            $reverse_endian = False;
        }
        if (@test[0].fmt('%x') eq "3736353433323130") {
            $reverse_endian = True;
        }
    }
    +$reverse_endian; # To throw any Failure

    if $sizeof_int == 4 {
        $shifts = (24,16,8,0);
    }
    if $sizeof_int == 8 {
        $shifts = (56,48,40,32,24,16,8,0);
    }
    if $reverse_endian {
        $shifts = reverse($shifts[]);
    }

    # Make a CArray[int] from a Perl6 Buf, with endianness conversion
    multi sub ZavolajBlock (Buf $data, :$bytes = $data.elems) is export {
        my $nInt = ($data.elems + $sizeof_int - 1)
                   div $sizeof_int;
        my $rem = $data.elems % $sizeof_int;
        my $res := CArray[int].new();
        my $padInt = ($bytes + $sizeof_int - 1)
                     div $sizeof_int;
        # No sparse magic, so setting the high index first avoids resize.
        for reverse($nInt - 1 ..^ $padInt) { $res[$^idx] = 0; }
"buf { now }".say;
        for 0..^$nInt -> $idx {
            $res[$idx] = 0;
            # We bitwise OR values in rather than assign, since it is signed.
            $res[$idx] +|= [+|]
                ($data[($idx * $sizeof_int) ..^
                   (min(($idx + 1) * $sizeof_int, $data.elems))]
                Z+< $shifts);
"block { now }".say;
        }
        $res;
    }

    # Make a Perl6 Buf from a CArray[int], with endianness conversion.
    # $len is in bytes.  Use explicit $len if the length is known by you
    # but not the compiler e.g. if you are working on a CArray returned
    # from a native interface.
    sub ZavolajBuf ($data,
                    $len where { $_ > 0 } = $data.elems * $sizeof_int)
        is export {
        my $whole = $len div $sizeof_int;
        my $rem = $len % $sizeof_int;

        Buf.new(
            (for (^$whole) -> $idx {
                my $i;
                if ($sizeof_int == 8) {
                    $i = Int($data[$idx]) +& 0xffffffffffffffff;
                }
                if ($sizeof_int == 4) {
                     $i = Int($data[$idx]) +& 0xffffffff;
                }
                255 X+& ($i X+> $shifts[^$sizeof_int])
             }),
            ($rem ?? (do {
                my $i;
                if ($sizeof_int == 8) {
                    $i = Int($data[$whole]) +& 0xffffffffffffffff;
                }
                if ($sizeof_int == 4) {
                    $i = Int($data[$whole]) +& 0xffffffff;
                }
                255 X+& ($i X+> $shifts[^$rem])
             }) !! ())
        );
    }

    # Make a Perl6 BigInt from a CArray[int], with endianness conversion.
    # $len is in bytes.  Use explicit $len if the length is known by you
    # but not the compiler e.g. if you are working on a CArray returned
    # from a native interface.
    sub ZavolajBigInt ($data,
                       $len where { $_ > 0 } = $data.elems * $sizeof_int)
        is export {
        my $whole = $len div $sizeof_int;
        my $rem = $len % $sizeof_int;

        [+|]((for (^$whole) -> $idx {
                my $i;
                if ($sizeof_int == 8) {
                    $i = Int($data[$idx]) +& 0xffffffffffffffff;
                }
                if ($sizeof_int == 4) {
                     $i = Int($data[$idx]) +& 0xffffffff;
                }
                255 X+& ($i X+> $shifts[^$sizeof_int])
             }),
            ($rem ?? (do {
                my $i;
                if ($sizeof_int == 8) {
                    $i = Int($data[$whole]) +& 0xffffffffffffffff;
                }
                if ($sizeof_int == 4) {
                    $i = Int($data[$whole]) +& 0xffffffff;
                }
                255 X+& ($i X+> $shifts[^$rem])
             }) !! ())
           Z+<
             (reverse(8 X* ^$len)))
    }

    sub ZavolajFree(CArray[int]) is native('libicuuc') is symbol('free')
        is export { * }

True;
} unless defined $up or $up.WHAT ~~ Failure;

# Re-prime any exceptions back into unthrown Failures.
$up = Failure.new($up) if $up.WHAT ~~ Exception;
True;
