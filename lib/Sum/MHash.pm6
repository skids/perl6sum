module Sum::MHash;

our $up = try {

use Sum::Zavolaj;

+$GLOBAL::Sum::Zavolaj::up; # Contains a Failure if Zavolaj sanity checks fail

use NativeCall;

# Hackery alert: many of these ints are actually size_t in the mhash
# API.  That probably won't work too well when sizeof(int) != (sizeof(size_t)).
# TODO: fix these to use size_t when Zavolaj gains support for it.
our sub count() returns int is native('libmhash')
    is symbol('mhash_count') { * }

our $count = count();

# This will segv if it returns NULL, and there ARE holes between 0..$count-1
our sub name(int) returns str is native('libmhash')
    is symbol('mhash_get_hash_name_static') { * }

# Fortunately, this tells us where the holes are by returning 0.
our sub block_size(int) returns int is native('libmhash')
    is symbol('mhash_get_block_size') { * }

our sub pblock_size(int) returns int is native('libmhash')
    is symbol('mhash_get_hash_pblock') { * }

class Algo {
      has Int $.id;
      has Str $.name;
      has Int $.block_size;
      has Int $.pblock_size;
}

our %Algos;

our $mhash_found_algos = (
    for (0..$count) {
        given block_size($^b) {
            when 0 { }
            default { %Algos{$b} = Algo.new(:id($b),
                                            :name(name($b)),
                                            :block_size(block_size($b)),
                                            :pblock_size(pblock_size($b))); }
        }
    }
);

class Instance is repr('CPointer') {
      my sub init(int) returns Instance
          is native('libmhash')
          is symbol('mhash_init') { * };
      my sub deinit(Instance, CArray[int])
          is native('libmhash')
          is symbol('mhash_deinit') { * };
      my sub mhash(Instance, CArray[int] $data, int $len) returns int
          is native('libmhash')
          is symbol('mhash') { * };
      my sub end(Instance) returns CArray[int]
          is native('libmhash')
          is symbol('mhash_end') { * };
      my sub cp(Instance) returns Instance
          is native('libmhash')
          is symbol('mhash_cp') { * };

      multi method new (Int $id) {
          fail ("No such hash ID in this installation of libmhash")
              unless %Algos{$id};
          init(+$id);
      }
      multi method new (Str $name) {
          my $id = %Algos.keys.grep({ %Algos{$_}.name eq $name });
          fail ("No unique algorithm named $name in libmhash")
              if $id.elems != 1;
          init(+$id[0]);
      }

      method add($data, $len = $data.elems * $GLOBAL::Sum::Zavolaj::sizeof_int)
      {
          mhash(self, $data, +$len);
      }

      method finalize() {
          end(self); # This frees the descriptor and allocates the digest
      }

      # not DESTROY: the user of this class must call this manually if end
      # has not been called.
      method destroy() {
          deinit(self,CArray[int]); # CArray[int] should result in C NULL
      }

      method clone() {
          cp(self);
      }
}

# Calculate a known MD5 to test functionality.
my $md5 := Instance.new("MD5");
#+$md5; # Sink to test for Failure

my $message := ZavolajBlock(Buf.new(0x30..0x37));
$md5.add($message);
my $result := $md5.finalize();
my $digest := ZavolajBuf($result, 16);
ZavolajFree($result);
fail("mhash functional sanity test failed") unless
    $digest eqv Buf.new(0x2e,0x9e,0xc3,0x17,0xe1,0x97,0x81,0x93,
                        0x58,0xfb,0xc4,0x3a,0xfc,0xa7,0xd8,0x37);

# It seems mhash has some endian problems with 4-byte digests.  Check for that.
# (There are no other 2..8-byte digest sizes but problems could be there, too.)
my $a32 := Instance.new("ADLER32");
$a32.add($message);
$result := $a32.finalize();
$digest := ZavolajBuf($result, 4);
ZavolajFree($result);

my $swab_4byte_digests = so $digest eqv Buf.new(0x9d,0x01,0x1c,0x07);

class Sum {

    has $.algo handles<id name block_size pblock_size>;
    has Instance $.inst;
    has $!res;

    my sub Buf2BigInt (Buf $b) {
        [+|] $b[reverse(0 ..^ $b.elems)] Z+< (8 X* 0 ..^ $b.elems);
    }

    multi method new (Int $id) {
        my $r = self.bless(*,:id($id));
        return $r unless $r.defined;
        return Nil unless $r.inst.defined;
        $r
    }

    multi method new (Str $name) {
        my $id = %Algos.keys.grep({ %Algos{$_}.name eq $name });
        fail ("No unique algorithm named $name in libmhash")
            if $id.elems != 1;
        my $r = self.bless(*,
                           :algo(%Algos{+$id[0]}),
                           :inst(Instance.new(+$id[0]))
                           );
        return $r unless $r.defined;
        return self.WHAT unless $r.inst.defined;
        $r
    }

    method clone() {
        my $r = self.bless(*,
                           :res($!res),
                           :algo($!algo),
                           :inst($!inst.clone())
                           );
        return $r unless $r.defined;
        return self.WHAT unless $r.inst.defined;
        $r
    }

    submethod BUILD(:$!algo, :$!inst, :$!res) { }

    submethod DESTROY() {
        unless $!res.defined {
	    # We are discarding before finalization, so we need to free
            # the memory at $!inst.
            $!inst.destroy();
            return;
        }
    }

    multi method add (*@addends) {
        return fail(X::Sum::Final.new()) unless defined $!inst;
	return unless @addends.elems;
        my $block = ZavolajBlock(Buf.new(|@addends));
        self.inst.add($block, +@addends);
    }

    method finalize(*@addends) {
        self.push(@addends) if @addends.elems;
        return Buf2BigInt($!res) if $!res.defined;
        return $!res if $!res.WHAT ~~ Failure;

        Buf2BigInt(self.Buf);
    }

    method Numeric () { self.finalize };

    method Buf () {
        return $!res if $!res.defined or $!res.WHAT ~~ Failure;
        my $r := self.inst.finalize();
        if $r.defined {
            $!res := ZavolajBuf($r, self.algo.block_size);
            ZavolajFree($r); # Free this now
            if (self.algo.block_size == 4 and $swab_4byte_digests) {
                $!res := Buf.new(reverse $!res[]);
            }
        } else {
            $!res := fail("Finalization failed");
        }
        $!inst := Instance:U; # This has been freed by libmhash
        $!res
    }

    # This is essentially Sum::Marshal::Raw, but we seem to not be
    # able to mix it.  Note that this class is always wrapped in a proxy,
    # into which the user may mix their own Sum::Marshal roles.
    method push (*@addends --> Failure) {
        # Pass the whole list to the class's add method, unprocessed.
        sink self.add(@addends).grep({$_.WHAT ~~ Failure }).map: { return $_ };
        Failure.new(X::Sum::Push::Usage.new());
    };

    multi method marshal (*@addends) { for @addends { $_ } };
}

True;
} unless defined $up or $up.WHAT ~~ Failure;

# Re-prime any exceptions back into unthrown Failures.
$up = Failure.new($up) if $up.WHAT ~~ Exception;
True;

