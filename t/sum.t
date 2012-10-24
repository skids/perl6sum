use v6;
BEGIN { @*INC.unshift: './lib'; }

use Test;

plan 64;

use Sum;
ok(1,'We use Sum and we are still alive');
lives_ok { X::Sum::Final.new() }, 'X::Sum::Final is available';
lives_ok { X::Sum::Missing.new() }, 'X::Sum::Missing is available';
lives_ok { X::Sum::Spill.new() }, 'X::Sum::Spill is available';
lives_ok { X::Sum::Push::Usage.new() }, 'X::Sum::Push::Usage is available';
lives_ok { X::Sum::Recourse.new() }, 'X::Sum::Recourse is available';
lives_ok { eval 'class foo1 does Sum { method finalize { }; method add { }; method push { }; }' }, 'Sum composes when interface is implemented';
dies_ok { eval 'class fooX does Sum { }' }, 'Sum requires interface to compose';
lives_ok { eval 'class foo2 does Sum does Sum::Marshal::Raw { method finalize { }; method add { }; }' }, 'Sum::Marshal::Raw composes and provides push';
lives_ok { eval 'class foo3 does Sum does Sum::Marshal::Cooked { method finalize { }; method add { }; }' }, 'Sum::Marshal::Cooked composes and provides push';
lives_ok { eval 'class foo4 does Sum does Sum::Marshal::StrOrds { method finalize { }; method add { }; }' }, 'Sum::Marshal::StrOrds composes and provides push';
lives_ok { eval 'class foo5 does Sum does Sum::Marshal::BufValues { method finalize { }; method add { }; }' }, 'Sum::Marshal::BufValues composes and provides push';
lives_ok { eval 'class foo6 does Sum does Sum::Marshal::Pack[] { method finalize { }; method add { }; }' }, 'Sum::Marshal::Pack composes and provides push';
lives_ok { eval 'class foo7 does Sum::Marshal::Pack::Bits[ :accept(Int) ] { method finalize { }; method add { }; }' }, 'Sum::Marshal::Pack::Bits composes';

todo "Waiting on resolution for diamond composition RT.",2;
lives_ok { eval 'class fooC1 does Sum does Sum does Sum::Marshal::StrOrds does Sum::Marshal::BufValues { method finalize { }; method add { }; }' }, 'Two Sum::Marshal subroles can compose with same crony';
lives_ok { eval 'class fooC2 does Sum does Sum does Sum::Marshal::Pack::Bits[ ] does Sum::Marshal::Pack::Bits[ :accept(Int) ] { method finalize { }; method add { }; }' }, 'Two Sum::Marshal::Pack subroles can compose with same crony';

lives_ok {
class Foo does Sum does Sum::Marshal::Cooked {
        has $.accum is rw = 0;
        method finalize (*@addends) {
            self.push(@addends);
            $.accum;
        }
        method Numeric () { self.finalize };
        method add (*@addends) {
            $.accum += [+] @addends;
        };
} }, "can compose a basic Sum class";

my Foo $f;
lives_ok { $f .= new(); }, "can instantiate a basic Sum class (Cooked)";

ok $f.elems.WHAT ~~ Failure, "missing elems method is a soft failure";
ok $f.pos.WHAT ~~ Failure, "missing pos method is a soft failure";
ok $f.push(1).WHAT ~~ Failure, "push method returns a failure (Cooked)";
$f.push(2,3);
is $f.accum, 6, "pushed a list of addends (Cooked)";
my @a;
@a <== $f <== (4,5);
is @a.join(""), "45", "is seen as feed tap (passes through values)";
is $f.accum, 15, "tapped a list of addends from a feed(Cooked)";
is $f.finalize, 15, "finalize with no arguments works (Cooked)";
is $f.finalize(5), 20, "finalize with one argument works (Cooked)";
is $f.finalize(5,6), 31, "finalize with multiple arguments works (Cooked)";
$f.push();
is $f.accum, 31, "push with no arguments works(Cooked)";

lives_ok {
class Foo2 does Sum does Sum::Marshal::Raw {
        has $.accum is rw = 0;
        method finalize (*@addends) {
            self.push(@addends);
            $.accum;
        }
        method Numeric () { self.finalize };
        method add (*@addends) {
            $.accum += [+] @addends;
        };
} }, "can compose a basic Sum class (Raw)";

my Foo2 $g;
lives_ok { $g .= new(); }, "can instantiate a basic Sum class";

ok $g.push(1).WHAT ~~ Failure, "push method returns a failure (Raw)";
$g.push(2,3);
is $g.accum, 6, "pushed a list of addends (Raw)";
my @b;
@b <== $g <== (4,5);
is @b.join(""), "45", "is seen as feed tap (passes through values) (Raw)";
is $g.accum, 15, "tapped a list of addends from a feed (Raw)";
is $g.finalize, 15, "finalize with no arguments works (Raw)";
is $g.finalize(5), 20, "finalize with one argument works (Raw)";
is $g.finalize(5,6), 31, "finalize with multiple arguments works (Raw)";
$g.push();
is $g.accum, 31, "push with no arguments works(Raw)";

lives_ok {
class Foo3 does Sum does Sum::Partial does Sum::Marshal::Cooked {
        has $.accum is rw = 0;
        method finalize (*@addends) {
            self.push(@addends);
            $.accum;
        }
        method Numeric () { self.finalize };
        method add (*@addends) {
            $.accum += [+] @addends;
        };
} }, "can compose a basic Sum class (Raw)";

my Foo3 $h;
lives_ok { $h .= new(); }, "can instantiate a partial Sum class";

ok $h.push(1).WHAT ~~ Failure, "push method returns a failure (Partial)";
$h.push(2,3);
is $h.accum, 6, "pushed a list of addends (Partial)";
my @c;
@c <== $h <== (4,5);
is @c.join(""), "45", "is seen as feed tap (passes through values) (Partial)";
is $h.accum, 15, "tapped a list of addends from a feed (Partial)";
is $h.finalize, 15, "finalize with no arguments works (Partial)";
is $h.finalize(5), 20, "finalize with one argument works (Partial)";
is $h.finalize(5,6), 31, "finalize with multiple arguments works (Partial)";
$h.push();
is $h.accum, 31, "push with no arguments works(Partial)";
is $h.partials(3,2,1).join(''), "343637", "partials method works";
is $h.partials(), Nil, "partials with no arguments gives empty list";
my @d;
#? rakudo skip 'feed through a slurpy arity function'
#@d <== $h.partials <== (2,3);
#is @d.join(""), "3942", "partials inserts values in a feed"

lives_ok {
class Foo4 does Sum does Sum::Partial does Sum::Marshal::StrOrds {
        has $.accum is rw = 0;
        method finalize (*@addends) {
            self.push(@addends);
            $.accum;
        }
        method Numeric () { self.finalize };
        method add (*@addends) {
            $.accum += [+] @addends;
        };
} }, "can compose a basic Sum class (StrOrds)";

my Foo4 $o1;
lives_ok { $o1 .= new(); }, "can instantiate a basic Cooked subclass";
$o1.push("ABC");
is $o1.finalize, 65 + 66 + 67, "Cooked subclass explodes an addend";
$o1 .= new();
$o1.push(1,"ABC");
is $o1.finalize, 65 + 66 + 67 + 1, "mix addend before exploding addend";
$o1 .= new();
$o1.push(1,"ABC",2);
is $o1.finalize, 65 + 66 + 67 + 3, "mix addends around exploding addend";

lives_ok {
class Foo5 does Sum does Sum::Marshal::Pack::Bits[] {
        has $.accum is rw = 0;
        method finalize (*@addends) {
            self.push(@addends);
            return fail(X::Sum::Missing.new()) unless self.whole;
            $.accum;
        }
        method Numeric () { self.finalize };
        method add (*@addends) {
            $.accum += [+] @addends;
        };
} }, "Can instantiate basic Pack subclass";

my Foo5 $o2;
lives_ok { $o2 .= new(); }, "can instantiate a basic Packed subclass";
$o2.push(True,False,False,False,True,False,True,False);
is $o2.finalize, 138, "can combine 8 bits";
$o2 .= new();
$o2.push(True,False,False,False,True,False,True,False,8);
is $o2.finalize, 146, "can combine 8 bits then add an Int";
$o2 .= new();
$o2.push(8,True,False,False,False,True,False,True,False);
is $o2.finalize, 146, "can add 8 combined bits after an Int";
$o2 .= new();
$o2.push(True,False,False,False,True,False,True);
ok $o2.finalize.WHAT ~~ Failure, "Trying to finalize 7 bits fails";
$o2 .= new();
$o2.push(True,False,False,False,True,False,True,8);
ok $o2.finalize.WHAT ~~ Failure, "Normal addend after 7 bits fails";
$o2 .= new();
$o2.push(True,False,False,False,True,False,True,8,False);
ok $o2.finalize.WHAT ~~ Failure, "Normal addend amid 8 bits fails";


# Now grab the code in the synopsis from the POD and make sure it runs.
# This is currently complete hackery but might improve when pod support does.
# And also an outputs_ok Test.pm function that redirects $*OUT might be nice.
class sayer {
    has $.accum is rw = "";
    method print (*@s) { $.accum ~= [~] @s }
}
my sayer $s .= new();
{ temp $*OUT = $s; eval $Sum::Doc::synopsis; }
is $s.accum, $Sum::Doc::synopsis.comb(/<.after \#\s> (<.ws> \d+)+/).join("\n") ~ "\n", 'Code in manpage synopsis actually works';
