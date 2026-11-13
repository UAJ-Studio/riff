#!/usr/bin/perl -0pi
# 6.10 changed __assign_str(dst, src) to __assign_str(dst) (src taken from
# __string(dst, src)). The stock WSL 6.6 kernel still needs the 2-arg form:
# re-insert src from the most recent __string(dst, src) in the same file.
our %m;
BEGIN { %m = (); }
my $bal = qr/(\((?:[^()]++|(?-1))*\))/;
s{(__string\(\s*(\w+)\s*,\s*((?:[^(),]++|$bal)+)\s*\))|(__assign_str\(\s*(\w+)\s*\))}{
    if (defined $1) { $m{$2} = $3; $1 }
    elsif (exists $m{$6}) { "__assign_str($6, $m{$6})" }
    else { warn "fix-trace: no __string for $6 in $ARGV\n"; $5 }
}ge;
