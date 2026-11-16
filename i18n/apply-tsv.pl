#!/usr/bin/perl
# Fill unfinished translations in a Qt .ts file from a TSV of
# "source<TAB>translation" (plain text, not XML-escaped).
# usage: perl apply-tsv.pl file.ts table.tsv
use strict; use warnings; use utf8;
use open qw(:std :encoding(UTF-8));
my ($ts, $tsv) = @ARGV;
sub unesc { my $s = shift; $s =~ s/&lt;/</g; $s =~ s/&gt;/>/g; $s =~ s/&quot;/"/g;
            $s =~ s/&apos;/'/g; $s =~ s/&amp;/&/g; return $s; }
sub esc { my $s = shift; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; return $s; }
my %tr;
open(my $t, '<', $tsv) or die "$tsv: $!";
while (<$t>) { chomp; s/\r$//; next unless /\t/; my ($k, $v) = split /\t/, $_, 2; s/\\n/\n/g for $k, $v; $tr{$k} = $v; }
close $t;
open(my $f, '<', $ts) or die "$ts: $!"; local $/; my $x = <$f>; close $f;
my ($done, $left) = (0, 0);
$x =~ s{(<message[^>]*>(?:(?!</message>).)*?<source>((?:(?!</message>).)*?)</source>(?:(?!</message>).)*?)<translation type="unfinished">((?:(?!</message>).)*?)</translation>}{
    my ($pre, $src) = ($1, unesc($2));
    if (exists $tr{$src}) {
        $done++;
        my $t = esc($tr{$src});
        # numerus messages: one form in Japanese
        $t = "<numerusform>$t</numerusform>" if $pre =~ /numerus="yes"/;
        $pre . '<translation>' . $t . '</translation>'
    }
    else { $left++; $& }
}gse;
open($f, '>', $ts) or die; print $f $x; close $f;
print "filled $done, still unfinished $left\n";
