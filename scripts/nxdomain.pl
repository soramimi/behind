#!/usr/bin/env perl
use strict;
use warnings;

# 使い方:
#   perl gen_rpz.pl domains.txt

while (my $line = <>) {
    chomp $line;
    $line =~ s/^\s+//;
    $line =~ s/\s+$//;
    next if $line eq '';
    next if $line =~ /^#/;
    next if $line =~ /^;/;

    my $domain = $line;

    print "nxdomain = $domain\n";
}

