#!/usr/bin/env perl
use warnings;
use strict;
#
# If only dd was a tiny bit more flexible.
# Alternatively, if only ddrescue was a tiny bit less rigid
#

use IO::File;

sub main() {
    my $inname = shift @ARGV || die "need infile";
    my $outname = shift @ARGV || die "need outfile";
    my $offset = shift @ARGV || die "need offset";
    my $count = shift @ARGV || die "need count";

    my $in = IO::File->new($inname, O_RDONLY);
    if (!defined($in)) {
        warn("Could not open $inname\n");
        exit(1);
    }
    my $out = IO::File->new($outname, O_WRONLY|O_CREAT);
    if (!defined($out)) {
        warn("Could not open $outname\n");
        exit(1);
    }

    # possibly convert from hex
    $offset = eval $offset;
    $count = eval $count;

    printf("Reading 0x%x bytes at 0x%x\n", $count, $offset);

    my $errors =0;
    while($count) {
        $in->seek($offset,SEEK_SET);
        my $c = chr(0xff);
        my $r = $in->sysread($c,1);
        if (!$r || $r!=1) {
            $errors++;
        }
        $out->syswrite($c,1);
        $count--;
        $offset++;
    }

    printf("Encountered $errors errors\n");
}
main();

