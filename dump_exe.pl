#!/usr/bin/env perl
use warnings;
use strict;
#
# Load a DOS EXE "MZ" header and dump its contents
#
# Optionally calculate the size of various segments and emit them
#
# Calculations and structure names taken directly from
#       http://www.delorie.com/djgpp/doc/exe/
#
# Copyright (C) 2016 Hamish Coleman

use IO::File;

use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Quotekeys = 0;

sub usage() {
    print("Dump the DOS EXE MZ header\n");
    exit(1);
}

sub cat {
    my $fh = shift;
    my $buf;
    while(!$fh->eof()) {
        $fh->read($buf,512);
        print $buf;
    }
}

sub read_header {
    my $fh = shift;
    my $db;

    # assume that we do not support nested files
    $fh->seek(0,SEEK_SET);

    my $buf;
    $fh->read($buf,0x1b);

    my @fields = qw(signature bytes_in_last_block blocks_in_file num_relocs
        header_paragraphs min_extra_paragraphs max_extra_paragraphs
        ss sp checksum ip cs
        reloc_table_offset overlay_number);
    my @values = unpack("SSSSSSSSSSSSSS",$buf);
    %{$db->{headers}} =
        map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    return $db;
}

sub main() {
    my $binaryfile = shift @ARGV;
    if (!defined($binaryfile)) {
        usage();
    }

    my $fh = IO::File->new($binaryfile, O_RDWR);
    if (!defined($fh)) {
        warn("Could not open $binaryfile\n");
        exit(1);
    }

    my $db = read_header($fh);

    $db->{calc}{exe_data_start} = $db->{headers}{header_paragraphs} * 16;
    $db->{calc}{extra_data_start} = $db->{headers}{blocks_in_file} * 512;
    if ($db->{calc}{bytes_in_last_block}) {
        $db->{headers}{extra_data_start} -= (512 - $db->{calc}{bytes_in_last_block});
    }

    if ($ARGV[0]||'' eq 'output_extra') {
        $fh->seek($db->{calc}{extra_data_start},SEEK_SET);
        cat($fh);
        exit(0);
    }

    print Dumper($db);
}
main();

