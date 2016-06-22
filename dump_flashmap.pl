#!/usr/bin/env perl
use warnings;
use strict;
#
# Load a phoenix bios image binary file, look for the FLASH MAP and dump its contents
#
# Ref http://wiki.phoenix.com/wiki/index.php/PHOENIX_FLASH_MAP_HEADER

use IO::File;
use UUID ':all';

use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Quotekeys = 0;

sub usage() {
    print("Dump the PHOENIX_FLASH_MAP information\n");
    exit(1);
}

sub find_flash_map {
    my $fh = shift;

    my $offset = 0;

    while(!$fh->eof()) {
        $fh->seek($offset,SEEK_SET);

        my $signature;
        $fh->read($signature,10);

        if ($signature eq '_FLASH_MAP') {
            return $offset;
        }

        $offset+=0x10;
    }

    return 0; # not found
}

sub hexify {
    my $val = shift;
    return sprintf("0x%02x",$val);
}

sub read_flash_map_info {
    my $db = shift;
    my $fh = shift;
    my $index = shift;

    my $buf;
    $fh->read($buf,16+2+2+8+4+4);

    my @fields = qw(Guid RegionType AreaType Base Size Offset);
    my @values = unpack("a16vvQVV",$buf);
    my %table = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    unparse($table{Guid},$table{Guid});
    $table{RegionType} = hexify($table{RegionType});
    $table{AreaType}   = hexify($table{AreaType});
    $table{Base}       = hexify($table{Base});
    $table{Size}       = hexify($table{Size});
    $table{Offset}     = hexify($table{Offset});


    $table{_index} = $index;
    push @{$db->{_FLASH_MAP}{_part}},\%table;
}

sub read_flash_map {
    my $db = shift;
    my $fh = shift;
    my $addr = shift;

    $fh->seek($addr,SEEK_SET);

    my $buf;
    $fh->read($buf,10+2+4);

    my @fields = qw(Signature NoOfRegion Reserved);
    my @values = unpack("A10va84",$buf);
    my %table = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    $table{_addr} = $addr;
    $db->{_FLASH_MAP} = \%table;

    for my $i (0..$table{NoOfRegion}-1) {
        read_flash_map_info($db,$fh,$i);
    }
    return 1;
}

sub dump_partition_one {
    my $part = shift;

    printf("%s %s %s %s %8s %8s\n",
        $part->{Guid},
        $part->{RegionType},
        $part->{AreaType},
        $part->{Base},
        $part->{Size},
        $part->{Offset},
    );
}

sub dump_partitions {
    my $db = shift;

    printf("%-30s %4s %4s %6s %8s %8s\n",
        "guid",
        "regionType",
        "areaType",
        "base",
        "size",
        "offset",
    );
    for my $part (@{$db->{_FLASH_MAP}{_part}}) {
        dump_partition_one($part);
    }
}

sub main() {
    my $binaryfile = shift @ARGV;
    if (!defined($binaryfile)) {
        usage();
    }

    my $fh = IO::File->new($binaryfile, O_RDONLY);
    if (!defined($fh)) {
        warn("Could not open $binaryfile\n");
        exit(1);
    }

    my $db = {};

    $db->{offset}{_FLASH_MAP} = find_flash_map($fh);
    if (!$db->{offset}) {
        die("Could not find FLASH MAP\n");
    }

    read_flash_map($db,$fh,$db->{offset}{_FLASH_MAP});

    dump_partitions($db);
    print Dumper($db);

}
main();

