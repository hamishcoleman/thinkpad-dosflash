#!/usr/bin/env perl
use warnings;
use strict;
#
# Load a phoenix bios image binary file, look for the $PFH and dump its contents
#
# Ref https://gist.github.com/skochinsky/181e6e338d90bb7f2693098dc43c6d54
#
# TODO
# - read the capsule header and do /something/ with it
#   (for now, we just offset seek addresses by 0x1d0)
my $capsule_offset_hack = 0x1d0;


use IO::File;
use UUID ':all';

use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Quotekeys = 0;

sub usage() {
    print("Dump the \$PFH information\n");
    exit(1);
}

sub find_pfh {
    my $fh = shift;

    my $offset = 0;

    while(!$fh->eof()) {
        $fh->seek($offset,SEEK_SET);

        my $signature;
        $fh->read($signature,4);

        if ($signature eq '$PFH') {
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

sub read_pfh_info {
    my $db = shift;
    my $fh = shift;
    my $index = shift;

    my $buf;
    $fh->read($buf,4+4+8+4);

    my @fields = qw(FileOffset Size FlashAddress NameOffset);
    my @values = unpack("VVQV",$buf);
    my %table = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    $table{FileOffset}   = hexify($table{FileOffset});
    $table{Size}         = hexify($table{Size});
    $table{FlashAddress} = hexify($table{FlashAddress});
    $table{NameOffset}   = hexify($table{NameOffset});

    $table{_index} = $index;
    push @{$db->{_PFH}{_part}},\%table;

    return 1;
}

sub read_pfh_names {
    my $db = shift;
    my $fh = shift;

    for my $entry (@{$db->{_PFH}{_part}}) {
        $fh->seek(hex($entry->{NameOffset})+$capsule_offset_hack,SEEK_SET);
        my $buf;
        $fh->read($buf,32); # FIXME - just a guess
        $entry->{_name} = unpack("Z*",$buf);
    }
}

sub read_pfh {
    my $db = shift;
    my $fh = shift;
    my $addr = shift;

    $fh->seek($addr,SEEK_SET);

    my $buf;
    $fh->read($buf,4+4+4+2+4+2+4+4+192);

    my @fields = qw(Signature Version HeaderSize HeaderChecksum TotalImageSize TotalImageChecksum NumberofImages imagetableOffset unknown);
    my @values = unpack("a4VVvVvVVa192",$buf);
    my %table = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    $table{Version}            = hexify($table{Version});
    $table{HeaderSize}         = hexify($table{HeaderSize});
    $table{HeaderChecksum}     = hexify($table{HeaderChecksum});
    $table{TotalImageSize}     = hexify($table{TotalImageSize});
    $table{TotalImageChecksum} = hexify($table{TotalImageChecksum});
    $table{imagetableOffset}   = hexify($table{imagetableOffset});

    $table{_addr} = $addr;
    $db->{_PFH} = \%table;

    for my $i (0..$table{NumberofImages}-1) {
        read_pfh_info($db,$fh,$i);
    }

    read_pfh_names($db,$fh);

    return 1;
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

    $db->{offset}{_PFH} = find_pfh($fh);
    if (!$db->{offset}{_PFH}) {
        die("Could not find FLASH MAP\n");
    }

    read_pfh($db,$fh,$db->{offset}{_PFH});

#    dump_partitions($db);
    print Dumper($db);

}
main();

