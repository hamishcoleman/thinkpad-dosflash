#!/usr/bin/env perl
use warnings;
use strict;
#
# Load a phoenix bios image binary file, look for the $PFH and dump its contents
#
# Ref https://gist.github.com/skochinsky/181e6e338d90bb7f2693098dc43c6d54
#


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

my $capsule_offset_hack = 0;

sub find_capsule {
    my $fh = shift;

    my $buf;
    $fh->read($buf,16);

    if ($buf eq "\xbd\x86\x66\x3b\x76\x0d\x30\x40\xb7\x0e\xb5\x51\x9e\x2f\xc5\xa0") {
        # TODO
        # - we should read the rest of the header
        # - this header has some size details, but they do not match up with
        #   the magic offset we are using
        # - Need to understand better why the resulting offset is 0x1d0
        $capsule_offset_hack = 0x1d0;
        return $capsule_offset_hack;
    }
    return undef;
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
    $fh->read($buf,4+4+4+2+4+2+4+4);

    my @fields = qw(Signature Version HeaderSize HeaderChecksum TotalImageSize TotalImageChecksum NumberofImages ImageTableOffset);
    my @values = unpack("a4VVvVvVV",$buf);
    my %table = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    $table{Version}            = hexify($table{Version});
    $table{HeaderSize}         = hexify($table{HeaderSize});
    $table{HeaderChecksum}     = hexify($table{HeaderChecksum});
    $table{TotalImageSize}     = hexify($table{TotalImageSize});
    $table{TotalImageChecksum} = hexify($table{TotalImageChecksum});
    $table{ImageTableOffset}   = hexify($table{ImageTableOffset});

    $table{_addr} = $addr;
    $db->{_PFH} = \%table;

    $fh->seek(hex($table{ImageTableOffset})+$capsule_offset_hack,SEEK_SET);
    for my $i (0..$table{NumberofImages}-1) {
        read_pfh_info($db,$fh,$i);
    }

    read_pfh_names($db,$fh);

    return 1;
}

sub dump_partition_one {
    my $part = shift;

    printf("%10s %10s %10s %s\n",
        $part->{FileOffset},
        $part->{FlashAddress},
        $part->{Size},
        $part->{_name},
    );
}

sub dump_partitions {
    my $db = shift;

    printf("%10s %10s %10s %s\n",
        "fileOfs",
        "flashAddr",
        "Size",
        "Name",
    );
    for my $part (@{$db->{_PFH}{_part}}) {
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

    $db->{offset}{Capsule_Magic} = find_capsule($fh);

    $db->{offset}{_PFH} = find_pfh($fh);
    if (!$db->{offset}{_PFH}) {
        die("Could not find FLASH MAP\n");
    }

    read_pfh($db,$fh,$db->{offset}{_PFH});

    dump_partitions($db);
    print Dumper($db);

}
main();

