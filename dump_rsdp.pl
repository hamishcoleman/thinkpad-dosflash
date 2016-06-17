#!/usr/bin/env perl
use warnings;
use strict;
#
# Load a bios image binary file, look for the RSDP and dump its contents
#
# Ref http://wiki.osdev.org/RSDP

use IO::File;

use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Quotekeys = 0;

sub usage() {
    print("Dump the RSDP descriptor\n");
    exit(1);
}

sub find_rsdp {
    my $fh = shift;

    my $offset = 0;

    while(!$fh->eof()) {
        $fh->seek($offset,SEEK_SET);

        my $signature;
        $fh->read($signature,8);

        if ($signature eq 'RSD PTR ') {
            return $offset;
        }

        $offset+=0x10;
    }

    return 0; # not found
}

sub read_rsdp {
    my $db = shift;
    my $fh = shift;

    $fh->seek($db->{offset},SEEK_SET);

    my $buf;
    $fh->read($buf,36);

    my @fields = qw(signature checksum oemid revision rsdtaddress length xsdtaddress extendedchecksum reserved);
    my @values = unpack("A[8]CA[6]cVVQCa[3]",$buf);
    %{$db->{file_header}} =
        map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);
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
    $db->{offset} = find_rsdp($fh);
    if (!$db->{offset}) {
        warn("Could not find RSDP\n");
        exit(1);
    }
    read_rsdp($db,$fh);

    print Dumper($db);

}
main();

