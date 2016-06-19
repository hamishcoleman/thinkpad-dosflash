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
    print("Dump the ACPI tables\n");
    print("Usage: dump_acpi.pl configfile\n");
    exit(1);
}

sub load_memory {
    my $db = shift;
    my ($phys_addr, $size, $filename, $file_offset, $flags) = @_;

    my $region;
    $region->{phys_addr}   = $phys_addr;
    $region->{size}        = $size;
    $region->{filename}    = $filename;
    $region->{file_offset} = $file_offset;
    $region->{flags}       = $flags;

    my $fh = IO::File->new($filename, O_RDONLY);
    if (!defined($fh)) {
        warn("Could not open $filename\n");
        exit(1);
    }
    $region->{fh} = $fh;

    push @{$db->{region}}, $region;
}

sub load_configfile {
    my $db = shift;
    my $filename = shift;

    my $fh = IO::File->new($filename, O_RDONLY);
    if (!defined($fh)) {
        warn("Could not open $filename\n");
        exit(1);
    }

    while(<$fh>) {
        chomp; s/\r//g;

        # remove whitespace
        s/^\s+//;

        # remove comment lines
        s/^[#].*//;

        if (m/^include\s+(\S+)/) {
            load_configfile($db,$1);
        } elsif (m/^load_memory\s+/) {
            my @a = split(/\s+/,$_);
            load_memory(
                $db,
                eval "$a[1]", eval "$a[2]", $a[3], eval "$a[4]", $a[5]
            );
        }
    }
}

sub memr_read {
    my $db = shift;
    my $phys_addr = shift;
    my $size = shift;

    my $region;
    # find the correct region
    for my $r (@{$db->{region}}) {
        if ($phys_addr > $r->{phys_addr} && $phys_addr+$size < $r->{phys_addr}+$r->{size}) {
            $region = $r;
            last;
        }
    }

    if (!defined($region)) {
        die("unhandled address ",$phys_addr);
    }

    my $offset = $phys_addr - $region->{phys_addr};
    $offset += $region->{file_offset};

    $region->{fh}->seek($offset,SEEK_SET);
    my $buf;
    $region->{fh}->read($buf,$size);

    return $buf;
}

sub find_rsdp {
    my $db = shift;

    my $offset = 0xe0000;

    while($offset < 0xfffff) {
        my $signature = memr_read($db,$offset,8);

        if ($signature eq 'RSD PTR ') {
            return $offset;
        }

        $offset+=0x10;
    }

    return 0; # not found
}

sub read_rsdp {
    my $db = shift;

    my $buf = memr_read($db,$db->{address}{rsdp},36);

    my @fields = qw(signature checksum oemid revision rsdtaddress length xsdtaddress extendedchecksum reserved);
    my @values = unpack("A[8]CA[6]cVVQCa[3]",$buf);
    %{$db->{data}{rsdp}} =
        map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);
}

sub main() {
    my $configfile = shift @ARGV;
    if (!defined($configfile)) {
        usage();
    }

    my $db = {};
    load_configfile($db,$configfile);

    $db->{address}{rsdp} = find_rsdp($db);
    if (!$db->{address}{rsdp}) {
        die("Could not find RSDP\n");
    }
    read_rsdp($db);

    print Dumper($db);

}
main();

