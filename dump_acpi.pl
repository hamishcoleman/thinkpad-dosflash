#!/usr/bin/env perl
use warnings;
use strict;
#
# Load a bios image binary file, look for the RSDP and dump its contents
#
# Ref http://wiki.osdev.org/RSDP

my $debug = 0;

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
        if ($phys_addr > $r->{phys_addr} && $phys_addr < $r->{phys_addr}+$r->{size}) {
            $region = $r;
            last;
        }
    }

    if (!defined($region)) {
        printf("unhandled address 0x%08x\n",$phys_addr);
        return undef;
    }

    my $offset = $phys_addr - $region->{phys_addr};
    $offset += $region->{file_offset};

    if ($debug) {
        printf("0x%08x(%x) = 0x%08x (%s)\n",
            $phys_addr,$size,
            $offset,
            $region->{filename},
        );
    }

    $region->{fh}->seek($offset,SEEK_SET);
    my $buf;
    $region->{fh}->read($buf,$size);

    return $buf;
}

sub find_rsdp {
    my $db = shift;

    my $offset = 0xf0000; # Note, this could be as early as 0xe0000

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
    my $addr = shift;

    my $buf = memr_read($db,$addr,36);

    my @fields = qw(signature checksum oemid revision rsdtaddress length xsdtaddress extendedchecksum reserved);
    my @values = unpack("A8CA6cVVQCa3",$buf);
    my %rsdp = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    $rsdp{_addr} = $addr;
    return \%rsdp;
}

sub dump_rsdp {
    my $rsdp = shift;

    printf("0x%08x: %s(%i) %s rsdt=0x%08x xsdt=0x%08x\n",
        $rsdp->{_addr},
        $rsdp->{signature}, $rsdp->{revision},
        $rsdp->{oemid},
        $rsdp->{rsdtaddress}, $rsdp->{xsdtaddress},
    );
}

sub read_SDT {
    my $db = shift;
    my $addr = shift;

    my $header_len = 36;
    my $buf = memr_read($db,$addr,$header_len);

    my @fields = qw(signature length revision checksum oemid oemtableid oemrevision creatorid creatorrevision);
    my @values = unpack("A4VccA6A8VA4V",$buf);
    my %header = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    return undef if ($header{signature} eq "\xff\xff\xff\xff");

    my $sdt;
    $sdt->{_header} = \%header;
    $sdt->{_addr} = $addr;

    my $tablename = $header{signature};
    my $i = 0;
    while (defined($db->{SDT}{$tablename})) {
        $tablename = sprintf("%s:%i",$header{signature},++$i);
    }
    $db->{SDT}{$tablename} = $sdt;

    my $remainder = $header{length} - $header_len;
    return $sdt if ($remainder<=0);

    $sdt->{_data} = memr_read($db,$addr+$header_len,$remainder);
    return $sdt;
}

sub dump_SDT {
    my $sdt = shift;
    my $header = $sdt->{_header};

    printf("0x%08x: %s(%i) %s %s(%i) %s(%i)\n",
        $sdt->{_addr},
        $header->{signature}, $header->{revision},
        $header->{oemid},
        $header->{oemtableid}, $header->{oemrevision},
        $header->{creatorid}, $header->{creatorrevision},
    );
}

sub read_XSDT {
    my $db = shift;
    my $addr = shift;

    my $SDT = read_SDT($db,$addr);

    my @tables = unpack("Q*",$SDT->{_data});

    delete $SDT->{_data};
    $SDT->{tables} = \@tables;

    return $SDT;
}

sub main() {
    my $configfile = shift @ARGV;
    if (!defined($configfile)) {
        usage();
    }

    my $db = {};
    load_configfile($db,$configfile);

    $db->{address}{RSDP} = find_rsdp($db);
    if (!$db->{address}{RSDP}) {
        die("Could not find RSDP\n");
    }

    $db->{RSDP} = read_rsdp($db,$db->{address}{RSDP});
    read_XSDT($db,$db->{RSDP}{xsdtaddress});

    dump_rsdp($db->{RSDP});
    dump_SDT($db->{SDT}{XSDT});

    for my $addr (@{$db->{SDT}{XSDT}{tables}}) {
        dump_SDT(read_SDT($db,$addr));
    }

    print Dumper($db);

}
main();

