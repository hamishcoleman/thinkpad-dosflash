#!/usr/bin/env perl
use warnings;
use strict;
#
# Load a bios image binary file, look for the RSDP and dump its contents
#
# Ref http://wiki.osdev.org/RSDP

my $debug = 0;

use IO::File;
use UUID ':all';


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
    $db->{RSDP} = \%rsdp;
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

sub handle_uuid_4 {
    my $SDT = shift;
    my @fields = qw(
        addr
        _data
    );
    my @values = unpack("Qa*",$SDT->{_data});
    map { $SDT->{$fields[$_]} = $values[$_] } (0..scalar(@fields)-1);

    return $SDT;
}

sub handle_uuid_2 {
    my $SDT = shift;

    # guessing that this is the same layout as the SMM Communication
    # ACPI Table. described in the UEFI docs
    # GUID {0xc68ed8e2, 0x9dc6, 0x4cbd, 0x9d, 0x94, 0xdb, 0x65, 0xac, 0xc5, 0xc3, 0x32}

    my @fields = qw(
        SW_SMI_Number
        Buffer_Ptr_Address
        _data
    );
    my @values = unpack("VQa*",$SDT->{_data});
    map { $SDT->{$fields[$_]} = $values[$_] } (0..scalar(@fields)-1);

    return $SDT;
}

my %handler_UEFI = (
    'e86395d2-e1cf-414d-8e54-da4322fede5c' => \&handle_uuid_4,
    'be96e815-df0c-e247-9b97-a28a398bc765' => \&handle_uuid_2,
);

sub handle_XSDT {
    my $SDT = shift;

    my @tables = unpack("Q*",$SDT->{_data});

    delete $SDT->{_data};
    $SDT->{tables} = \@tables;

    return $SDT;
}

sub handle_FACP {
    my $SDT = shift;

    my @fields = qw(
        FirmwareCtrl Dsdt Reserved PreferredPowerManagementProfile
        SCI_Interrupt SMI_CommandPort AcpiEnable AcpiDisable S4BIOS_REQ
        PSTATE_Control PM1aEventBlock PM1bEventBlock PM1aControlBlock
        PM1bControlBlock PM2ControlBlock PMTimerBlock GPE0Block GPE1Block
        PM1EventLength PM1ControlLength PM2ControlLength PMTimerLength
        GPE0Length GPE1Length GPE1Base CStateControl
        WorstC2Latency WorstC3Latency FlushSize FlushStride
        DutyOffset DutyWidth DayAlarm MonthAlarm Century
        BootArchitectureFlags
        Reserved2 Flags
        ResetReg.AddressSpace ResetReg.BitWidth ResetReg.BitOffset
        ResetReg.AccessSize ResetReg.Address
        _data
    );
    # TODO - GenericAddressStructure helper and the rest of the fields
    my @values = unpack("VVCCvVCCCCVVVVVVVVCCCCCCCCvvvvCCCCCvCVCCCCQa*",$SDT->{_data});
    map { $SDT->{$fields[$_]} = $values[$_] } (0..scalar(@fields)-1);

    return $SDT;
}

sub handle_AML {
    my $SDT = shift;

    delete $SDT->{_data};
    $SDT->{AML} = "Binary AML data not processed";
    # use an acpi decompiler ...

    return $SDT;
}

sub handle_UEFI {
    my $SDT = shift;

    my ($uuid,$DataOffset,$data) = unpack("a16va*",$SDT->{_data});
    unparse($uuid,$uuid);
    $SDT->{UUID} = $uuid;
    $SDT->{DataOffset} = $DataOffset;
    # TODO - DataOffset technically should be used to set the _data field
    $SDT->{_data} = $data;

    if (defined($handler_UEFI{$uuid})) {
        $handler_UEFI{$uuid}($SDT);
    }

    return $SDT;
}

my %handler = (
    XSDT => \&handle_XSDT,
    FACP => \&handle_FACP,
    DSDT => \&handle_AML,
    SSDT => \&handle_AML,
    UEFI => \&handle_UEFI,
);

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

    if (defined($handler{$header{signature}})) {
        $handler{$header{signature}}($sdt);
    }

    return $sdt;
}

sub dump_SDT {
    my $sdt = shift;
    my $header = $sdt->{_header};

    printf("0x%08x(%04x): %s(%i) %s %s(%i) %s(%i)\n",
        $sdt->{_addr}, $header->{length},
        $header->{signature}, $header->{revision},
        $header->{oemid},
        $header->{oemtableid}, $header->{oemrevision},
        $header->{creatorid}, $header->{creatorrevision},
    );
}

sub read_FACS {
    my $db = shift;
    my $addr = shift;

    my $signature = memr_read($db,$addr,4);
    return if ($signature ne 'FACS');

    my $length = unpack("V",memr_read($db,$addr+4,4));

    my $buf = memr_read($db,$addr,$length);

    my @fields = qw(signature Length Hardware_Signature
        Firmware_Waking_Vector Global_Lock Flags X_Firmware_Waking_Vector
        Version Reserved
        );
    my @values = unpack("A4VVVVVQCA31",$buf);
    my %table = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    $table{_addr} = $addr;
    $db->{FACS} = \%table;
    return \%table;
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

    read_rsdp($db,$db->{address}{RSDP});
    read_SDT($db,$db->{RSDP}{xsdtaddress});

    dump_rsdp($db->{RSDP});
    dump_SDT($db->{SDT}{XSDT});

    for my $addr (@{$db->{SDT}{XSDT}{tables}}) {
        dump_SDT(read_SDT($db,$addr));
    }

    dump_SDT(read_SDT($db,$db->{SDT}{FACP}{Dsdt}));
    read_FACS($db,$db->{SDT}{FACP}{FirmwareCtrl});

    print Dumper($db);

}
main();

