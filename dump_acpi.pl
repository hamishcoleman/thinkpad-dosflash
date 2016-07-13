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

# A generic hexdumper
sub hexdump(\$) {
    my ($buf,$size) = @_;
    my $r;

    if (!defined $$buf) {
        return undef;
    }
    if (!defined($size)) {
        $size = length $$buf;
    }

    my $offset=0;
    while ($offset<$size) {
        if (defined($r)) {
            # we have more than one line, so end the previous one first
            $r.="\n";
        }
        my @buf16= split //, substr($$buf,$offset,16);
        $r.=sprintf('%03x: ',$offset);
        for my $i (0..15) {
            if (defined $buf16[$i]) {
                $r.=sprintf('%02x ',ord($buf16[$i]));
            } else {
                $r.=sprintf('   ');
            }
        }
        $r.= "| ";
        for my $i (@buf16) {
            if (defined $i && ord($i)>0x20 && ord($i)<0x7f) {
                $r.=sprintf('%s',$i);
            } else {
                $r.=sprintf(' ');
            }
        }
        $offset+=16;
    }
    return $r;
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

    push @{$db->{region}}, $region;

    if ($flags & 2) {
        # anonymous memory has no file backing
        return;
    }

    my $fh = IO::File->new($filename, O_RDONLY);
    if (!defined($fh)) {
        warn("Could not open $filename\n");
        exit(1);
    }
    $region->{fh} = $fh;
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
        if ($phys_addr >= $r->{phys_addr} && $phys_addr <= $r->{phys_addr}+$r->{size}) {
            $region = $r;
            last;
        }
    }

    if (!defined($region)) {
        printf("unhandled address 0x%08x(0x%x)\n",$phys_addr,$size);
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

    if ($region->{flags} & 2) {
        # anonymous memory
        return chr(0)x$size;
    }

    $region->{fh}->seek($offset,SEEK_SET);
    my $buf;
    $region->{fh}->read($buf,$size);

    return $buf;
}

# dump a memr buffer
sub read_hexdump {
    my $db = shift;
    my $name = shift;
    my $addr = shift;
    my $size = shift;

    my $entry;
    $entry->{_addr} = $addr;

    # unhexify
    $addr = eval $addr;
    my $buf = memr_read($db,$addr,$size);

    $entry->{_hexdump} = "\n".hexdump($buf);
    $db->{$name} = $entry;
}

# turn an int into a hex
sub hexify {
    my $val = shift;
    return sprintf("0x%02x",$val);
}

sub sum_buf_bytes {
    my $buf = shift;

    my $sum = 0;
    my @bytes = unpack("C*",$buf);
    foreach (@bytes) {
        $sum += $_;
    }
    return $sum;
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

    $rsdp{_sum} = hexify(sum_buf_bytes($buf));
    $rsdp{_addr} = hexify($addr);
    $rsdp{xsdtaddress} = hexify($rsdp{xsdtaddress});
    $rsdp{rsdtaddress} = hexify($rsdp{rsdtaddress});
    $db->{RSDP} = \%rsdp;
    $db->{address}{$rsdp{_addr}} = $rsdp{signature};

    queue_add($db,\&read_SDT,$rsdp{xsdtaddress});
    queue_add($db,\&read_SDT,$rsdp{rsdtaddress});
    return 1;
}

sub dump_rsdp {
    my $rsdp = shift;

    printf("%s: %s(%i) %s rsdt=%s xsdt=%s\n",
        $rsdp->{_addr},
        $rsdp->{signature}, $rsdp->{revision},
        $rsdp->{oemid},
        $rsdp->{rsdtaddress}, $rsdp->{xsdtaddress},
    );
}

sub read_uuid_2_ptr {
    my $db = shift;
    my $addr = shift;
    my $entry;

    # unhexify
    $addr = eval $addr;
    $entry->{_addr} = hexify($addr);
    $entry->{_data} = memr_read($db,$addr,0x200);

    my @fields = qw(
        all_ff
        all_00_1
        maybe_uuid
        maybe_size_1
        all_00_2
        unknown6
        addr1
        addr2
        maybe_size_2
        addr3
        addr4
        _data
    );
    my @values = unpack("VVa16QQQQQQQQa*",$entry->{_data});
    map { $entry->{$fields[$_]} = $values[$_] } (0..scalar(@fields)-1);

    unparse($entry->{maybe_uuid},$entry->{maybe_uuid});
    $entry->{all_ff} = hexify($entry->{all_ff});
    $entry->{addr1} = hexify($entry->{addr1});
    $entry->{addr2} = hexify($entry->{addr2});
    $entry->{addr3} = hexify($entry->{addr3});
    $entry->{addr4} = hexify($entry->{addr4});

    queue_add($db,\&read_hexdump,"uuid_2_ptr_addr1",$entry->{addr1},0x100);
    queue_add($db,\&read_hexdump,"uuid_2_ptr_addr2",$entry->{addr2},0x100);
    queue_add($db,\&read_hexdump,"uuid_2_ptr_addr3",$entry->{addr3},0x100);
    queue_add($db,\&read_hexdump,"uuid_2_ptr_addr4",$entry->{addr4},0x100);

    $db->{uuid}{uuid_2_ptr} = $entry;
}

sub handle_uuid_4 {
    my $db = shift;
    my $SDT = shift;
    my @fields = qw(
        addr
        _data
    );
    my @values = unpack("Qa*",$SDT->{_data});
    map { $SDT->{$fields[$_]} = $values[$_] } (0..scalar(@fields)-1);

    $SDT->{addr} = hexify($SDT->{addr});
    queue_add($db,\&read_hexdump,"uuid_4",$SDT->{addr},0x1000);
    return $SDT;
}

sub handle_uuid_2 {
    my $db = shift;
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

    queue_add($db,\&read_uuid_2_ptr,$SDT->{Buffer_Ptr_Address}-8);
    $SDT->{Buffer_Ptr_Address} = hexify($SDT->{Buffer_Ptr_Address});
    return $SDT;
}

my %handler_UEFI = (
    'e86395d2-e1cf-414d-8e54-da4322fede5c' => \&handle_uuid_4,
    'be96e815-df0c-e247-9b97-a28a398bc765' => \&handle_uuid_2,
);

sub handle_RSDT {
    my $db = shift;
    my $SDT = shift;

    my @tables = unpack("V*",$SDT->{_data});

    delete $SDT->{_data};
    foreach (@tables) {
        my $addr = hexify($_);
        push @{$SDT->{tables}}, $addr;
        queue_add($db,\&read_SDT,$addr);
    }

    return $SDT;
}

sub handle_XSDT {
    my $db = shift;
    my $SDT = shift;

    my @tables = unpack("Q*",$SDT->{_data});

    delete $SDT->{_data};
    foreach (@tables) {
        my $addr = hexify($_);
        push @{$SDT->{tables}}, $addr;
        queue_add($db,\&read_SDT,$addr);
    }

    return $SDT;
}

sub handle_FACP {
    my $db = shift;
    my $SDT = shift;

    my @fields = qw(
        FACS DSDT Reserved PreferredPowerManagementProfile
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

    queue_add($db,\&read_SDT,$SDT->{DSDT});
    queue_add($db,\&read_FACS,$SDT->{FACS});

    return $SDT;
}

sub handle_AML {
    my $db = shift;
    my $SDT = shift;

    delete $SDT->{_data};
    $SDT->{AML} = "Binary AML data not processed";
    # use an acpi decompiler ...

    return $SDT;
}

sub handle_UEFI {
    my $db = shift;
    my $SDT = shift;

    my ($uuid,$DataOffset,$data) = unpack("a16va*",$SDT->{_data});
    unparse($uuid,$uuid);
    $SDT->{UUID} = $uuid;
    $SDT->{DataOffset} = $DataOffset;
    # TODO - DataOffset technically should be used to set the _data field
    $SDT->{_data} = $data;

    if (defined($handler_UEFI{$uuid})) {
        $handler_UEFI{$uuid}($db,$SDT);
    }

    return $SDT;
}

my %handler = (
    RSDT => \&handle_RSDT,
    XSDT => \&handle_XSDT,
    FACP => \&handle_FACP,
    DSDT => \&handle_AML,
    SSDT => \&handle_AML,
    UEFI => \&handle_UEFI,
);

sub read_SDT {
    my $db = shift;
    my $addr = shift;

    if (defined($db->{address}{$addr})) {
        $db->{address_dupe}{$addr} ++;
        return undef;
    }

    # de hex if needed
    $addr = eval $addr;

    my $header_len = 36;
    my $buf = memr_read($db,$addr,$header_len);

    my @fields = qw(signature length revision checksum oemid oemtableid oemrevision creatorid creatorrevision);
    my @values = unpack("A4VCCA6A8VA4V",$buf);
    my %header = map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

    return undef if ($header{signature} eq "\xff\xff\xff\xff");

    my $sdt;
    $sdt->{_header} = \%header;
    $sdt->{_addr} = hexify($addr);

    my $tablename = $header{signature};
    my $i = 0;
    while (defined($db->{SDT}{$tablename})) {
        $tablename = sprintf("%s:%i",$header{signature},++$i);
    }
    $db->{SDT}{$tablename} = $sdt;
    $db->{address}{$sdt->{_addr}} = $tablename;

    my $remainder = $header{length} - $header_len;
    return $sdt if ($remainder<=0);
    $sdt->{_data} = memr_read($db,$addr+$header_len,$remainder);

    $sdt->{_sum} = hexify(sum_buf_bytes($buf)+sum_buf_bytes($sdt->{_data}));
    if (defined($handler{$header{signature}})) {
        $handler{$header{signature}}($db,$sdt);
    }

    return $sdt;
}

sub dump_SDT {
    my $sdt = shift;
    my $header = $sdt->{_header};

    printf("%s(%04x): %s(%i) %s %s(%i) %s(%i)\n",
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

    # possibly dehexify
    $addr = eval $addr;

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

    $table{_addr} = hexify($addr);
    $db->{FACS} = \%table;
    $db->{address}{$table{_addr}} = $table{signature};
    return \%table;
}

sub queue_add {
    my $db = shift;
    my $entry;
    $entry->{fn} = shift;
    @{$entry->{args}} = @_;
    push @{$db->{queue}}, $entry;
}

sub queue_run {
    my $db = shift;

    my $entry;
    while ($entry = shift(@{$db->{queue}})) {
        my @args = @{$entry->{args}};
        $entry->{fn}($db,@args);
    }
}

sub main() {
    my $configfile = shift @ARGV;
    if (!defined($configfile)) {
        usage();
    }

    my $db = {};
    load_configfile($db,$configfile);

    my $address_rsdp = find_rsdp($db);
    if (!$address_rsdp) {
        die("Could not find RSDP\n");
    }

    queue_add($db,\&read_rsdp,$address_rsdp);
    queue_run($db);

    dump_rsdp($db->{RSDP});

    my @tables = values(%{$db->{SDT}});
    @tables = sort { $a->{_header}{signature} cmp $b->{_header}{signature} } @tables;
    for my $sdt (@tables) {
        dump_SDT($sdt);
    }

    print Dumper($db);

}
main();

