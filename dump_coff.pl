#!/usr/bin/env perl
use warnings;
use strict;
#
# Load a djgcc COFF file and dump its contents
#
# Calculations and structure names taken directly from
#       http://www.delorie.com/djgpp/doc/coff/
#
# Copyright (C) 2016 Hamish Coleman

use IO::File;

use Data::Dumper;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Quotekeys = 0;

sub usage() {
    print("Dump the COFF data\n");
    exit(1);
}

sub read_file_header {
    my $db = shift;
    my $fh = shift;

    # assume that we do not support nested files
    $fh->seek(0,SEEK_SET);

    my $buf;
    $fh->read($buf,20);

    my @fields = qw(f_magic f_nscns f_timdat f_symptr f_nsyms f_opthdr f_flags);
    my @values = unpack("SSLLLSS",$buf);
    %{$db->{file_header}} =
        map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);
}

sub read_opthdr {
    my $db = shift;
    my $fh = shift;

    my $buf;
    my @fields;
    my @values;

    $fh->read($buf,$db->{file_header}{f_opthdr});

    if($db->{file_header}{f_opthdr}==28) {

        @fields = qw(magic vstamp tsize dsize bsize  entry text_start data_start);
        @values = unpack("SSLLLLLL",$buf);
        %{$db->{aouthdr}} =
            map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);
    } else {
        $db->{opthdr} = "FIXME - add a hexdump";
    }
}

sub read_section_header {
    my $db = shift;
    my $fh = shift;
    my $section_nr = shift;

    my $buf;
    $fh->read($buf,40);

    my @fields = qw(s_name s_paddr s_vaddr s_size s_scnptr s_relptr s_lnnoptr
        s_nreloc s_nlnno s_flags);
    my @values = unpack("a8LLLLLLSSL",$buf);
    %{$db->{section}{$section_nr}} =
        map { $fields[$_] => $values[$_] } (0..scalar(@fields)-1);

}

sub read_section_headers {
    my $db = shift;
    my $fh = shift;

    foreach (1..$db->{file_header}{f_nscns}) {
        read_section_header($db,$fh,$_);
    }
}

sub write_flat {
    my $db = shift;
    my $coff_fh = shift;
    my $outname = shift;

    my $flat_fh = IO::File->new($outname, O_WRONLY|O_CREAT);
    if (!defined($flat_fh)) {
        warn("Could not open $outname\n");
        exit(1);
    }

    for my $section (values(%{$db->{section}})) {
        printf("writing section %s src 0x%x dst 0x%x size 0x%x\n",
            $section->{s_name}, $section->{s_scnptr}, $section->{s_paddr}, $section->{s_size});

        $flat_fh->seek($section->{s_paddr},SEEK_SET);

        if ($section->{s_flags} == 0x80) {
            # STYP_BSS
            my $buf = chr(0)x$section->{s_size};
            $flat_fh->write($buf);
        } else {
            $coff_fh->seek($section->{s_scnptr},SEEK_SET);
            my $buf;
            $coff_fh->read($buf,$section->{s_size});
            $flat_fh->write($buf);
        }
    }
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

    my $db = {};
    read_file_header($db,$fh);
    read_opthdr($db,$fh);
    read_section_headers($db,$fh);

    print Dumper($db);

    if ($ARGV[0]||'' eq 'write_flat') {
        write_flat($db,$fh,$ARGV[1]);
    }
}
main();

