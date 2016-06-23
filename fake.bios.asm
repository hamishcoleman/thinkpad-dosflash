;
; Generate the right signatures and tables to make the dosflash happy that
; it has a BIOS
;
;

%macro ACPISDTHeader 2
    db %1
    dd %2
    db 1        ; revision
    db 0        ; checksum
    db "FAKE02"
    db "Table002"
    dd 1        ; OEMRevision
    db "CT02"   ; CreatorID
    dd 1        ; CreatorRevision
%endmacro

%define addr_ram        0
%define addr_io         1
%define addr_pci        2
%define addr_ec         3
%define addr_smbus      4
%macro GenericAddressStructure 5
    db %1       ; AddressSpace
    db %2       ; BitWidth
    db %3       ; BitOffset
    db %4       ; AccessSize
    dq %5       ; Address
%endmacro

org 0xf0000

bios_sig:
    db "Fake Phoenix"

    align 16
rsd_ptr:
    db "RSD PTR "
    db 0        ; checksum
    db "FAKE01" ; OEMID
    db 2        ; Revision
    dd rsdt
    dd rsd_ptr_size
    dq xsdt
    db 0        ; checksum
    db 0,0,0    ; reserved

rsd_ptr_size equ $ - rsd_ptr

    align 16
rsdt:
    ACPISDTHeader "RSDT",rsdt_size
    dd facp
    dd uefi1
    dd uefi2
rsdt_size equ $ - rsdt

    align 16
xsdt:
    ACPISDTHeader "XSDT",xsdt_size
    dq facp
    dq uefi1
    dq uefi2
xsdt_size equ $ - xsdt

    align 16
facp:
    ACPISDTHeader "FACP",facp_size
    dd facs     ; FirmwareCtrl
    dd dsdt
    db 0        ; Reserved;
    db 2        ; PreferredPowerManagementProfile;
    dw 9        ; SCI_Interrupt;
    dd 0xb2     ; SMI_CommandPort;
    db 0xf2     ; AcpiEnable;
    db 0xf1     ; AcpiDisable;
    db 0        ; S4BIOS_REQ;
    db 0xf3     ; PSTATE_Control;
    dd 0x400    ; PM1aEventBlock;
    dd 0        ; PM1bEventBlock;
    dd 0x404    ; PM1aControlBlock;
    dd 0        ; PM1bControlBlock;
    dd 0x450    ; PM2ControlBlock;
    dd 0x408    ; PMTimerBlock;
    dd 0x420    ; GPE0Block;
    dd 0        ; GPE1Block;
    db 4        ; PM1EventLength;
    db 2        ; PM1ControlLength;
    db 1        ; PM2ControlLength;
    db 4        ; PMTimerLength;
    db 16       ; GPE0Length;
    db 0        ; GPE1Length;
    db 16       ; GPE1Base;
    db 0xf4     ; CStateControl;
    dw 101      ; WorstC2Latency;
    dw 57       ; WorstC3Latency;
    dw 0        ; FlushSize;
    dw 0        ; FlushStride;
    db 1        ; DutyOffset;
    db 3        ; DutyWidth;
    db 13       ; DayAlarm;
    db 0        ; MonthAlarm;
    db 50       ; Century;
    dw 0x13     ; BootArchitectureFlags;
    db 0        ; Reserved2;
    dd 0x46ad   ; Flags;
    GenericAddressStructure addr_io,8,0,0,0xcf9 ; ResetReg;
    db 6        ; ResetValue;
    db 0,0,0    ; Reserved3[3];
    dq 0        ; facs; X_FirmwareControl;
    dq 0        ; dsdt; X_Dsdt;
    GenericAddressStructure addr_io,32,0,3,0x400 ; X_PM1aEventBlock;
    GenericAddressStructure addr_io,0,0,0,0      ; X_PM1bEventBlock;
    GenericAddressStructure addr_io,16,0,2,0x404 ; X_PM1aControlBlock;
    GenericAddressStructure addr_io,0,0,0,0      ; X_PM1bControlBlock;
    GenericAddressStructure addr_io,8,0,1,0x450  ; X_PM2ControlBlock;
    GenericAddressStructure addr_io,32,0,3,0x408 ; X_PMTimerBlock;
    GenericAddressStructure addr_io,0x80,0,0,0x420 ; X_GPE0Block;
    GenericAddressStructure addr_io,0,0,0,0      ; X_GPE1Block;
    ;GenericAddressStructure addr_io,8,0,0,0
    ;GenericAddressStructure addr_io,8,0,0,0
facp_size equ $ - facp

    align 16
dsdt:
    ACPISDTHeader "DSDT",dsdt_size
dsdt_size equ $ - dsdt

    align 16
    db 0
    align 16
facs:
    db "FACS"
    dd facs_size
    dd 0        ; Hardware_Signature
    dd 0        ; Firmware_Waking_Vector
    dd 0        ; Global_Lock
    dd 0        ; Flags
    dq 0        ; X_Firmware_Waking_Vector
    db 1        ; Version
    times 31 db 0 ; Reserved

facs_size equ $ - facs

    align 16
uefi1:
    ACPISDTHeader "UEFI",uefi1_size
    db 0xbe, 0x96, 0xe8, 0x15, 0xdf, 0x0c, 0xe2, 0x47  ; uuid
    db 0x9b, 0x97, 0xa2, 0x8a, 0x39, 0x8b, 0xc7, 0x65
    dw $ - uefi1 +2     ; DataOffset
    dd 2        ; SW_SMI_Number
    dq data1+8  ; Buffer_Ptr_Address

uefi1_size equ $ - uefi1

    align 16
uefi2:
    ACPISDTHeader "UEFI",uefi2_size
    db 0xe8, 0x63, 0x95, 0xd2, 0xe1, 0xcf, 0x41, 0x4d   ; uuid
    db 0x8e, 0x54, 0xda, 0x43, 0x22, 0xfe, 0xde, 0x5c
    dw $ - uefi2 +2     ; DataOffset
    dq data2
uefi2_size equ $ - uefi2

    align 16
data1:
    ; This appears to be the data transfer buffer for the SMI commands
times 0x200 db 0

    align 16
data2:
    ; Dont know what this is, but it is filled with data on the real BIOS
times 0x1000 db 0 ; dunno if this is the right size ..

times 0x10000-($-$$) db 0
bios_end:
