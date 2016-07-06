;
; Generate a FL2 file that looks good to the dosflash tool.
;
; Note that with xx20 and xx30 the dosflash tool is looking for a flashmap
; but with the xx50 and xx60, it is looking for a different "_EC" struct
;
; For the moment, just output a flashmap
;

%macro FLASHMAP 1
    align 16
    db "_FLASH_MAP"     ; signature
    dw %1               ; number of regions in map
    db 0,0,0,0          ; padding? reserved?
%endmacro

%macro FLASHMAP_entry 6
    db %1       ; UUID
    dw %2       ; RegionType
    dw %3       ; AreaType
    dq %4       ; Base
    dd %5       ; Size
    dd %6       ; Offset
%endmacro

org 0
    align 16
bin1:
    times 0x10 db 0
bin1_size equ $ - bin1

    align 16
bin2:
    times 0x10 db 0
bin2_size equ $ - bin2

times 0x1c0 - ($-$$) db 0x90
flashmap:
    FLASHMAP 2
    FLASHMAP_entry "0000000000000000", 0, 0, 0xf000000, bin1_size, bin1
    FLASHMAP_entry "0000000000000001", 0, 0, 0xf010000, bin2_size, bin2




; "_EC" struct stuff:
; org 0
; db "_EC", 1, 0x20     ; signature?
;; db 0x01, 0x03, 0x00   ; x250
;; db 0x60, 0x04, 0x00   ; x260 - choose one def
; dd filesize           ; on x250, this is filesize + hdrsize - 0x100, 
;                       ; on x260, this is filesize + hdrsize
; dd 1  ; unknown
; dd 1  ; unknown
; dd checksum?  ; on x250 38 0e fd ab, on x260 9a ad 98 4d
; db 0,0,0,0,0,0,0,0    ; padding?
; 
