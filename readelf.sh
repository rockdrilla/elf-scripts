#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# (c) 2021, Konstantin Demin

set -f

## VERY naive readelf implementation

## refs:
## - https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
## - https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/elf.h;h=4738dfa28f6549fc11654996a15659dc8007e686;hb=refs/heads/release/2.34/master
## - https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=binutils/readelf.c;h=af10bcd0e170f1a3267a321571285c9d28ea2d9d;hb=refs/heads/binutils-2_37-branch
## - https://github.com/llvm/llvm-project/blob/release/13.x/llvm/include/llvm/BinaryFormat/ELF.h
## and so on :D

me=${0##*/}
dir0=${0%"${me}"}
dir0=${dir0:-'.'}
arg1=$1

## common functions

msg() {
	__f="## ${me}: $1: %s\\n" ; shift
	printf "${__f}" "with '${arg1}':" "$@" 1>&2
}
info()  { msg 'info' "$@" ; }
warn()  { msg 'Warn' "$@" ; }
err()   { msg 'ERROR' "$@" ; exit 1 ; }

assert() {
	[ $? -eq 0 ] || {
		if [ -z "${LOOSE}" ]
		then err "$@"
		else warn "$@"
		fi
	}
}

alias readbin="'${dir0}/readbin.sh'"

## $1 - struct
## $2 - field
## $3 - struct index in list (optional)
## NB: ensure that stdin is filled with data
dump_value() {
	: "${1:?}" "${2:?}"
	sed -En "/^$1${3:+\\.$3}\\.$2( .*|)/{s//\\1/;s/^ //;p}"
}

## $1 - struct
## $2 - field
## NB: ensure that stdin is filled with data
## output is formatted like "index field_data"
iterate_ary() {
	: "${1:?}" "${2:?}"
	sed -En "/^$1\\.(\\S)\\.$2( .*|)\$/{s//\\1\\2/;p}"
}

## $1 - value
## $2 - range start
## $3 - range end
in_range() {
	: "${1:?}" "${2:?}" "${3:?}"
	[ $(($1)) -ge $(($2)) ] && [ $(($1)) -le $(($3)) ]
}

## $1 - value
## $2 - reference value
hex_pad() {
	: "${1:?}" "${2:?}"
	__b=$(printf '%x' $(($2)) )
	__b=${#__b}
	__b=$((__b + (__b % 2) ))
	printf "0x%0${__b}x" "$1"
}

## $1 - value
## $2 - base value (string identifier)
## $3 - base value (integer)
base_value() {
	: "${1:?}" "${2:?}" "${3:?}"
	__a=$(($1 - $3))
	__a=$(hex_pad ${__a} $3)
	printf "%s %s" "$2" "${__a}"
}

## $1 - value
## $2 - bit(s)
test_bit() {
	: "${1:?}" "${2:?}"
	[ $(($1 & $2)) -eq $(($2)) ]
}

## ELF-related functions

## $1 - struct.field[:bits[:endian[:arch[:osabi[:abiver]]]]]
## $2 - value
elf_value() {
	: "${1:?}" "${2:?}"

	v=$(($2)) ; c='' p=''

	IFS=':' read -r _field _bits _endian _arch _osabi _abiver <<-EOF
	$1
	EOF

	p=none

	case "${_field}" in
	Elf_Ehdr.e_ident.ei_class)
		case "$v" in
		0) c=ELFCLASSNONE           ;;
		1) c=ELFCLASS32   ; p=32bit ;;
		2) c=ELFCLASS64   ; p=64bit ;;
		esac
	;;
	Elf_Ehdr.e_ident.ei_data)
		case "$v" in
		0) c=ELFDATANONE          ;;
		1) c=ELFDATA2LSB ; p=lsb  ;;
		2) c=ELFDATA2MSB ; p=msb  ;;
		esac
	;;
	Elf_Ehdr.e_ident.ei_version|Elf_Ehdr.e_version)
		case "$v" in
		0) c=EV_NONE             ;;
		1) c=EV_CURRENT ; p=1    ;;
		esac
	;;
	Elf_Ehdr.e_ident.ei_osabi)
		case "$v" in
		  0) c=ELFOSABI_SYSV       ; p=sysv       ;;
		  3) c=ELFOSABI_GNU        ; p=gnu        ;;
		 64) c=ELFOSABI_ARM_AEABI  ; p=arm_eabi   ;;
		 97) c=ELFOSABI_ARM        ; p=arm        ;;
		esac
	;;
	Elf_Ehdr.e_type)
		case "$v" in
		0) c=ET_NONE          ;;
		1) c=ET_REL  ; p=rel  ;;
		2) c=ET_EXEC ; p=exe  ;;
		3) c=ET_DYN  ; p=dyn  ;;
		4) c=ET_CORE ; p=core ;;
		esac

		ET_LOOS=0xFE00 ; ET_HIOS=0xFEFF
		if in_range $v ${ET_LOOS} ${ET_HIOS} ; then
			c=$(base_value $v ET_LOOS  ${ET_LOOS})
			p=$(base_value $v _os_spec ${ET_LOOS})
		fi

		ET_LOPROC=0xFF00 ; ET_HIPROC=0xFFFF
		if in_range $v ${ET_LOPROC} ${ET_HIPROC} ; then
			c=$(base_value $v ET_LOPROC  ${ET_LOPROC})
			p=$(base_value $v _proc_spec ${ET_LOPROC})
		fi
	;;
	Elf_Ehdr.e_machine)
		## script recongizes these arches but doesn't "support" them
		## head to "${ve_machine}" for details
		case "$v" in
		  0) c=EM_NONE              ;;
		  3) c=EM_386     ; p=i386  ;;
		  8) c=EM_MIPS    ; p=mips  ;;
		 20) c=EM_PPC     ; p=ppc   ;;
		 21) c=EM_PPC64   ; p=ppc64 ;;
		 22) c=EM_S390    ; p=s390  ;;
		 62) c=EM_X86_64  ; p=amd64 ;;
		183) c=EM_AARCH64 ; p=arm64 ;;
		243) c=EM_RISCV   ; p=riscv ;;
		247) c=EM_BPF     ; p=bpf   ;;
		esac

		v=$(printf '0x%x' $v)
		case "$v" in
		0xA390) c=EM_S390 ; p=s390 ;;
		esac
	;;
	Elf_Phdr.p_type)
		case "$v" in
		0) c=PT_NULL    ; p=null    ;;
		1) c=PT_LOAD    ; p=load    ;;
		2) c=PT_DYNAMIC ; p=dynamic ;;
		3) c=PT_INTERP  ; p=interp  ;;
		4) c=PT_NOTE    ; p=note    ;;
		5) c=PT_SHLIB   ; p=shlib   ;;
		6) c=PT_PHDR    ; p=phdr    ;;
		7) c=PT_TLS     ; p=tls     ;;
		esac

		PT_LOOS=0x60000000 ; PT_HIOS=0x6FFFFFFF
		if in_range $v ${PT_LOOS} ${PT_HIOS} ; then
			c=$(base_value $v PT_LOOS  ${PT_LOOS})
			p=$(base_value $v _os_spec ${PT_LOOS})

			PT_GNU_LO=$((PT_LOOS + 0x0474E550))
			PT_GNU_NUM=4
			PT_GNU_HI=$((PT_GNU_LO + PT_GNU_NUM - 1))
			if in_range $v ${PT_GNU_LO} ${PT_GNU_HI} ; then
				case $((v - PT_GNU_LO)) in
				0) c=PT_GNU_EH_FRAME ; p=gnu_eh_frame ;;
				1) c=PT_GNU_STACK    ; p=gnu_stack    ;;
				2) c=PT_GNU_RELRO    ; p=gnu_relro    ;;
				3) c=PT_GNU_PROPERTY ; p=gnu_property ;;
				esac
			fi

			case "${_osabi}" in
			gnu)
				PT_GNU_MBIND_LO=$((PT_LOOS + 0x0474E555))
				PT_GNU_MBIND_NUM=4096
				PT_GNU_MBIND_HI=$((PT_GNU_MBIND_LO + PT_GNU_MBIND_NUM - 1))

				if in_range $v ${PT_GNU_MBIND_LO} ${PT_GNU_MBIND_HI} ; then
					c=$(base_value $v PT_GNU_MBIND ${PT_GNU_MBIND_LO})
					p=$(base_value $v gnu_mbind    ${PT_GNU_MBIND_LO})
				fi
			;;
			esac
		fi

		PT_LOPROC=0x70000000 ; PT_HIPROC=0x7FFFFFFF
		if in_range $v ${PT_LOPROC} ${PT_HIPROC} ; then
			c=$(base_value $v PT_LOPROC  ${PT_LOPROC})
			p=$(base_value $v _proc_spec ${PT_LOPROC})

			## arch-specific code here
		fi
	;;
	Elf_Dyn.d_tag)
		case "$v" in
		 0) c=DT_NULL            ; p=null            ;;
		 1) c=DT_NEEDED          ; p=needed          ;;
		 2) c=DT_PLTRELSZ        ; p=pltrelsz        ;;
		 3) c=DT_PLTGOT          ; p=pltgot          ;;
		 4) c=DT_HASH            ; p=hash            ;;
		 5) c=DT_STRTAB          ; p=strtab          ;;
		 6) c=DT_SYMTAB          ; p=symtab          ;;
		 7) c=DT_RELA            ; p=rela            ;;
		 8) c=DT_RELASZ          ; p=relasz          ;;
		 9) c=DT_RELAENT         ; p=relaent         ;;
		10) c=DT_STRSZ           ; p=strsz           ;;
		11) c=DT_SYMENT          ; p=syment          ;;
		12) c=DT_INIT            ; p=init            ;;
		13) c=DT_FINI            ; p=fini            ;;
		14) c=DT_SONAME          ; p=soname          ;;
		15) c=DT_RPATH           ; p=rpath           ;;
		16) c=DT_SYMBOLIC        ; p=symbolic        ;;
		17) c=DT_REL             ; p=rel             ;;
		18) c=DT_RELSZ           ; p=relsz           ;;
		19) c=DT_RELENT          ; p=relent          ;;
		20) c=DT_PLTREL          ; p=pltrel          ;;
		21) c=DT_DEBUG           ; p=debug           ;;
		22) c=DT_TEXTREL         ; p=textrel         ;;
		23) c=DT_JMPREL          ; p=jmprel          ;;
		24) c=DT_BIND_NOW        ; p=bind_now        ;;
		25) c=DT_INIT_ARRAY      ; p=init_array      ;;
		26) c=DT_FINI_ARRAY      ; p=fini_array      ;;
		27) c=DT_INIT_ARRAYSZ    ; p=init_arraysz    ;;
		28) c=DT_FINI_ARRAYSZ    ; p=fini_arraysz    ;;
		29) c=DT_RUNPATH         ; p=runpath         ;;
		30) c=DT_FLAGS           ; p=flags           ;;
		32) c=DT_PREINIT_ARRAY   ; p=preinit_array   ;;
		33) c=DT_PREINIT_ARRAYSZ ; p=preinit_arraysz ;;
		34) c=DT_SYMTAB_SHNDX    ; p=symtab_shndx    ;;
		esac

		DT_LOOS=0x6000000D ; DT_HIOS=0x6FFFF000
		if in_range $v ${DT_LOOS} ${DT_HIOS} ; then
			c=$(base_value $v DT_LOOS  ${DT_LOOS})
			p=$(base_value $v _os_spec ${DT_LOOS})
		fi

		## top to bottom allocation!
		DT_VALRNGHI=0x6FFFFDFF
		# DT_VALNUM=12 ; DT_VALRNGLO=$((DT_VALRNGHI - DT_VALNUM + 1))
		DT_VALRNGLO=0x6FFFFD00
		if in_range $v ${DT_VALRNGLO} ${DT_VALRNGHI} ; then
			_v=$((DT_VALRNGHI - v))
			c="DT_VALTAG ${_v}"
			p="_valtag ${_v}"

			case "${_v}" in
			 0) c=DT_SYMINENT       ; p=syminent       ;;
			 1) c=DT_SYMINSZ        ; p=syminsz        ;;
			 2) c=DT_POSFLAG_1      ; p=posflag_1      ;;
			 3) c=DT_FEATURE_1      ; p=feature_1      ;;
			 4) c=DT_MOVESZ         ; p=movesz         ;;
			 5) c=DT_MOVEENT        ; p=moveent        ;;
			 6) c=DT_PLTPADSZ       ; p=pltpadsz       ;;
			 7) c=DT_CHECKSUM       ; p=checksum       ;;
			 8) c=DT_GNU_LIBLISTSZ  ; p=gnu_liblistsz  ;;
			 9) c=DT_GNU_CONFLICTSZ ; p=gnu_conflictsz ;;
			10) c=DT_GNU_PRELINKED  ; p=gnu_prelinked  ;;
			11) c=DT_GNU_FLAGS_1    ; p=gnu_flags_1    ;;
			esac
		fi

		## top to bottom allocation!
		DT_ADDRRNGHI=0x6FFFFEFF
		# DT_ADDRNUM=11 ; DT_ADDRRNGLO=$((DT_ADDRRNGHI - DT_ADDRNUM + 1))
		DT_ADDRRNGLO=0x6FFFFE00
		if in_range $v ${DT_ADDRRNGLO} ${DT_ADDRRNGHI} ; then
			_v=$((DT_ADDRRNGHI - v))
			c="DT_ADDRTAG ${_v}"
			p="_addrtag ${_v}"

			case "${_v}" in
			 0) c=DT_SYMINFO      ; p=syminfo      ;;
			 1) c=DT_MOVETAB      ; p=movetab      ;;
			 2) c=DT_PLTPAD       ; p=pltpad       ;;
			 3) c=DT_AUDIT        ; p=audit        ;;
			 4) c=DT_DEPAUDIT     ; p=depaudit     ;;
			 5) c=DT_CONFIG       ; p=config       ;;
			 6) c=DT_GNU_LIBLIST  ; p=gnu_liblist  ;;
			 7) c=DT_GNU_CONFLICT ; p=gnu_conflict ;;
			 8) c=DT_TLSDESC_GOT  ; p=tlsdesc_got  ;;
			 9) c=DT_TLSDESC_PLT  ; p=tlsdesc_plt  ;;
			10) c=DT_GNU_HASH     ; p=gnu_hash     ;;
			esac
		fi

		## top to bottom allocation!
		DT_VERSIONHI=0x6FFFFFFF
		DT_VERSIONTAGNUM=16
		DT_VERSIONLO=$((DT_VERSIONHI - DT_VERSIONTAGNUM + 1))
		if in_range $v ${DT_VERSIONLO} ${DT_VERSIONHI} ; then
			_v=$((DT_VERSIONHI - v))
			c="DT_VERSIONTAG ${_v}"
			p="_versiontag ${_v}"

			case "${_v}" in
			 0) c=DT_VERNEEDNUM ; p=verneednum ;;
			 1) c=DT_VERNEED    ; p=verneed    ;;
			 2) c=DT_VERDEFNUM  ; p=verdefnum  ;;
			 3) c=DT_VERDEF     ; p=verdef     ;;
			 4) c=DT_FLAGS_1    ; p=flags_1    ;;
			 5) c=DT_RELCOUNT   ; p=relcount   ;;
			 6) c=DT_RELACOUNT  ; p=relacount  ;;
			15) c=DT_VERSYM     ; p=versym     ;;
			esac
		fi

		DT_LOPROC=0x70000000 ; DT_HIPROC=0x7FFFFFFF
		if in_range $v ${DT_LOPROC} ${DT_HIPROC} ; then
			c=$(base_value $v DT_LOPROC  ${DT_LOPROC})
			p=$(base_value $v _proc_spec ${DT_LOPROC})

			## top to bottom allocation!
			## NB: nobody knows why Sun put these sections
			##     in proc-specific range ("because we CAN", lol)
			DT_EXTRAHI=0x7FFFFFFF
			DT_EXTRANUM=3
			DT_EXTRALO=$((DT_EXTRAHI - DT_EXTRANUM + 1))
			if in_range $v ${DT_EXTRALO} ${DT_EXTRAHI} ; then
				_v=$((DT_EXTRAHI - v))
				c="DT_EXTRATAG ${_v}"
				p="_extratag ${_v}"

				case "${_v}" in
				0) c=DT_FILTER    ; p=filter    ;;
				1) c=DT_USED      ; p=used      ;;
				2) c=DT_AUXILIARY ; p=auxiliary ;;
				esac
			fi

			case "${_arch}" in
			ppc)
				case $((v - DT_LOPROC)) in
				0) c=DT_PPC_GOT ; p=got ;;
				1) c=DT_PPC_OPT ; p=opt ;;
				esac
			;;
			ppc64)
				case $((v - DT_LOPROC)) in
				0) c=DT_PPC64_GLINK ; p=got   ;;
				1) c=DT_PPC64_OPD   ; p=opd   ;;
				2) c=DT_PPC64_OPDSZ ; p=opdsz ;;
				3) c=DT_PPC64_OPT   ; p=opt   ;;
				esac
			;;
			esac
		fi
	;;
	*) err "unknown field name: '${_field}'" ;;
	esac

	[ -n "$c" ] && [ -n "$p" ]
	assert "unknown value '$2' for '$1'"

	[ "${OUT}" = c ] && p=$c
	echo $p
}

## $1 - struct.field[:bits[:endian[:arch[:osabi[:abiver]]]]]
## $2 - value
## $3 - value kind (any non-empty string)
elf_value_expect() {
	: "${1:?}" "${2:?}" "${3:?}"

	v=$2 ; e=''

	IFS=':' read -r _field _bits _endian _arch _osabi _abiver <<-EOF
	$1
	EOF

	case "${_field}" in
	Elf_Ehdr.e_ident.ei_mag) e='7f454c46' ;;
	Elf_Ehdr.e_ident.ei_pad) e='00000000000000' ;;
	Elf_Ehdr.e_ehsize)
		v=$((v))
		case "${_bits}" in
		32) e=52 ;;
		64) e=64 ;;
		esac
	;;
	Elf_Ehdr.e_phentsize)
		v=$((v))
		case "${_bits}" in
		32) e=32 ;;
		64) e=56 ;;
		esac
	;;
	Elf_Ehdr.e_shentsize)
		v=$((v))
		case "${_bits}" in
		32) e=40 ;;
		64) e=64 ;;
		esac
	;;
	*) err "unknown field name: '${_field}'" ;;
	esac

	[ -n "$e" ]
	LOOSE='' assert "unhandled value for '$1'"

	[ "$e" = "$v" ]
	assert "$3 mismatch: expected '$e', got '$2'"
}

## $1 - value
## $2 - "c-value" accumulator
## $3 - "p-value" accumulator
## $4 - flag
## $5 - "c-value" flag
## $6 - "p-value" flag
elf_xflag() {
	: "${1:?}" "${4:?}" "${5:?}" "${6:?}"

	_v=$1 ; _c="$2" ; _p="$3" ; _f=$4
	if test_bit ${_v} ${_f} ; then
		_c="${_c}${_c:+ }$5"
		_p="${_p}${_p:+ }$6"
		_v=$((_v & ~(_f) ))
	fi
	printf '%s|%s|%s' "${_v}" "${_c}" "${_p}"
}

## $1 - struct.field[:bits[:endian[:arch[:osabi[:abiver]]]]]
## $2 - value
elf_flag() {
	: "${1:?}" "${2:?}"

	v=$(($2)) ; c='' p=''

	IFS=':' read -r _field _bits _endian _arch _osabi _abiver <<-EOF
	$1
	EOF

	if [ $(($2)) -eq 0 ] ; then
		c='0x00' ; p=none

		[ "${OUT}" = c ] && p=$c
		echo $p
		return
	fi

	case "${_field}" in
	Elf_Ehdr.e_flags)
		case "${_arch}" in
		mips)
			EF_MIPS_MACH=0x00FF0000
			_v=$(( (v & EF_MIPS_MACH) >> 16))
			_v=$(printf '0x%02x' ${_v})
			_c='' ; _p=''
			case "${_v}" in
			0x00) ;;
			0x81) _c=EF_MIPS_MACH_3900    ; _p=cpu_3900    ;;
			0x82) _c=EF_MIPS_MACH_4010    ; _p=cpu_4010    ;;
			0x83) _c=EF_MIPS_MACH_4100    ; _p=cpu_4100    ;;
			0x85) _c=EF_MIPS_MACH_4650    ; _p=cpu_4650    ;;
			0x87) _c=EF_MIPS_MACH_4120    ; _p=cpu_4120    ;;
			0x88) _c=EF_MIPS_MACH_4111    ; _p=cpu_4111    ;;
			0x8A) _c=EF_MIPS_MACH_SB1     ; _p=cpu_sb1     ;;
			0x8B) _c=EF_MIPS_MACH_OCTEON  ; _p=cpu_octeon  ;;
			0x8C) _c=EF_MIPS_MACH_XLR     ; _p=cpu_xlr     ;;
			0x8D) _c=EF_MIPS_MACH_OCTEON2 ; _p=cpu_octeon2 ;;
			0x8E) _c=EF_MIPS_MACH_OCTEON3 ; _p=cpu_octeon3 ;;
			0x91) _c=EF_MIPS_MACH_5400    ; _p=cpu_5400    ;;
			0x92) _c=EF_MIPS_MACH_5900    ; _p=cpu_5900    ;;
			0x93) _c=EF_MIPS_MACH_IAMR2   ; _p=cpu_iamr2   ;;
			0x98) _c=EF_MIPS_MACH_5500    ; _p=cpu_5500    ;;
			0x99) _c=EF_MIPS_MACH_9000    ; _p=cpu_9000    ;;
			0xA0) _c=EF_MIPS_MACH_LS2E    ; _p=cpu_ls2e    ;;
			0xA1) _c=EF_MIPS_MACH_LS2F    ; _p=cpu_ls2f    ;;
			0xA2) _c=EF_MIPS_MACH_GS464   ; _p=cpu_gs464   ;;
			0xA3) _c=EF_MIPS_MACH_GS464E  ; _p=cpu_gs464e  ;;
			0xA4) _c=EF_MIPS_MACH_GS264E  ; _p=cpu_gs264e  ;;
			*)
				_c=$(hex_pad $((_v << 16)) 0x10000000)
				_p="_cpu_${_v}"
			;;
			esac
			c=$(echo $c ${_c}) ; p=$(echo $p ${_p})
			v=$((v & ~EF_MIPS_MACH))


			EF_MIPS_ARCH=0xF0000000
			_v=$(( (v & EF_MIPS_ARCH) >> 28))
			_v=$(printf '0x%02x' ${_v})
			_c='' ; _p=''
			case "${_v}" in
			0x00) _c=EF_MIPS_ARCH_1    ; _p=isa_mips1    ;;
			0x01) _c=EF_MIPS_ARCH_2    ; _p=isa_mips2    ;;
			0x02) _c=EF_MIPS_ARCH_3    ; _p=isa_mips3    ;;
			0x03) _c=EF_MIPS_ARCH_4    ; _p=isa_mips4    ;;
			0x04) _c=EF_MIPS_ARCH_5    ; _p=isa_mips5    ;;
			0x05) _c=EF_MIPS_ARCH_32   ; _p=isa_mips32   ;;
			0x06) _c=EF_MIPS_ARCH_64   ; _p=isa_mips64   ;;
			0x07) _c=EF_MIPS_ARCH_32R2 ; _p=isa_mips32r2 ;;
			0x08) _c=EF_MIPS_ARCH_64R2 ; _p=isa_mips64r2 ;;
			0x09) _c=EF_MIPS_ARCH_32R6 ; _p=isa_mips32r6 ;;
			0x0A) _c=EF_MIPS_ARCH_64R6 ; _p=isa_mips64r6 ;;
			*)
				_c=$(hex_pad $((_v << 28)) 0x10000000)
				_p="_isa_${_v}"
			;;
			esac
			c=$(echo $c ${_c}) ; p=$(echo $p ${_p})
			v=$((v & ~EF_MIPS_ARCH))


			EF_MIPS_ABI=0x0000F000
			_v=$(( (v & EF_MIPS_MACH) >> 12 ))
			_v=$(printf '0x%02x' ${_v})
			_c='' ; _p=''
			case "${_v}" in
			0x00) ;;
			0x01) _c=EF_MIPS_ABI_O32    ; _p=abi_o32    ;;
			0x02) _c=EF_MIPS_ABI_O64    ; _p=abi_o64    ;;
			0x03) _c=EF_MIPS_ABI_EABI32 ; _p=abi_eabi32 ;;
			0x04) _c=EF_MIPS_ABI_EABI64 ; _p=abi_eabi64 ;;
			*)
				_c=$(hex_pad $((_v << 12)) 0x10000000)
				_p="_abi_${_v}"
			;;
			esac
			c=$(echo $c ${_c}) ; p=$(echo $p ${_p})
			v=$((v & ~EF_MIPS_ABI))


			while read -r f_v f_c f_p ; do
				IFS='|' read -r v c p <<-EOF
				$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
				EOF
			done <<-EOF
			$((1 <<  0))  EF_MIPS_NOREORDER      noreorder
			$((1 <<  1))  EF_MIPS_PIC            pic
			$((1 <<  2))  EF_MIPS_CPIC           cpic
			$((1 <<  3))  EF_MIPS_XGOT           xgot
			$((1 <<  4))  EF_MIPS_UCODE          ucode
			$((1 <<  5))  EF_MIPS_ABI2           abi2
			$((1 <<  6))  EF_MIPS_ABI_ON32       abi_on32
			$((1 <<  8))  EF_MIPS_32BITMODE      32bitmode
			$((1 <<  9))  EF_MIPS_FP64           fp64
			$((1 << 10))  EF_MIPS_NAN2008        nan2008
			EOF


			while read -r f_v f_c f_p ; do
				IFS='|' read -r v c p <<-EOF
				$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
				EOF
			done <<-EOF
			$((1 << 25))  EF_MIPS_MICROMIPS      ase_micromips
			$((1 << 26))  EF_MIPS_ARCH_ASE_M16   ase_mips16
			$((1 << 27))  EF_MIPS_ARCH_ASE_MDMX  ase_mdmx
			EOF
			EF_MIPS_ARCH_ASE=0x0F000000
			_v=$(( (v & EF_MIPS_ARCH_ASE) >> 24))
			_c='' ; _p=''
			if [ ${_v} -ne 0 ] ; then
				_c=$(hex_pad $((_v << 24)) 0x10000000)
				_v=$(printf '0x%02x' ${_v})
				_p="_ase_${_v}"
			fi
			c=$(echo $c ${_c}) ; p=$(echo $p ${_p})
		;;
		ppc)
			while read -r f_v f_c f_p ; do
				IFS='|' read -r v c p <<-EOF
				$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
				EOF
			done <<-EOF
			$((1 << 31))  EF_PPC_EMB              emb
			$((1 << 12))  EF_PPC_RELOCATABLE      relocatable
			$((1 << 15))  EF_PPC_RELOCATABLE_LIB  relocatable_lib
			EOF
		;;
		esac
	;;
	Elf_Phdr.p_flags)
		## flags are sorted in human-preferred order :)
		while read -r f_v f_c f_p ; do
			IFS='|' read -r v c p <<-EOF
			$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
			EOF
		done <<-EOF
		$((1 << 2))  PF_R  read
		$((1 << 1))  PF_W  write
		$((1 << 0))  PF_X  execute
		EOF
	;;
	Elf_Dyn.d_val+feature_1)
		while read -r f_v f_c f_p ; do
			IFS='|' read -r v c p <<-EOF
			$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
			EOF
		done <<-EOF
		$((1 << 0))  DTF_1_PARINIT  parinit
		$((1 << 1))  DTF_1_CONFEXP  confexp
		EOF
	;;
	Elf_Dyn.d_val+posflag_1)
		while read -r f_v f_c f_p ; do
			IFS='|' read -r v c p <<-EOF
			$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
			EOF
		done <<-EOF
		$((1 << 0))  DF_P1_LAZYLOAD   lazyload
		$((1 << 1))  DF_P1_GROUPPERM  groupperm
		EOF
	;;
	Elf_Dyn.d_val+flags_1)
		while read -r f_v f_c f_p ; do
			IFS='|' read -r v c p <<-EOF
			$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
			EOF
		done <<-EOF
		$((1 <<  0))  DF_1_NOW         now
		$((1 <<  1))  DF_1_GLOBAL      global
		$((1 <<  2))  DF_1_GROUP       group
		$((1 <<  3))  DF_1_NODELETE    nodelete
		$((1 <<  4))  DF_1_LOADFLTR    loadfltr
		$((1 <<  5))  DF_1_INITFIRST   initfirst
		$((1 <<  6))  DF_1_NOOPEN      noopen
		$((1 <<  7))  DF_1_ORIGIN      origin
		$((1 <<  8))  DF_1_DIRECT      direct
		$((1 <<  9))  DF_1_TRANS       trans
		$((1 << 10))  DF_1_INTERPOSE   interpose
		$((1 << 11))  DF_1_NODEFLIB    nodeflib
		$((1 << 12))  DF_1_NODUMP      nodump
		$((1 << 13))  DF_1_CONFALT     confalt
		$((1 << 14))  DF_1_ENDFILTEE   endfiltee
		$((1 << 15))  DF_1_DISPRELDNE  dispreldne
		$((1 << 16))  DF_1_DISPRELPND  disprelpnd
		$((1 << 17))  DF_1_NODIRECT    nodirect
		$((1 << 18))  DF_1_IGNMULDEF   ignmuldef
		$((1 << 19))  DF_1_NOKSYMS     noksyms
		$((1 << 20))  DF_1_NOHDR       nohdr
		$((1 << 21))  DF_1_EDITED      edited
		$((1 << 22))  DF_1_NORELOC     noreloc
		$((1 << 23))  DF_1_SYMINTPOSE  symintpose
		$((1 << 24))  DF_1_GLOBAUDIT   globaudit
		$((1 << 25))  DF_1_SINGLETON   singleton
		$((1 << 26))  DF_1_STUB        stub
		$((1 << 27))  DF_1_PIE         pie
		$((1 << 28))  DF_1_KMOD        kmod
		$((1 << 29))  DF_1_WEAKFILTER  weakfilter
		$((1 << 30))  DF_1_NOCOMMON    nocommon
		EOF
	;;
	Elf_Dyn.d_val+gnu_flags_1)
		while read -r f_v f_c f_p ; do
			IFS='|' read -r v c p <<-EOF
			$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
			EOF
		done <<-EOF
		$((1 << 0))  DF_GNU_1_UNIQUE  unique
		EOF
	;;
	Elf_Dyn.d_val+flags)
		while read -r f_v f_c f_p ; do
			IFS='|' read -r v c p <<-EOF
			$(elf_xflag $v "$c" "$p" ${f_v} ${f_c} ${f_p})
			EOF
		done <<-EOF
		$((1 << 0))  DF_ORIGIN      origin
		$((1 << 1))  DF_SYMBOLIC    symbolic
		$((1 << 2))  DF_TEXTREL     textrel
		$((1 << 3))  DF_BIND_NOW    bind_now
		$((1 << 4))  DF_STATIC_TLS  static_tls
		EOF
	;;
	*) err "unknown field name: '${_field}'" ;;
	esac

	if [ $v -ne 0 ] ; then
		[ -n "$c" ] && [ -n "$p" ]
		assert "unknown value '$2' for '$1'"

		v=$(hex_pad $v $2)
		c="$c${c:+' '}$v"
		p="$p${p:+' '}$v"
	fi

	[ "${OUT}" = c ] && p=$c
	echo $p
}

## required for further reading ptr-based values and/or offsets
decode_elfehdr_eiclass() {
	case "$1" in
	none) err "incorrect ELF class: '$1'" ;;
	32bit) echo 32 ;;
	64bit) echo 64 ;;
	*) err "unsupported ELF class: ${2:-$1}" ;;
	esac
}

## required for further reading values longer than 1 byte :)
decode_elfehdr_eidata() {
	case "$1" in
	none) err "incorrect ELF data order: '$1'" ;;
	lsb|msb) echo $1 ;;
	*) err "unsupported ELF data order: ${2:-$1}" ;;
	esac
}

## $1 - ELF file
read_elf_header() {
	: "${1:?}"

	## read ElfXX_Ehdr.e_ident
	layout='4:b 1:5:x 7:b'
	d=$(readbin "i:$1" ${layout})
	assert "unable to read data: '${layout}'"

	struct='Elf_Ehdr.e_ident'
	read -r ei_mag ei_class ei_data ei_version ei_osabi ei_abiversion ei_pad <<-EOF
	$d
	EOF

	## parse ElfXX_Ehdr.e_ident.ei_mag[4]
	elf_value_expect "${struct}.ei_mag" "${ei_mag}" \
	"ELF signature"

	## parse ElfXX_Ehdr.e_ident.ei_class
	vei_class=$(elf_value ${struct}.ei_class ${ei_class})
	bits=$(decode_elfehdr_eiclass ${vei_class} ${ei_class})
	ptr_size=$((bits / 8))

	## parse ElfXX_Ehdr.e_ident.ei_data
	vei_data=$(elf_value ${struct}.ei_data ${ei_data})
	endian=$(decode_elfehdr_eidata ${vei_data} ${ei_data})

	## parse ElfXX_Ehdr.e_ident.ei_version
	vei_version=$(elf_value ${struct}.ei_version ${ei_version})
	case "${vei_version}" in
	none) err "incorrect ELF header version: '${vei_version}'" ;;
	1) ;;
	*) err "unsupported ELF header version: ${ei_version}" ;;
	esac

	## parse ElfXX_Ehdr.e_ident.ei_osabi
	vei_osabi=$(elf_value ${struct}.ei_osabi ${ei_osabi})
	case "${vei_osabi}" in
	sysv|gnu) ;;
	*) err "unsupported ELF OS ABI: ${vei_osabi}" ;;
	esac

	## parse ElfXX_Ehdr.e_ident.ei_pad[7]
	LOOSE=1 elf_value_expect "${struct}.ei_pad" "${ei_pad}" \
	"ELF header padding"

	## read ElfXX_Ehdr past ElfXX_Ehdr.e_ident
	layout="p:16 x 2:2 4 ${ptr_size} ${ptr_size}:2:d 4 2:6:d"
	d=$(readbin "i:$1" ${endian} ${layout})
	assert "unable to read data: '${layout}'"

	struct='Elf_Ehdr'
	read -r e_type e_machine e_version e_entry e_phoff e_shoff e_flags e_ehsize e_phentsize e_phnum e_shentsize e_shnum e_shstrndx <<-EOF
	$d
	EOF

	## parse ElfXX_Ehdr.e_type
	ve_type=$(elf_value ${struct}.e_type ${e_type})
	case "${ve_type}" in
	none) err "incorrect ELF file type: '${ve_type}'" ;;
	rel|exe|dyn) ;;
	*) err "unsupported ELF file type: ${ve_type:-${e_type}}" ;;
	esac

	## parse ElfXX_Ehdr.e_machine
	ve_machine=$(elf_value ${struct}.e_machine ${e_machine})
	case "${ve_machine}" in
	none) err "incorrect ELF arch type: '${ve_machine}'" ;;
	i386|amd64|mips) ;;
	*) err "unsupported ELF arch type: ${ve_machine:-${e_machine}}" ;;
	esac

	## parse ElfXX_Ehdr.e_version
	ve_version=$(elf_value ${struct}.e_version ${e_version})
	case "${ve_version}" in
	none) err "incorrect ELF format version: '${ve_version}'" ;;
	1) ;;
	*) err "unsupported ELF format version: ${e_version}" ;;
	esac

	## parse ElfXX_Ehdr.e_flags
	ve_flags=$(elf_flag "${struct}.e_flags:::${ve_machine}" ${e_flags})

	## parse ElfXX_Ehdr.e_ehsize
	elf_value_expect "${struct}.e_ehsize:${bits}" "${e_ehsize}" \
	"ELF header size"

	## parse ElfXX_Ehdr.e_phentsize
	elf_value_expect "${struct}.e_phentsize:${bits}" "${e_phentsize}" \
	"ELF program header entry size"

	## parse ElfXX_Ehdr.e_shentsize
	elf_value_expect "${struct}.e_shentsize:${bits}" "${e_shentsize}" \
	"ELF program header entry size"

	## output values
	sed -E 's/^/Elf_Ehdr.e_ident./' <<-EOF
	ei_class ${vei_class}
	ei_data ${vei_data}
	ei_version ${vei_version}
	ei_osabi ${vei_osabi}
	ei_abiversion ${ei_abiversion}
	EOF
	sed -E 's/^/Elf_Ehdr./' <<-EOF
	e_type ${ve_type}
	e_machine ${ve_machine}
	e_version ${ve_version}
	e_entry ${e_entry}
	e_phoff ${e_phoff}
	e_shoff ${e_shoff}
	e_flags ${ve_flags}
	e_ehsize ${e_ehsize}
	e_phentsize ${e_phentsize}
	e_phnum ${e_phnum}
	e_shentsize ${e_shentsize}
	e_shnum ${e_shnum}
	e_shstrndx ${e_shstrndx}
	EOF
	echo
}

## $1 - ELF file
## $2 - Elf_Ehdr dump
read_elf_pht() {
	: "${1:?}" "${2:?}"

	ei_class=$(dump_value Elf_Ehdr e_ident.ei_class < "$2")
	bits=$(decode_elfehdr_eiclass "${ei_class}")

	ei_data=$(dump_value Elf_Ehdr e_ident.ei_data < "$2")
	endian=$(decode_elfehdr_eidata "${ei_data}")

	e_phoff=$(dump_value Elf_Ehdr e_phoff < "$2")
	e_phnum=$(dump_value Elf_Ehdr e_phnum < "$2")
	e_phentsize=$(dump_value Elf_Ehdr e_phentsize < "$2")

	if [ ${e_phnum} -eq 0 ] ; then
		info "program header table is empty"
		return
	fi

	f_size=$(stat -L -c %s "$1")
	[ $((e_phoff + e_phnum * e_phentsize)) -le ${f_size} ]
	assert "ELF program header table exceeds file size"

	struct='Elf_Phdr'
	## we don't use ptr_size semantics because struct layouts
	## differ for 32 and 64 bits code
	layout=''
	case "${bits}" in
	32) layout="4:x 4 4:2:x 4:2 4:x 4" ;;
	64) layout="4:2:x 8 8:2:x 8:3" ;;
	esac

	i=0 ; while [ $i -lt ${e_phnum} ] ; do
		offset=$((e_phoff + i * e_phentsize))
		d=$(readbin "i:$1" ${endian} p:${offset} ${layout})
		assert "unable to read data: 'p:${offset} ${layout}'"

		case "${bits}" in
		32)
			read -r p_type p_offset p_vaddr p_paddr p_filesz p_memsz p_flags p_align <<-EOF
			$d
			EOF
		;;
		64)
			read -r p_type p_flags p_offset p_vaddr p_paddr p_filesz p_memsz p_align <<-EOF
			$d
			EOF
		;;
		esac

		## parse ElfXX_Phdr.p_type
		vp_type=$(elf_value ${struct}.p_type ${p_type})
		vp_type=${vp_type:-${p_type}}

		## parse ElfXX_Phdr.p_flags
		vp_flags=$(elf_flag ${struct}.p_flags ${p_flags})

		sed -E "s/^/Elf_Phdr.$i./" <<-EOF
		p_type ${vp_type}
		p_flags ${vp_flags}
		p_offset ${p_offset}
		p_align ${p_align}
		p_filesz ${p_filesz}
		p_memsz ${p_memsz}
		p_paddr ${p_paddr}
		p_vaddr ${p_vaddr}
		EOF
		echo

		i=$((i + 1))
	done
}

## $1 - ELF file
## $2 - Elf_Ehdr dump
## $3 - Elf_Phdr dump
read_elf_dt() {
	: "${1:?}" "${2:?}" "${3:?}"

	dt_idx='' ; k=0
	while read -r i v ; do
		[ "$v" = dynamic ] || continue
		dt_idx="${dt_idx}${dt_idx:+ }$i"
		k=$((k+1))
	done <<-EOF
	$(iterate_ary Elf_Phdr p_type < "$3")
	EOF

	case "$k" in
	0) info 'dynamic section was not found' ; return ;;
	1) ;;
	*) err "more than one ($k) dynamic section" ;;
	esac

	ei_class=$(dump_value Elf_Ehdr e_ident.ei_class < "$2")
	bits=$(decode_elfehdr_eiclass "${ei_class}")
	ptr_size=$((bits / 8))

	ei_data=$(dump_value Elf_Ehdr e_ident.ei_data < "$2")
	endian=$(decode_elfehdr_eidata "${ei_data}")

	dt_offset=$(dump_value Elf_Phdr p_offset ${dt_idx} < "$3")
	dt_size=$(dump_value Elf_Phdr p_filesz ${dt_idx} < "$3")

	## TODO: validate/reassign ${dt_offset} and ${dt_size}
	## as readelf does in process_program_headers()

	if [ ${dt_offset} -eq 0 ] ; then
		info 'dynamic section was not found'
		return
	fi

	struct='Elf_Dyn'
	dt_entsize=$((ptr_size*2))
	layout="${ptr_size}:2:x"

	if [ ${dt_size} -eq 0 ] ; then
		info 'dynamic section is empty'
		return
	fi

	[ ${dt_size} -ge ${dt_entsize} ]
	assert "dynamic section is too short (${dt_size}<${dt_entsize})"

	[ $((dt_size % dt_entsize)) -eq 0 ]
	assert "ELF dynamic section violates struct size boundaries"

	f_size=$(stat -L -c %s "$1")
	[ $((dt_offset + dt_size)) -le ${f_size} ]
	assert "ELF dynamic section exceeds file size"

	dt_count=$((dt_size / dt_entsize))
	i=0 ; while [ $i -lt ${dt_count} ] ; do
		offset=$((dt_offset + i * dt_entsize))
		d=$(readbin "i:$1" ${endian} p:${offset} ${layout})
		assert "unable to read data: 'p:${offset} ${layout}'"

		read -r d_tag d_val <<-EOF
		$d
		EOF

		## parse ElfXX_Dyn.d_tag
		vd_tag=$(elf_value ${struct}.d_tag ${d_tag})

		## handle ElfXX_Dyn.d_val
		vd_val=${d_val}
		case "${vd_tag}" in
		feature_1|posflag_1|flags_1|gnu_flags_1|flags)
			vd_val=$(elf_flag "${struct}.d_val+${vd_tag}" ${d_val})
		;;
		## plain (unsigned) integer below:
		pltrelsz|relasz|strsz|relsz|relaent|syment|relent|pltpadsz)
			vd_val=$((d_val))
		;;
		moveent|movesz|init_arraysz|fini_arraysz|gnu_conflictsz|gnu_liblistsz)
			vd_val=$((d_val))
		;;
		verdefnum|verneednum|relacount|relcount)
			vd_val=$((d_val))
		;;
		gnu_prelinked)
			## actually it's UNIX timestamp in UTC
			vd_val=$((d_val))
		;;
		esac

		sed -E "s/^/Elf_Dyn.$i./" <<-EOF
		d_tag ${vd_tag}
		d_val ${vd_val}
		EOF
		echo

		i=$((i + 1))

		if [ "${vd_tag}" = null ] ; then
			[ $i -eq ${dt_count} ] && continue
			[ "${extra_after_null}" = 1 ] && continue

			warn "there are extra $((dt_count - i)) entry(-ies) after DT_NULL"
			extra_after_null=1
		fi
	done
}

## main

unset OUT LOOSE

w=$(mktemp -d) ; : "${w:?}"

echo 1 > "$w/_r"
( read_elf_header "$1" ; echo $? > "$w/_r" ) | tee "$w/ehdr"
_ret=$(cat "$w/_r") ; if [ "${_ret}" != 0 ] ; then
	rm -rf "$w"
	exit 1
fi

echo 1 > "$w/_r"
( read_elf_pht "$1" "$w/ehdr" ; echo $? > "$w/_r" ) | tee "$w/phdr"
_ret=$(cat "$w/_r") ; if [ "${_ret}" != 0 ] ; then
	rm -rf "$w"
	exit 1
fi

echo 1 > "$w/_r"
( read_elf_dt "$1" "$w/ehdr" "$w/phdr" ; echo $? > "$w/_r" ) | tee "$w/dt"
_ret=$(cat "$w/_r") ; if [ "${_ret}" != 0 ] ; then
	rm -rf "$w"
	exit 1
fi

rm -rf "$w"
exit 0
