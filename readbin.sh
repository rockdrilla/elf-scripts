#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# (c) 2021, Konstantin Demin

set -f

## TODO: subject to TOCTOU?

## global variables

me=${0##*/}

## streams
f_in=
f_out=

## input stream offset
i_off=0

## stream modes
## input mode: exact bytes or at most bytes
i_exact=1
## output mode: truncate or append to output
o_trunc=

## data mode (endianness)
i_mode=msb

## value kind
## b - "binary" stream
## u - unsigned decimal integer
## d - signed decimal integer
## o - octal integer
## x - hexadecimal integer
## f - floating-point value
## s - string
i_kind=u

## value separator
## s - space
## t - tab
## n - newline
o_sep=s

## is separator needed before value?
o_needsep=0

## common functions

msg() {
	__msg__f="## ${me}: $1: %s\\n" ; shift
	printf "${__msg__f}" "$@" 1>&2
}
info()  { msg 'info' "$@" ; }
warn()  { msg 'Warn' "$@" ; }
err()   { msg 'ERROR' "$@" ; exit 1 ; }

## $1 - file name
get_ftype() {
	stat -c '%A' "$1" | cut -c 1
}

## $1 - file name
is_tty() {
	get_ftype "$1" | grep -Fq 'c'
}

## $1 - io type ("i" for "input", "o" for "output")
## $2 - file name
f_demangle() {
	case "$1" in
	i|o) ;;
	*) err "f_demangle: wrong function mode '$1'" ;;
	esac

	case "$2" in
	/proc/self/fd/0|/dev/fd/0|/dev/stdin)
		case "$1" in
		i) echo /dev/stdin ;;
		o) err "refusing to write into 'read' stream '$2'" ;;
		esac
	;;
	/proc/self/fd/1|/dev/fd/1|/dev/stdout)
		case "$1" in
		o) echo /dev/stdout ;;
		i) err "refusing to read from 'write' stream '$2'" ;;
		esac
	;;
	-)
		case "$1" in
		i) echo /dev/stdin ;;
		o) echo /dev/stdout ;;
		esac
	;;
	*)
		__f_demangle__p=
		__f_demangle__tty=
		## try get own tty (if any)
		if [ -t 0 ] ; then
			for __f_demangle__p in /proc/self/fd/0 /dev/fd/0 /dev/stdin ; do
				__f_demangle__p=$(readlink -e "${__f_demangle__p}")
				[ -n "${__f_demangle__p}" ] || continue
				is_tty "${__f_demangle__p}" || continue
				__f_demangle__tty="${__f_demangle__p}" ; break
			done
		elif [ -t 1 ] ; then
			for __f_demangle__p in /proc/self/fd/1 /dev/fd/1 /dev/stdout ; do
				__f_demangle__p=$(readlink -e "${__f_demangle__p}")
				[ -n "${__f_demangle__p}" ] || continue
				is_tty "${__f_demangle__p}" || continue
				__f_demangle__tty="${__f_demangle__p}" ; break
			done
		fi

		__f_demangle__p=
		case "$1" in
		i) __f_demangle__p=$(readlink -e "$2") ;;
		o) __f_demangle__p=$(readlink -f "$2") ;;
		esac

		if [ -n "${__f_demangle__tty}" ] ; then
			if [ "${__f_demangle__p}" = "${__f_demangle__tty}" ] ; then
				## why you're so tricky, huh?..
				case "$1" in
				i) echo /dev/stdin ;;
				o) echo /dev/stdout ;;
				esac
				return
			fi
		fi

		printf '%s' "${__f_demangle__p}"
	;;
	esac
}

## $1 - value
is_int() {
	printf '%s' "$1" \
	| grep -Eq '^[+-]?(0x[0-9a-fA-F]+|[0-9]+)$'
}

## $1 - length
## TODO: ensure that dd has read num of bytes _exactly_ not "at most"
peek_stdin() {
	[ $(($1)) -gt 0 ] || return 1

	dd of=/dev/null bs=4096 count=$(($1 / 4096)) 2>/dev/null
	[ $(($1 % 4096)) = 0 ] && return
	dd of=/dev/null bs=$(($1 % 4096)) count=1 2>/dev/null
}

## main proc

for a ; do
	case "$a" in
	i:*|in:*)
		v=${a#*:}
		if [ -z "$v" ] ; then
			warn "input spec: empty, do nothing"
			continue
		fi

		v=$(f_demangle i "$v")
		if [ -z "$v" ] ; then
			warn "input spec: not exist, do nothing"
			continue
		fi
		[ "$v" = '/dev/stdin' ] && v=

		[ "$v" = "${f_in}" ] || i_off=0
		f_in="$v"
	;;
	o:*|out:*)
		v=${a#*:}
		if [ -z "$v" ] ; then
			warn "output spec: empty, do nothing"
			continue
		fi

		v=$(f_demangle o "$v")
		if [ -z "$v" ] ; then
			warn "output spec: not exist, do nothing"
			continue
		fi
		[ "$v" = '/dev/stdout' ] && v=

		[ "$v" = "${f_out}" ] || o_needsep=0
		if [ -n "$v" ] ; then
			o_needsep=1
			x=$( (
				set -e
				s=$(stat -c '%s' "$v")
				dd "if=$v" bs=1 count=1 skip=$((s - 1))
			) 2>/dev/null | cat)
			if echo "$x" | grep -Eq '^\s$' ; then
				o_needsep=0
			fi
		fi
		f_out="$v"
	;;

	r:*|read:*)
		v=${a#*:}
		if [ -z "$v" ] ; then
			warn "read spec: empty, do nothing"
			continue
		fi

		case "$v" in
		e|exact) i_exact=1 ;;
		l|loose)
			i_exact=0
			warn "read spec: 'loose' mode MAY read LESS bytes than was requested" \
			     "and is suitable for binary stream dumps only." \
			     "you're been warned!"
		;;
		*) warn "read spec: unknown subspec: '$v', skipping" ;;
		esac
	;;
	w:*|write:*)
		v=${a#*:}
		if [ -z "$v" ] ; then
			warn "write spec: empty, do nothing"
			continue
		fi

		case "$v" in
		a|append) o_trunc= ;;
		t|trunc)
			o_trunc=1
			warn "write spec: 'trunc' mode WILL OVERWRITE destination" \
			     "EACH TIME you're willing to write any value" \
			     "(in case of file output and not stdout)." \
			     "you're been warned!"
		;;
		z|zap)
			## treat 'zap' as 'truncate output (once)'
			[ -z "${f_out}" ] && continue
			( : > "${f_out}" )
			o_needsep=0
		;;
		*) warn "write spec: unknown subspec: '$v', skipping" ;;
		esac
	;;

	p:*|pos:*)
		v=${a#*:}
		if [ -z "$v" ] ; then
			warn "position spec: empty, do nothing"
			continue
		fi

		off=${i_off}

		case "$v" in
		b|begin)
			off=0
		;;
		[+-][0-9]*|[0-9]*)
			if ! is_int "$v" ; then
				warn "position spec: '$a' looks spoiled, skipping"
				continue
			fi

			off=$((off + v))
		;;
		*)
			warn "position spec: unknown subspec: '$v', skipping"
			continue
		;;
		esac

		if [ -z "${f_in}" ] ; then
			p=$((off - i_off))
			if [ $p -lt 0 ] ; then
				warn "impossible to rewind stdin back to ${p#-} byte(s)"
			fi
			peek_stdin $p
		fi

		i_off=${off}
	;;

	l|lsb) i_mode=lsb ;;
	m|msb) i_mode=msb ;;

	b|bin)      i_kind=b ;;
	u|unsigned) i_kind=u ;;
	d|decimal)  i_kind=d ;;
	o|oct)      i_kind=o ;;
	x|hex)      i_kind=x ;;
	f|float)    i_kind=f ;;
	s|string)   i_kind=s ;;

	_s|_space)    o_sep=s ;;
	_t|_tab)      o_sep=t ;;
	_n|_newline)  o_sep=n ;;

	_[stn]:*|_space:*|_tab:*|_newline:*)
		IFS=':' read -r sep count <<-EOF
		$a
		EOF

		c=''
		case "${sep}" in
		_s|_space)   c=' '         ;;
		_t|_tab)     c=${FS:-'\t'} ;;
		_n|_newline) c='\n'        ;;
		esac

		if [ -n "${count}" ] ; then
			if is_int "${count}" ; then
				count=$((count))
				if [ ${count} -lt 1 ] ; then
					warn "separator spec: count subspec: less than 1, defaulting to 1"
					count=
				fi
			else
				warn "separator spec: '$a' looks spoiled, skipping"
				continue
			fi
		fi
		[ -z "${count}" ] && count=1

		s=''
		k=0 ; while [ $k -lt ${count} ] ; do
			k=$((k + 1))
			s=$s$c
		done

		printf "$s" \
		| (
			[ -n "${f_out}" ] && exec >> "${f_out}"
			cat
		)
		o_needsep=0
	;;

	[0-9]*)
		IFS=':' read -r len count xtra <<-EOF
		$a
		EOF

		if ! is_int "${len}" ; then
			warn "value spec: '$a' looks spoiled, skipping"
			continue
		fi
		len=$((len))

		if [ ${len} -lt 1 ] ; then
			warn "value spec: won't read '${len}' bytes, skipping"
			continue
		fi

		if is_int "${count}" ; then
			count=$((count))
			if [ ${count} -lt 1 ] ; then
				warn "value spec: array subspec: less than 1, defaulting to 1"
				count=
			fi
		else
			[ -n "${count}" ] && xtra="${count}:${xtra}"
			count=
		fi
		[ -z "${count}" ] && count=1

		mode=
		kind=
		sep=
		zap=

		## treat ${xtra} as colon-separated list
		while [ -n "${xtra}" ] ; do
			v=${xtra%%:*}
			[ -n "$v" ] && xtra=${xtra#"$v"}
			xtra=${xtra#:}
			if [ -z "$v" ] ; then
				warn "value spec: empty subspec"
				continue
			fi

			case "$v" in
			l|lsb)
				if [ -z "${mode}" ] ; then
					mode=lsb
					continue
				fi
				warn "value spec: endianness subspec already set to '${mode}', skipping"
				continue
			;;
			m|msb)
				if [ -z "${mode}" ] ; then
					mode=msb
					continue
				fi
				warn "value spec: endianness subspec already set to '${mode}', skipping"
				continue
			;;

			b|bin)
				if [ -z "${kind}" ] ; then
					kind=b
					continue
				fi
				warn "value spec: type subspec already set to '${kind}', skipping"
				continue
			;;
			u|unsigned)
				if [ -z "${kind}" ] ; then
					kind=u
					continue
				fi
				warn "value spec: type subspec already set to '${kind}', skipping"
				continue
			;;
			d|decimal)
				if [ -z "${kind}" ] ; then
					kind=d
					continue
				fi
				warn "value spec: type subspec already set to '${kind}', skipping"
				continue
			;;
			o|oct)
				if [ -z "${kind}" ] ; then
					kind=o
					continue
				fi
				warn "value spec: type subspec already set to '${kind}', skipping"
				continue
			;;
			x|hex)
				if [ -z "${kind}" ] ; then
					kind=x
					continue
				fi
				warn "value spec: type subspec already set to '${kind}', skipping"
				continue
			;;
			f|float)
				if [ -z "${kind}" ] ; then
					kind=f
					continue
				fi
				warn "value spec: type subspec already set to '${kind}', skipping"
				continue
			;;
			s|string)
				if [ -z "${kind}" ] ; then
					kind=s
					continue
				fi
				warn "value spec: type subspec already set to '${kind}', skipping"
				continue
			;;

			_s|_space)
				if [ -z "${sep}" ] ; then
					sep=s
					continue
				fi
				warn "value spec: separator subspec already set to '${sep}', skipping"
				continue
			;;
			_t|_tab)
				if [ -z "${sep}" ] ; then
					sep=t
					continue
				fi
				warn "value spec: separator subspec already set to '${sep}', skipping"
				continue
			;;
			_n|_newline)
				if [ -z "${sep}" ] ; then
					sep=n
					continue
				fi
				warn "value spec: separator subspec already set to '${sep}', skipping"
				continue
			;;

			z|zap)
				if [ -z "${zap}" ] ; then
					zap=1
					continue
				fi
				warn "value spec: zap subspec already set to '${zap}', skipping"
				continue
			;;

			*) warn "value spec: unknown subspec: '$v', skipping" ;;
			esac
		done

		if [ "${zap}" = 1 ] ; then
			len=$((len * count))
			i_off=$((i_off + len))
			[ -z "${f_in}" ] && peek_stdin ${len}
			continue
		fi

		[ -z "${mode}" ] && mode=${i_mode}
		[ -z "${kind}" ] && kind=${i_kind}
		[ -z "${sep}" ]  && sep=${o_sep}
		exact=${i_exact}
		trunc=${o_trunc}

		fmt="${kind}${len}"
		case "${kind}" in
		b) fmt='x1' ;;
		f)
			case "${len}" in
			4|8|10) ;;
			*)
				warn "'${len}' is non-standard length for floats (choose one from 4/8/10), skipping"
				continue
			;;
			esac
		;;
		[udox])
			case "${len}" in
			1|2|4|8|16) ;;
			*)
				warn "'${len}' is non-standard length for integers (choose one from 1/2/4/8/16), skipping"
				continue
			;;
			esac
		;;
		s) fmt=${kind} ;;
		esac

		k=0 ; while [ $k -lt ${count} ] ; do
			k=$((k + 1))

			x=$(dd bs=1 count=${len} \
			        ${f_in:+ skip=${i_off} "if=${f_in}" } 2>/dev/null \
			    | od -v -A n -t x1)

			y=$(echo "$x" | tr -c -d '0-9a-fA-F')

			bytes=${#y}
			bytes=$((bytes / 2))

			if [ "${bytes}" != "${len}" ] ; then
				if [ "${exact}" = 1 ] ; then
					err "unable to read exactly ${len} byte(s)" \
					"succeed to read only ${bytes} byte(s)"
				else
					warn "read ${bytes} byte(s), expected ${len} byte(s)"
				fi
			fi

			case "${fmt}" in
			x1) x=$y ;;
			s)
				y=$(printf '\\x%s' $x)
				x=$(env printf "$y")
			;;
			*)
				e=
				case "${mode}" in
				lsb) e=little ;;
				msb) e=big ;;
				esac

				y=$(printf '\\x%s' $x)
				x=$(env printf "$y" \
				    | od --endian=$e \
				      -v -A n -t ${fmt} -N ${len} \
				    | tr -d '[:space:]')
			;;
			esac

			{
				fmt=''
				case "${sep}" in
				s) fmt=' '         ;;
				t) fmt=${FS:-'\t'} ;;
				n) fmt='\n'        ;;
				esac
				[ "${o_needsep}" = 0 ] && fmt=''
				[ -n "${trunc}" ]      && fmt=''

				case "${kind}" in
				o) fmt="${fmt}0"  ;;
				x) fmt="${fmt}0x" ;;
				esac

				fmt="${fmt}%s"

				printf "${fmt}" "$x"
			} \
			| (
				if [ -n "${f_out}" ] ; then
					if [ -n "${trunc}" ] ; then
						exec > "${f_out}"
					else
						exec >> "${f_out}"
					fi
				fi
				cat
			)

			trunc=
			o_needsep=1
			i_off=$((i_off + bytes))
		done
	;;

	*)
		warn "unknown spec '$a', skipping"
		continue
	;;
	esac
done

if [ "${o_needsep}" = 1 ] ; then
	(
		[ -n "${f_out}" ] && exec >> "${f_out}"
		echo
	)
fi
exit 0
