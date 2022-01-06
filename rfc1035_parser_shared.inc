IFNDEF _rfc1035_parser_shared_inc_
_rfc1035_parser_shared_inc_ equ 1

rfc1035_str2RRname_F_FQDNrev		equ					1
rfc1035_str2RRname_F_SPECIALNAME	equ					2		;Специалное имя <>.mens.arpa. ;ВНИМАНИЕ! Изменяет назначение параметров lpStr:TSTR_o_PST, cbStr:DWORD
rfc1035_str2RRname_F_email			equ					4

rfc1035_str2RRname_F_INPUTPST		equ					20000000h
rfc1035_str2RRname_F_StaticBuffer	equ					40000000h
rfc1035_str2RRname_F_OutDataF2		equ					80000000h


rfc1035_str2RRname_M_STANDARD		equ					0			;внутренний!
rfc1035_str2RRname_M_FORWARDERS		equ					1			;имя f<hex8:lpStr>.servers.mens.arpa.
rfc1035_str2RRname_M_REDIRECTS		equ					2			;имя r<hex8:lpStr>.servers.mens.arpa.
rfc1035_str2RRname_M_NAMEINCONFIG	equ					3			;имя <lpStr>.config.mens.arpa.

;---------------------------------------------------------------------------------------
IFDEF _rfc1035_parser_shared_protos_
include rfc1035_parser_shared_protos.inc
ELSE
IFNDEF _rfc1035_parser_shared_self_
include rfc1035_parser_shared_exp.inc
ENDIF
ENDIF


ENDIF
