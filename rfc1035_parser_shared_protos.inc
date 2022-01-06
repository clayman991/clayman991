IFNDEF _rfc1035_parser_shared_protos_inc_
_rfc1035_parser_shared_protos_inc_ equ 1

rfc1035_RRnameLen PROTO C
rfc1035_RRnameLen_PST PROTO C
rfc1035_RRname2str PROTO lpRRname:LPPST, Flags:DWORD, lppstBuffer:LPPST ;int/nfz
rfc1035_str2RRname PROTO lpStr:TSTR_o_PST, cbStr:DWORD, Flags:DWORD, lpRRnameBuffer:LPPST ;int/nfz

rfc1035_RRnameChkAsterisk PROTO C
rfc1035_RRnameChkMENS PROTO C
rfc1035_fullRRName PROTO C

ENDIF
