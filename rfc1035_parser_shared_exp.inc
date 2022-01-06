IFNDEF _rfc1035_parser_shared_exp_inc_
_rfc1035_parser_shared_exp_inc_ equ 1

externdef _imp__fc_rfc1035_RRnameLen:PTR pr0
rfc1035_RRnameLen equ <_imp__fc_rfc1035_RRnameLen>

externdef _imp__fc_rfc1035_RRnameLen_PST:PTR pr0
rfc1035_RRnameLen_PST equ <_imp__fc_rfc1035_RRnameLen_PST>


externdef _imp__rfc1035_RRname2str@12:PTR pr3
rfc1035_RRname2str equ <_imp__rfc1035_RRname2str@12>

externdef _imp__rfc1035_str2RRname@16:PTR pr4
rfc1035_str2RRname equ <_imp__rfc1035_str2RRname@16>


externdef _imp__fc_rfc1035_RRnameChkAsterisk:PTR pr0
rfc1035_RRnameChkAsterisk equ <_imp__fc_rfc1035_RRnameChkAsterisk>

externdef _imp__fc_rfc1035_RRnameChkMENS:PTR pr0
rfc1035_RRnameChkMENS equ <_imp__fc_rfc1035_RRnameChkMENS>

externdef _imp__fc_rfc1035_fullRRName:PTR pr0
rfc1035_fullRRName equ <_imp__fc_rfc1035_fullRRName>


ENDIF
