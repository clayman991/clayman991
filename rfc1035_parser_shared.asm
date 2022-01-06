;
; Merkulov Engineering (MerEngi.COM) 2021
; ME Internet Name Service
;   Domain Name Service Support
;
; Версии:
;	1.000  (1.000)	- 2021-12-20 начало 
;
; rfc1035_parser_shared.asm - парсер данных DNS (rfc1034/rfc1035/rfc2929 etc)
; Общие ф-и с 
; 
; Модификации
;
.686
.model flat, stdcall
option casemap:none

include P:\ASM\_libs\include\windows.inc
include P:\ASM\_libs\_texts\kernel32.inc

include P:\ASM\AU\auapi\auapi136\auapi.inc

include P:\ASM\menamed\menamed\struc_RRmenm.inc

_rfc1035_parser_shared_self_ equ 1
include rfc1035_parser_shared.inc


.const
cFQDN_mensconfig					db					'config.mens.arpa.',0
cFQDN_mensservers					db					'servers.mens.arpa.',0

cDN_menszones						LABEL				BYTE
cDN_menszone_strings				db					'strings',0
cDN_menszone_smtpsrv				db					'smtpsrv',0
									db					0

DW_MENS								equ					736e656dh	;mens
SIZEOF_DW_MENS						equ					4
DW_ARPA								equ					61707261h	;arpa
SIZEOF_DW_ARPA						equ					4


.code
include func_common.inc
include P:\ASM\_libs\_texts\aucommon_protos.inc

;---------------------------------------------------------------------------------------
;
; Расчитывает длину строки RR.Name
;
rfc1035_RRnameLen:
		; IN: esi - lpStr, ebx - cbStr
		;OUT: ecx - len
		push		eax

		xor			eax,eax
		mov			ecx,eax																;0
l_rfc1035_RRnameLen_loop:
		cmp			ecx,ebx
		jae			l_rfc1035_RRnameLen_loopend_badstr

		mov			al,byte ptr [esi+ecx]
		inc			ecx

		test		eax,eax
		je			l_rfc1035_RRnameLen_loopend

		add			ecx,eax
		jmp			l_rfc1035_RRnameLen_loop

l_rfc1035_RRnameLen_loopend_badstr:
		;Поврежденная строка
		xor			ecx,ecx

l_rfc1035_RRnameLen_loopend:
		pop			eax
		ret

PUBLIC C rfc1035_RRnameLen
;---------------------------------------------------------------------------------------
;
; Расчитывает длину строки RR.Name
;
rfc1035_RRnameLen_PST:
		; IN: edx - (LPPST) lpRRname
		;OUT: ecx - len

		push		ebx
		push		esi

		mov			esi,dword ptr [edx+PST.lpStr]
		mov			ebx,dword ptr [edx+PST.cbStr]
		; IN: esi - lpStr, ebx - cbStr
		;OUT: ecx - len
		call		rfc1035_RRnameLen

		pop			esi
		pop			ebx
		ret

PUBLIC C rfc1035_RRnameLen_PST
;---------------------------------------------------------------------------------------
;
; Копирует RR.Name в строку FQDN или FQDNrev
; ВНИМАНИЕ! Используется DefaultHeap !
;
rfc1035_RRname2str PROC lpRRname:LPPST, Flags:DWORD, lppstBuffer:LPPST						;int/nfz
		LOCAL tmplpEO:LPSTR

		push		esi
		push		edi

		mov			edx,dword ptr [lpRRname]
		; IN: edx - (LPPST) lpRRname
		;OUT: ecx - len
		call		rfc1035_RRnameLen_PST

		test		ecx,ecx
		je			l_error_baddata

		mov			esi,dword ptr [lppstBuffer]

		test		dword ptr [Flags],rfc1035_str2RRname_F_StaticBuffer
		jne			l_rfc1035_RRname2str_staticbuffer

		cmp			dword ptr [esi+PST.lpStr],0
		jne			l_rfc1035_RRname2str_testfreemem

		push		ecx

		;LPVOID MM_AnyAlloc(DWORD Flags, DWORD dwSize);
		push		ecx
		push		0
		call		dword ptr [MM_AnyAlloc]
		mov			dword ptr [esi+PST.lpStr],eax
		mov			edi,eax

		pop			ecx
		jmp			l_rfc1035_RRname2str_copy
;- - - - - - - - - -
l_rfc1035_RRname2str_testfreemem:
		; ecx - cbNeed (включая терминатор)

		mov			edi,dword ptr [esi+PST.cbStr]		;lpStrEO

		test		dword ptr [Flags],rfc1035_str2RRname_F_OutDataF2
		jne			l_rfc1035_RRname2str_testfreemem_isF2

		add			edi,dword ptr [esi+PST.lpStr]

l_rfc1035_RRname2str_testfreemem_isF2:
		mov			edx,ecx
		lea			eax,dword ptr [esi+PST.lpStr]
		;IN: eax - * (начало буффера), edi - конец буфера, edx - необходимая память, ecx - выделяемый блок
		LIBcall		testfreemem

		jmp			l_rfc1035_RRname2str_copy
;- - - - - - - - - -
l_rfc1035_RRname2str_staticbuffer:
		; ecx - cbNeed (включая терминатор)
		mov			eax,dword ptr [esi+PST.cbStr]		;MaxBuffer
		cmp			ecx,eax
		ja			l_error_outofmemory

		mov			edi,dword ptr [esi+PST.lpStr]
		test		edi,edi
		je			l_error_outofmemory

;-------------------
l_rfc1035_RRname2str_copy:
		; edi - lpBuffer, ecx - cbNeed (включая терминатор)
		mov			edx,edi
		dec			ecx

		mov			eax,dword ptr [Flags]

		test		eax,rfc1035_str2RRname_F_FQDNrev
		je			l_rfc1035_RRname2str_copyloopstart

		add			edx,ecx
		mov			dword ptr [tmplpEO],edx

l_rfc1035_RRname2str_copyloopstart:
		mov			esi,dword ptr [lpRRname]
		mov			esi,dword ptr [esi+PST.lpStr]

		;Проверка root
		cmp			byte ptr [esi],0
		je			l_rfc1035_RRname2str_copyloopend_root

		;Преобразование
l_rfc1035_RRname2str_copyloop:
		movzx		ecx,byte ptr [esi]
		inc			esi

		jecxz		l_rfc1035_RRname2str_copyloopend

		test		eax,rfc1035_str2RRname_F_FQDNrev
		jne			l_rfc1035_RRname2str_copyloop_rev

		mov			edi,edx
		add			edx,ecx

		test		eax,rfc1035_str2RRname_F_email
		je			l_rfc1035_RRname2str_copyloop_fwd_dot

		mov			byte ptr [edx],'@'
		inc			edx
		
		and			eax,NOT rfc1035_str2RRname_F_email
		jmp			l_rfc1035_RRname2str_copyloop_docopy
;-  -  -  -  -  -  -
l_rfc1035_RRname2str_copyloop_fwd_dot:
		mov			byte ptr [edx],'.'
		inc			edx
		
		jmp			l_rfc1035_RRname2str_copyloop_docopy
;-  -  -  -  -  -  -
l_rfc1035_RRname2str_copyloop_rev:
		sub			edx,ecx
		dec			edx

		mov			edi,edx

		mov			byte ptr [edi],'.'
		inc			edi

l_rfc1035_RRname2str_copyloop_docopy:
		;IN: edi - outstr, esi - instr, ecx - len; OUT: edi - eo outstr, esi - eo instr
		LIBcall		copymem

		jmp			l_rfc1035_RRname2str_copyloop
;-  -  -  -  -  -  -
l_rfc1035_RRname2str_copyloopend_root:
		mov			byte ptr [edx],'.'
		inc			edx

		and			dword ptr [Flags],NOT rfc1035_str2RRname_F_FQDNrev

l_rfc1035_RRname2str_copyloopend:
;- - - - - - - - - -
		; ecx - 0

		;Возврат длины
		mov			eax,dword ptr [Flags]

		mov			edi,edx

		test		eax,rfc1035_str2RRname_F_FQDNrev
		je			l_rfc1035_RRname2str_not2rev

		mov			edi,dword ptr [tmplpEO]

l_rfc1035_RRname2str_not2rev:
		mov			edx,dword ptr [lppstBuffer]

		test		eax,rfc1035_str2RRname_F_OutDataF2
		jne			l_rfc1035_RRname2str_is2F2

		sub			edi,dword ptr [edx+PST.lpStr]

l_rfc1035_RRname2str_is2F2:
		mov			dword ptr [edx+PST.cbStr],edi

;- - - - - - - - - -
		mov			eax,ecx																;0
		jmp			l_exit
;-------------------
l_error_baddata:
		mov			eax,AU_ERRCODE__BADDATA
		jmp			l_error
;-------------------
l_error_outofmemory:
		mov			eax,AU_ERRCODE__OUTOFMEMORY

l_error:
;-------------------
l_exit:
		test		eax,eax
		pop			edi
		pop			esi
		ret
rfc1035_RRname2str ENDP

PUBLIC rfc1035_RRname2str
;---------------------------------------------------------------------------------------
;
; Копирует строку FQDN или FQDNrev в RR.Name
; ВНИМАНИЕ! Используется DefaultHeap !
;
rfc1035_str2RRname PROC lpStr:TSTR_o_PST, cbStr:DWORD, Flags:DWORD, lpRRnameBuffer:LPPST	;int/nfz
		push		ebx
		push		esi
		push		edi

		;Выделение памяти
		lea			edx,dword ptr [lpStr]
		xor			ecx,ecx								;Len

		mov			ebx,dword ptr [Flags]

		test		ebx,rfc1035_str2RRname_F_SPECIALNAME
		je			l_rfc1035_str2RRname_notspname

		mov			eax,dword ptr [cbStr]												;Mode
;-  -  -  -  -  -  -
		;Имя записи сервера (<f|m><hex8:lpStr>.servers.mens.arpa.)
		cmp			eax,rfc1035_str2RRname_M_REDIRECTS		;rfc1035_str2RRname_M_FORWARDERS || rfc1035_str2RRname_M_REDIRECTS
		ja			l_rfc1035_str2RRname_spname_l1next

		;ВНИМАНИЕ! Для rfc1035_str2RRname_M_FORWARDERS || rfc1035_str2RRname_M_REDIRECTS  
		;		   lpStr - всегда DWORD!

		mov			ecx,SIZEOF cFQDN_mensservers-1+10
		jmp			l_rfc1035_str2RRname_getmem
;-  -  -  -  -  -  -
l_rfc1035_str2RRname_spname_l1next:
		;Имя записи в конфиге (<lpStr>.config.mens.arpa.)
		cmp			eax,rfc1035_str2RRname_M_NAMEINCONFIG
		jne			l_error_notsupported

		;ВНИМАНИЕ! Для rfc1035_str2RRname_M_NAMEINCONFIG lpStr 
		;		   всегда PST!

		mov			ecx,SIZEOF cFQDN_mensconfig-1
		jmp			l_rfc1035_str2RRname_is1pst
;-  -  -  -  -  -  -
l_rfc1035_str2RRname_notspname:
		xor			eax,eax																;Mode

		test		ebx,rfc1035_str2RRname_F_INPUTPST
		je			l_rfc1035_str2RRname_not1pst
		
l_rfc1035_str2RRname_is1pst:
		mov			edx,dword ptr [edx]

l_rfc1035_str2RRname_not1pst:
		add			ecx,dword ptr [edx+PST.cbStr]
;- - - - - - - - - -
l_rfc1035_str2RRname_getmem:
		; ecx - Need/Out Len, edx - (LPPST) lpInStr/(LPPST) lpInRRName/(DWORD) dwId, eax - Mode
		mov			ebx,eax																;Mode

		push		edx

		mov			esi,dword ptr [lpRRnameBuffer]

		cmp			dword ptr [esi+PST.lpStr],0
		jne			l_rfc1035_str2RRname_testfreemem

		inc			ecx
		;LPVOID MM_AnyAlloc(DWORD Flags, DWORD dwSize);
		push		ecx
		push		0
		call		dword ptr [MM_AnyAlloc]
		mov			edi,eax

		mov			dword ptr [esi+PST.lpStr],edi
		jmp			l_rfc1035_str2RRname_copy
;- - - - - - - - - -
l_rfc1035_str2RRname_testfreemem:
		mov			edi,dword ptr [esi+PST.cbStr]		;lpStrEO
		lea			eax,dword ptr [esi+PST.lpStr]

		test		dword ptr [Flags],rfc1035_str2RRname_F_OutDataF2
		jne			l_rfc1035_str2RRname_F2_l0001

		add			edi,dword ptr [eax]

l_rfc1035_str2RRname_F2_l0001:
		inc			ecx
		mov			edx,ecx
		;IN: eax - * (начало буффера), edi - конец буфера, edx - необходимая память, ecx - выделяемый блок
		LIBcall		testfreemem

;*******************
l_rfc1035_str2RRname_copy:
		pop			edx

		; edi - lpBuffer, edx - (LPPST) lpInStr/(LPPST) lpInRRName/(DWORD) dwId, ebx - Mode

		test		ebx,ebx		;~ rfc1035_str2RRname_M_STANDARD
		je			l_rfc1035_str2RRname_standardmode

		cmp			ebx,rfc1035_str2RRname_M_FORWARDERS
		jne			l_rfc1035_str2RRname_spname2_l1next

		mov			ah,'f'
		jmp			l_rfc1035_str2RRname_spname2_mode_mensservers
;-  -  -  -  -  -  -
l_rfc1035_str2RRname_spname2_l1next:
		cmp			ebx,rfc1035_str2RRname_M_REDIRECTS
		jne			l_rfc1035_str2RRname_spname2_l2next

		mov			ah,'r'
l_rfc1035_str2RRname_spname2_mode_mensservers:
		mov			al,9				;Длина <f|m><hex8:lpStr>

		stos		word ptr [edi]

		;<hex8:lpStr>
		;DWORD Bin2HexBin(LPVOID lpData, DWORD cbData, DWORD IsMacOrder, LPTSTR lpBuffer, DWORD cbBuffer);
		push		9
		push		edi
		push		0
		push		4
		push		edx																	;dwId
		call		dword ptr [Bin2HexBin]
		add			edi,eax

		;Преобразовать суффикс
		mov			ecx,SIZEOF cFQDN_mensservers-1
		mov			esi,offset cFQDN_mensservers
		mov			edx,1																;direction +1
		jmp			l_rfc1035_str2RRname_loop
;- - - - - - - - - -
l_rfc1035_str2RRname_spname2_l2next:
		;cmp		eax,rfc1035_str2RRname_M_NAMEINCONFIG
		;jne		l_error_notsupported

		;Скопировань RRName
		mov			ecx,dword ptr [edx+PST.cbStr]
		jecxz		l_rfc1035_str2RRname_spname2_l2next_noRRName

		dec			ecx											;Последний 0
		je			l_rfc1035_str2RRname_spname2_l2next_noRRName

		mov			esi,dword ptr [edx+PST.lpStr]
		;IN: edi - outstr, esi - instr, ecx - len; OUT: edi - eo outstr, esi - eo instr
		LIBcall		copymem

l_rfc1035_str2RRname_spname2_l2next_noRRName:
		;Преобразовать суффикс
		mov			ecx,SIZEOF cFQDN_mensconfig-1
		mov			esi,offset cFQDN_mensconfig
		mov			edx,1																;direction +1
		jmp			l_rfc1035_str2RRname_loop
;-------------------
l_rfc1035_str2RRname_standardmode:
		;Преобразование
		mov			ecx,dword ptr [edx+PST.cbStr]
		jecxz		l_rfc1035_str2RRname_loopend

		mov			esi,dword ptr [edx+PST.lpStr]

		mov			edx,1																;direction +1

		test		dword ptr [Flags],rfc1035_str2RRname_F_FQDNrev
		je			l_rfc1035_str2RRname_loop

		lea			esi,dword ptr [esi+ecx-1]
		neg			edx																	;direction -1

l_rfc1035_str2RRname_loop:
		mov			ebx,esi

l_rfc1035_str2RRname_looploop:
		jecxz		l_rfc1035_str2RRname_looploopend

		mov			al,byte ptr [esi]

		cmp			al,'.'
		je			l_rfc1035_str2RRname_looploopend

		;
		cmp			al,'-'
		je			l_rfc1035_str2RRname_loop0cont

		cmp			al,'0'
		jb			l_error_baddata
		cmp			al,'9'
		jbe			l_rfc1035_str2RRname_loop0cont

		cmp			al,'A'
		jb			l_error_baddata
		cmp			al,'Z'
		jbe			l_rfc1035_str2RRname_loop0cont

		cmp			al,'a'
		jb			l_error_baddata
		cmp			al,'z'
		jbe			l_rfc1035_str2RRname_loop0cont

		cmp			al,'_'
		jne			l_error_baddata		
		
l_rfc1035_str2RRname_loop0cont:
		add			esi,edx																;+direction
		dec			ecx
		jmp			l_rfc1035_str2RRname_looploop

l_rfc1035_str2RRname_looploopend:
		push		ecx
		push		esi

		;Расчет длины элемента
		mov			ecx,esi
		mov			esi,ebx

		cmp			edx,1
		je			l_rfc1035_str2RRname_loop_copy_notrev

		xchg		esi,ecx
		inc			esi
		inc			ecx

l_rfc1035_str2RRname_loop_copy_notrev:
		sub			ecx,esi

		mov			byte ptr [edi],cl
		inc			edi

		;Скопировать элемент (если есть)
		jecxz		l_rfc1035_str2RRname_loop_copy_exit
		
		;IN: edi - outstr, esi - instr, ecx - len; OUT: edi - eo outstr, esi - eo instr
		LIBcall		copymem

l_rfc1035_str2RRname_loop_copy_exit:
		mov			eax,ecx
		pop			esi
		pop			ecx
		jecxz		l_rfc1035_str2RRname_loopend

		;Была найдена '.'
		add			esi,edx																;+direction
		dec			ecx
		jne			l_rfc1035_str2RRname_loop

		test		eax,eax
		je			l_rfc1035_str2RRname_loopend

		;ROOT-терминатор
		mov			byte ptr [edi],cl													;0
		inc			edi

l_rfc1035_str2RRname_loopend:
		; ecx - 0

		;char-терминатор
		;mov			byte ptr [edi],cl													;0

		;Расчет длины данных
		mov			edx,dword ptr [lpRRnameBuffer]

		test		dword ptr [Flags],rfc1035_str2RRname_F_OutDataF2
		jne			l_rfc1035_str2RRname_l0001

		sub			edi,dword ptr [edx+PST.lpStr]
l_rfc1035_str2RRname_l0001:
		mov			dword ptr [edx+PST.cbStr],edi

		;***
		mov			eax,ecx																;0
		jmp			l_exit
;-------------------
l_error_baddata:
		mov			eax,AU_ERRCODE__BADDATA
		jmp			l_error
;-------------------
l_error_notsupported:
		mov			eax,AU_ERRCODE__NOTSUPPORTED

l_error:
;-------------------
l_exit:
		test		eax,eax
		pop			edi
		pop			esi
		pop			ebx
		ret
rfc1035_str2RRname ENDP

PUBLIC rfc1035_str2RRname
;---------------------------------------------------------------------------------------
;
; Проверяет RR.Name на наличие '*' (запрос поиска)
;
rfc1035_RRnameChkAsterisk:
		; IN: edx - (LPPST) lpRRname
		;OUT: fz - is_found
 
		push		eax
		push		ecx
		push		ebx
		push		edi

		;Поиск '*'
		mov			edi,dword ptr [edx+PST.lpStr]
		mov			ebx,dword ptr [edx+PST.cbStr]

		mov			al,'*'
l_rfc1035_RRnameChkAsterisk_loop:
		movzx		ecx,byte ptr [edi]
		inc			edi

		jecxz		l_rfc1035_RRnameChkAsterisk_loopend

		sub			ebx,ecx
		jb			l_rfc1035_RRnameChkAsterisk_loopend

		add			edx,ecx

		repne scas	byte ptr [edi]
		je			l_rfc1035_RRnameChkAsterisk_loopend_found

		dec			edi
		jmp			l_rfc1035_RRnameChkAsterisk_loop

l_rfc1035_RRnameChkAsterisk_loopend_found:
		xor			edi,edi

l_rfc1035_RRnameChkAsterisk_loopend:
		test		edi,edi

		pop			edi
		pop			ebx
		pop			ecx
		pop			eax
		ret

PUBLIC C rfc1035_RRnameChkAsterisk
;---------------------------------------------------------------------------------------
;
; Проверяет RR.Name суффикса MENS ('mens.arpa.')
; Определяет ZoneId для <zone>.mens.arpa.
;
rfc1035_RRnameChkMENS:
		; IN: edx - (LPPST) lpRRname
		;OUT: fz - is_found, eax - ZoneId
		push		ecx
		push		edi

		mov			ecx,dword ptr [edx+PST.cbStr]
		cmp			ecx,SIZEOF_DW_ARPA+1+SIZEOF_DW_MENS+1
		jb			l_rfc1035_RRnameChkMENS_exit

		mov			edi,dword ptr [edx+PST.lpStr]

		lea			edi,dword ptr [edi+ecx]

		;<root>
		dec			edi

		;arpa
		sub			edi,SIZEOF_DW_ARPA+1

		cmp			byte ptr [edi],SIZEOF_DW_ARPA
		jne			l_rfc1035_RRnameChkMENS_exit

		cmp			dword ptr [edi+1],DW_ARPA
		jne			l_rfc1035_RRnameChkMENS_exit
		
		;mens
		sub			edi,SIZEOF_DW_MENS+1

		cmp			byte ptr [edi],SIZEOF_DW_MENS
		jne			l_rfc1035_RRnameChkMENS_exit

		cmp			dword ptr [edi+1],DW_MENS
		jne			l_rfc1035_RRnameChkMENS_exit
;- - - - - - - - - -
		;Определение ZoneId
		mov			eax,MENS_ZONE_ID

		mov			edi,dword ptr [edx+PST.lpStr]

		movzx		ecx,byte ptr [edi]
		add			ecx,1+SIZEOF_DW_ARPA+1+SIZEOF_DW_MENS+1

		cmp			ecx,dword ptr [edx+PST.cbStr]
		jne			l_rfc1035_RRnameChkMENS_exitEq

		movzx		ecx,byte ptr [edi]
		inc			edi

		push		edx
		push		ebx
		mov			edx,offset cDN_menszones
		; IN: esi - lpTextFunc, ecx - cbTextFunc, edx - lpFuncs
		;OUT: ebx - iFunc, fz - no_func
		LIBcall		findfunc_wlen
		lea			eax,dword ptr [ebx+MENS_ZONE_ID]
		pop			ebx
		pop			edx

l_rfc1035_RRnameChkMENS_exitEq:
		xor			edi,edi
;-------------------
l_rfc1035_RRnameChkMENS_exit:
		test		edi,edi

		pop			edi
		pop			ecx
		ret

PUBLIC C rfc1035_RRnameChkMENS
;---------------------------------------------------------------------------------------
;
; Добавляет к RR.Name суффикс RRSfx, если RR.Name не заканчивается '.' (0)
;
rfc1035_fullRRName:
		; IN: edx - (LPPST) lpRRname, edi - (LPPST) lpRRSfx
		;OUT: fz - is_full
		push		esi

		;Проверка не полного имени
		mov			esi,dword ptr [edx+PST.lpStr]
		add			esi,dword ptr [edx+PST.cbStr]

		cmp			byte ptr [esi-1],0
		je			l_rfc1035_fullRRName_exit

		;Добавить суффикс из 'ORIGN'
		push		eax
		push		ecx
		push		edi

		mov			ecx,dword ptr [edi+PST.cbStr]
		mov			edi,dword ptr [edi+PST.lpStr]

		lea			eax,dword ptr [edx+PST.lpStr]

		xchg		esi,edi
		push		edx

		inc			ecx
		mov			edx,ecx
		;IN: eax - * (начало буффера), edi - конец буфера, edx - необходимая память, ecx - выделяемый блок
		LIBcall		testfreemem

		pop			edx

		dec			ecx
		;IN: edi - outstr, esi - instr, ecx - len; OUT: edi - eo outstr, esi - eo instr
		LIBcall		copymem

		add			dword ptr [edx+PST.cbStr],ecx

		pop			edi
		pop			ecx
		pop			eax

l_rfc1035_fullRRName_exit:
		pop			esi
		ret

PUBLIC C rfc1035_fullRRName
;---------------------------------------------------------------------------------------


END
