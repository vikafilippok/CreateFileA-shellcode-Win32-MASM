.386
.model flat, stdcall
assume fs:nothing

.code
	main proc
		push eax
		push ebx
		push ecx
		push edx
		push esi
		push edi
		push ebp	
		
		push ebp
		mov ebp, esp
		
		sub esp, 20h		; Allocate memory for variables
							; one var = 4 bytes
							; last one reserved
		
		; init vars by zeroes	
		xor eax, eax		
		mov [ebp - 4h], eax		; [ebp - 0x04] - addres of kernel32.dll
		mov [ebp - 8h], eax		; [ebp - 0x08] - num of exported funcs
		mov [ebp - 0Ch], eax	; [ebp - 0x0C] - export address table
		mov [ebp - 10h], eax	; [ebp - 0x10] - address of name pointer table
		mov [ebp - 14h], eax	; [ebp - 0x14] - address of ordinal table
		mov [ebp - 18h], eax	; addres to string "CreateFileA" on stack
		mov [ebp - 1Ch], eax	; addres to string "Halo.txt" on stack
		
		
								;
		
		xor esi,esi				; for null-free bytes
		mov eax, [fs:30h + esi]	;PEB
		mov eax, [eax + 0Ch]	;Ldr
		mov eax, [eax + 14h]	;InMemoryOrderModuleList
		mov eax, [eax + esi]	;current exe module
		mov eax, [eax + esi]	;ntdll
		mov eax, [eax + 10h] 	;Kernel32.DllBase
		mov [ebp - 4h], eax
		
		mov ebx, eax			; save kernel32.dll base address
		mov eax, [ebx + 3Ch]	; 0x3C intro the image - RVA of PE signature
		add eax, ebx			; PE signature = RVA of PE signature + kernel32
		
		; get address of Export Table
		mov  eax, [eax + 78h]	; RVA of Export Table
		add eax, ebx			; Export Table = RVA ExpTable + kernel32 base
		
		; ebx = kernel32 base
		; eax = Export Table
		
		;get number of exported functios in export table
		mov ecx, [eax + 14h]	; number
		mov [ebp - 8h], ecx
		
		mov ecx, [eax + 1Ch]	; Address of exported functions
		add ecx, ebx
		mov [ebp - 0Ch], ecx
		
		;get addr of name pointer table
		mov ecx, [eax + 20h]
		add ecx, ebx
		mov [ebp - 10h], ecx
		
		;get addr of ordinal table
		mov ecx, [eax + 24h]
		add ecx, ebx
		mov [ebp - 14h], ecx
		
		;push on stack "CreateFileA"
		xor esi, esi
		push esi
		; 43 72 65 61 74 65 46 69 6C 65 41
		push 4141656Ch	;"CreateFileAA" in ASCII little-endian
		push 69466574h
		push 61657243h
		mov [ebp - 18h], esp	;save pointer to string on stack
		xor eax, eax	; AL = 0 (for null-free)
		; in "CreateFileAA" 
		mov     byte ptr [esp+11], al	; change last 'A' to '\0'
		
		
		;push on stack name of file
		;"Halo.txt" 48 61 6C 6F 2E 74 78 74
		push esi	; "\0"
		push 7478742Eh
		push 6F6C6148h
		mov [ebp - 1Ch], esp
		
		xor ecx, ecx
		
		findCreateFileFunc:
			mov esi, [ebp - 18h]	;esi = pointer to "CreateFileA"
			mov edi, [ebp - 10h]	;edi = addr to func name table
			cld						;lowest-to-highest direction
			
			mov edi, [edi + eax*4]	;get rva of the next func name in dunc name table
			add edi, ebx
			
			;compare 12 bytes
			;mov cx, 0Ch				;len('CreateFileA') + '\0'
			mov cx, 1117h
			sub cx, 110bh		; 1117h - 110b = 0Ch - for null-free
			
			; runs until zf == 1
			; but causing no more than indicated in cx
			repe cmpsb		;check if esi == edi
			
			jz CreateFileFound
			inc eax			; counter++
			
			;check that the counter is less than num of funcs 
			cmp eax, [ebp - 8h]	
			je final				;if counter = num of exported funs => end of list => function not found 
			jmp findCreateFileFunc	; else => loop
			
		CreateFileFound:
			mov ecx, [ebp - 14h]	;ordinal table (ordinal is unique number of function)
			mov edx, [ebp - 0Ch]	;export adress table
			
			;get addr of CreateFileA ordinal
			mov ax, [ecx + eax*2]	;get ordinal
			mov eax, [edx + eax*4]	;get RVA of CreateFileA function
			add eax, ebx			;get VA of func
			
		InvokedCreateFileA:
		
		;HANDLE CreateFileA(  
		;[in]           LPCSTR                lpFileName,  
		;[in]           DWORD                 dwDesiredAccess,  
		;[in]           DWORD                 dwShareMode,  
		;[in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,  
		;[in]           DWORD                 dwCreationDisposition,  
		;[in]           DWORD                 dwFlagsAndAttributes,  
		;[in, optional] HANDLE                hTemplateFile
		;);
			
			
			; hTemplateFile = NULL
			xor edx, edx
			push edx		   ; 0
				
			; dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL (0x80)
			mov dl, 80h
			push edx
			
			;dwCreationDisposition = CREATE_ALWAYS(0x02)
			xor edx, edx
			mov dl, 2h
			push edx
			
			;lpSecurityAttributes = NULL
			xor edx, edx
			push edx
			
			;dwShareMode = NULL
			push edx
			
			;dwDesiredAccess
			xor edx, edx
			mov dl, 4h	;0x40000000 (GENEIC_WRITE)
			push edx
			
			;lpFileName = "Halo.txt" 48 61 6C 6F 2E 74 78 74
			mov edx, [ebp - 1Ch]
			push edx
			
			call eax
			
			
		final:
			pop ebp
			pop edi
			pop esi
			pop edx
			pop ecx
			pop ebx
			pop eax
		
			ret

	main endp
	end main
	
	; shellcode:
	50535152565755558bec83ec2033c08945fc8945f88945f48945f08945ec8945e88945e433f6648b46308b400c8b40148b04068b04068b40108945fc8bd88b433c03c38b407803c38b4814894df88b481c03cb894df48b482003cb894df08b482403cb894dec33f656686c654141687465466968437265618965e833c08844240b56682e7478746848616c6f8965e433c98b75e88b7df0fc8b3c8703fb66b917116681e90b11f3a67408403b45f8742bebdf8b4dec8b55f4668b04418b048203c333d252b2805233d2b2025233d2525233d2b204528b55e452ffd05d5f5e5a595b58c3
	