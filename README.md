# MASM32 CreateFileA Shellcode

This project contains MASM32 assembly code that dynamically locates the base address of **kernel32.dll**, parses its export table to resolve the address of the **CreateFileA** function, and then calls it with prepared arguments. The code avoids null bytes, making it shellcode-friendly.  

The target API function can be changed easily (for example, to `WinExec` or `WriteFile`) by modifying the pushed string and arguments.

---

##  About

- Finds the base address of **kernel32.dll** via the PEB → Ldr → InMemoryOrderModuleList chain.  
- Locates the export table and iterates over it until it finds `CreateFileA`.  
- Constructs the function arguments (`"Halo.txt"`, `GENERIC_WRITE`, `CREATE_ALWAYS`, etc.) directly on the stack.  
- Invokes `CreateFileA` to create the file.  
- The code avoids null bytes where possible, suitable for shellcode demonstrations.  

---
# MASM32 CreateFileA Shellcode Demo

This project contains MASM32 assembly code that dynamically locates the base address of **kernel32.dll**, parses its export table to resolve the address of the **CreateFileA** function, and then calls it with prepared arguments. The code avoids null bytes, making it shellcode-friendly.  

The target API function can be changed easily (for example, to `WinExec` or `WriteFile`) by modifying the pushed string and arguments.

---

## 🔗 Resources

- [RadASM IDE](http://assembler-code.com/programmnoe-obespechenie/) – IDE used for writing and testing the assembly code.  

---

