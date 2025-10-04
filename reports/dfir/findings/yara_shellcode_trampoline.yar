rule x64_shellcode_trampoline_generic {
  meta:
    description = "x64 trampoline: mov rax, imm64 + jmp rax (+mov r10d)"
  strings:
    $mov_rax_imm = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? }
    $jmp_rax     = { FF E0 }
    $mov_r10d    = { 49 C7 C2 ?? ?? ?? ?? }
  condition:
    all of them
}
