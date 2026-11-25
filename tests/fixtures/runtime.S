.text
.p2align 12
.global amtracer_runtime_point
.type amtracer_runtime_point, %function
amtracer_runtime_point:
    .inst 0x74959469
    ret
    .rept 1022
    nop
    .endr
.size amtracer_runtime_point, .-amtracer_runtime_point
.section .note.GNU-stack,"",%progbits
