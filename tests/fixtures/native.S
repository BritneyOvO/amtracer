.text
.p2align 2
.global amtracer_target
.type amtracer_target, %function
amtracer_target:
    .cfi_startproc
    mov x13, x0
.global amtracer_point
.type amtracer_point, %function
amtracer_point:
    ldr x0, [x13]
    ret
    .cfi_endproc
.size amtracer_target, .-amtracer_target
.section .note.GNU-stack,"",%progbits
