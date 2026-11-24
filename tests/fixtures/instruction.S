.text
.p2align 12
.global amtracer_trace
.type amtracer_trace, %function
amtracer_trace:
    mov x9, x30
    mov x1, #0
    mov x2, #3
1:
    add x1, x1, #1
    subs x2, x2, #1
    b.ne 1b
    cbz x0, 2f
    bl amtracer_trace_leaf
    b 3f
2:
    mov x1, #99
3:
    adr x3, amtracer_trace_leaf
    blr x3
    mov x30, x9
    mov x0, x1
    ret
.global amtracer_trace_leaf
.type amtracer_trace_leaf, %function
amtracer_trace_leaf:
    add x1, x1, #7
    ret
.global amtracer_trace_end
amtracer_trace_end:
.size amtracer_trace, .-amtracer_trace

.p2align 12
.global amtracer_trace_fault
.type amtracer_trace_fault, %function
amtracer_trace_fault:
    ldr x0, [x0]
    ret
.size amtracer_trace_fault, .-amtracer_trace_fault

.p2align 12
.global amtracer_trace_atomic
.type amtracer_trace_atomic, %function
amtracer_trace_atomic:
    ldxr x1, [x0]
    add x1, x1, #1
    stxr w2, x1, [x0]
    ret
.size amtracer_trace_atomic, .-amtracer_trace_atomic

.p2align 12
.global amtracer_trace_svc
.type amtracer_trace_svc, %function
amtracer_trace_svc:
    svc #0
    ret
.size amtracer_trace_svc, .-amtracer_trace_svc

// An unreachable authenticated call forces the current emitter's page-wide
// native fallback. The tested add/ret themselves remain ordinary uprobes.
.p2align 12
.global amtracer_trace_fallback
.type amtracer_trace_fallback, %function
amtracer_trace_fallback:
    add x0, x0, #1
    ret
    .space 248
    .inst 0xd63f091f
.size amtracer_trace_fallback, .-amtracer_trace_fallback

.p2align 12
.global amtracer_trace_many
.type amtracer_trace_many, %function
amtracer_trace_many:
    .rept 80
    nop
    .endr
    ret
.global amtracer_trace_many_end
amtracer_trace_many_end:
.size amtracer_trace_many, .-amtracer_trace_many

.p2align 12
.global amtracer_trace_cross
.type amtracer_trace_cross, %function
amtracer_trace_cross:
    mov x9, x30
    bl amtracer_trace_cross_leaf
    mov x30, x9
    ret
.global amtracer_trace_cross_end
amtracer_trace_cross_end:
.size amtracer_trace_cross, .-amtracer_trace_cross

.p2align 12
.global amtracer_trace_cross_leaf
.type amtracer_trace_cross_leaf, %function
amtracer_trace_cross_leaf:
    add x0, x0, #1
    ret
.global amtracer_trace_cross_leaf_end
amtracer_trace_cross_leaf_end:
.size amtracer_trace_cross_leaf, .-amtracer_trace_cross_leaf

// Finish the source page before compiler-generated functions/veneers follow.
.p2align 12
.section .note.GNU-stack,"",%progbits
