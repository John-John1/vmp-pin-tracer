/*
 * VMP 3.6 VM Context + Dispatch + Handler Capture
 * Tracks: handler entries, dispatch step3 (s2_eax), EDI memory dumps
 * SPECIAL: handler 0x046a4324 cipher tracing (registers + stack + memory)
 */
#include "pin.H"
#include <stdio.h>

FILE* trace;
FILE* cipherTrace;          // Separate file for cipher handler traces
PIN_LOCK traceLock;
PIN_LOCK cipherLock;
UINT64 totalHits = 0;
UINT64 maxHits = 500000;
ADDRINT lastEdi = 0;

// Cipher handler 0x046a4324 tracking
#define CIPHER_HANDLER_ADDR  0x046a4324
#define CIPHER_MAX_CAPTURES  2000
#define CIPHER_SKIP_FIRST    50000  // Skip initialization phase
static UINT64 cipherCaptureCount = 0;
static UINT64 dispatchCount = 0;
static BOOL   cipherPending = FALSE;   // Set when handler 0x046a4324 enters
static ADDRINT cipherHandlerEax, cipherHandlerEbx, cipherHandlerEcx, cipherHandlerEdx;
static ADDRINT cipherHandlerEsi, cipherHandlerEdi, cipherHandlerEsp, cipherHandlerEbp;

// Handler addresses (54 known)
static UINT32 handlerAddrs[] = {
    0x466f330, 0x46828cb, 0x468e838, 0x467b3f8, 0x4678829, 0x46822e2,
    0x469479b, 0x468f10b, 0x46a2aed, 0x466d0d2, 0x46a5502, 0x469b3ec,
    0x4672be7, 0x46a137e, 0x468875e, 0x46701f3, 0x468edf8, 0x466e344,
    0x46a4324, 0x468c835, 0x46a010f, 0x468d492, 0x46830b0, 0x46801fe,
    0x46a0bcb, 0x46772b7, 0x467d7a3, 0x469b885, 0x466e90f, 0x4685977,
    0x4685f41, 0x4687b70, 0x4692817, 0x46975f2, 0x46992c2, 0x46916c0,
    0x468cb70, 0x4699b85, 0x467233c, 0x467db00, 0x468c6e6, 0x468b70b,
    0x4692c75, 0x4699632, 0x4690b73, 0x46a5b32, 0x4681cbb, 0x468e1f2,
    0x4688e97, 0x46741fe, 0x469d191, 0x469cae2, 0x4699a1e, 0x4688032,
};
#define NUM_HANDLERS (sizeof(handlerAddrs)/sizeof(handlerAddrs[0]))

// Dispatch step3 (0x468461d): s2_eax loaded
VOID RecordDispatch(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    dispatchCount++;
    ADDRINT edi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI);
    ADDRINT eax = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX);
    ADDRINT ebx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX);
    ADDRINT esi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI);

    fprintf(trace, "D %x eax=%x ebx=%x esi=%x edi=%x\n",
            (UINT32)(ADDRINT)ip, (UINT32)eax, (UINT32)ebx,
            (UINT32)esi, (UINT32)edi);
    fflush(trace);

    // Dump EDI memory on change
    if (edi != lastEdi) {
        fprintf(trace, "EDI %x\n", (UINT32)edi);
        for (UINT32 off = 0; off < 0x1000; off += 4) {
            UINT32 val;
            if (PIN_SafeCopy(&val, (void*)(edi + off), 4) == 4) {
                fprintf(trace, "M %04x %08x\n", off, val);
            }
        }
        fprintf(trace, "END_EDI\n");
        lastEdi = edi;
    }
    PIN_ReleaseLock(&traceLock);
}

// Handler entry
VOID RecordHandler(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalHits++;
    if (totalHits <= maxHits) {
        fprintf(trace, "H %x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x\n",
                (UINT32)(ADDRINT)ip,
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI));
        fflush(trace);
    }
    PIN_ReleaseLock(&traceLock);
}

// === Cipher handler 0x046a4324 BEFORE state ===
VOID RecordCipherHandler(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&cipherLock, 1);
    cipherCaptureCount++;
    if (cipherCaptureCount <= CIPHER_SKIP_FIRST) {
        PIN_ReleaseLock(&cipherLock);
        return;
    }
    if (cipherCaptureCount <= CIPHER_SKIP_FIRST + CIPHER_MAX_CAPTURES) {
        ADDRINT eax = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX);
        ADDRINT ebx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX);
        ADDRINT ecx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX);
        ADDRINT edx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX);
        ADDRINT esi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI);
        ADDRINT edi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI);
        ADDRINT esp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESP);
        ADDRINT ebp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBP);

        fprintf(cipherTrace, "CIPHER_IN dispatch=%llu eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x esp=%x ebp=%x\n",
                (unsigned long long)dispatchCount,
                (UINT32)eax, (UINT32)ebx, (UINT32)ecx, (UINT32)edx,
                (UINT32)esi, (UINT32)edi, (UINT32)esp, (UINT32)ebp);

        // Stack dump: 32 bytes from ESP (8 x DWORD)
        fprintf(cipherTrace, "STACK");
        for (UINT32 off = 0; off < 32; off += 4) {
            UINT32 val = 0;
            PIN_SafeCopy(&val, (void*)(esp + off), 4);
            fprintf(cipherTrace, " [esp+%02x]=%08x", off, val);
        }
        fprintf(cipherTrace, "\n");

        // Memory dump: 64 bytes from EDI (16 x DWORD)
        fprintf(cipherTrace, "MEMORY");
        for (UINT32 off = 0; off < 64; off += 4) {
            UINT32 val = 0;
            PIN_SafeCopy(&val, (void*)(edi + off), 4);
            fprintf(cipherTrace, " [edi+%02x]=%08x", off, val);
        }
        fprintf(cipherTrace, "\n");
        fflush(cipherTrace);

        // Save for after-state comparison
        cipherHandlerEax = eax;
        cipherHandlerEbx = ebx;
        cipherHandlerEcx = ecx;
        cipherHandlerEdx = edx;
        cipherHandlerEsi = esi;
        cipherHandlerEdi = edi;
        cipherHandlerEsp = esp;
        cipherHandlerEbp = ebp;
        cipherPending = TRUE;
    }
    PIN_ReleaseLock(&cipherLock);
}

// === Cipher handler 0x046a4324 AFTER state (at next dispatch step3) ===
VOID RecordCipherAfter(VOID* ip, CONTEXT* ctx)
{
    if (!cipherPending) return;

    PIN_GetLock(&cipherLock, 1);
    if (cipherPending && cipherCaptureCount > CIPHER_SKIP_FIRST && cipherCaptureCount <= CIPHER_SKIP_FIRST + CIPHER_MAX_CAPTURES) {
        ADDRINT eax = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX);
        ADDRINT ebx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX);
        ADDRINT ecx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX);
        ADDRINT edx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX);
        ADDRINT esi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI);
        ADDRINT edi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI);
        ADDRINT esp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESP);
        ADDRINT ebp = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBP);

        fprintf(cipherTrace, "CIPHER_OUT dispatch=%llu eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x esp=%x ebp=%x\n",
                (unsigned long long)dispatchCount,
                (UINT32)eax, (UINT32)ebx, (UINT32)ecx, (UINT32)edx,
                (UINT32)esi, (UINT32)edi, (UINT32)esp, (UINT32)ebp);

        // After-state stack dump
        fprintf(cipherTrace, "STACK_AFTER");
        for (UINT32 off = 0; off < 32; off += 4) {
            UINT32 val = 0;
            PIN_SafeCopy(&val, (void*)(esp + off), 4);
            fprintf(cipherTrace, " [esp+%02x]=%08x", off, val);
        }
        fprintf(cipherTrace, "\n");

        // After-state memory dump (EDI may have changed)
        fprintf(cipherTrace, "MEMORY_AFTER");
        for (UINT32 off = 0; off < 64; off += 4) {
            UINT32 val = 0;
            PIN_SafeCopy(&val, (void*)(edi + off), 4);
            fprintf(cipherTrace, " [edi+%02x]=%08x", off, val);
        }
        fprintf(cipherTrace, "\n");

        // Delta summary: which registers changed
        fprintf(cipherTrace, "DELTA");
        if ((UINT32)eax != (UINT32)cipherHandlerEax) fprintf(cipherTrace, " EAX:%x->%x", (UINT32)cipherHandlerEax, (UINT32)eax);
        if ((UINT32)ebx != (UINT32)cipherHandlerEbx) fprintf(cipherTrace, " EBX:%x->%x", (UINT32)cipherHandlerEbx, (UINT32)ebx);
        if ((UINT32)ecx != (UINT32)cipherHandlerEcx) fprintf(cipherTrace, " ECX:%x->%x", (UINT32)cipherHandlerEcx, (UINT32)ecx);
        if ((UINT32)edx != (UINT32)cipherHandlerEdx) fprintf(cipherTrace, " EDX:%x->%x", (UINT32)cipherHandlerEdx, (UINT32)edx);
        if ((UINT32)esi != (UINT32)cipherHandlerEsi) fprintf(cipherTrace, " ESI:%x->%x", (UINT32)cipherHandlerEsi, (UINT32)esi);
        if ((UINT32)edi != (UINT32)cipherHandlerEdi) fprintf(cipherTrace, " EDI:%x->%x", (UINT32)cipherHandlerEdi, (UINT32)edi);
        if ((UINT32)esp != (UINT32)cipherHandlerEsp) fprintf(cipherTrace, " ESP:%x->%x", (UINT32)cipherHandlerEsp, (UINT32)esp);
        if ((UINT32)ebp != (UINT32)cipherHandlerEbp) fprintf(cipherTrace, " EBP:%x->%x", (UINT32)cipherHandlerEbp, (UINT32)ebp);
        fprintf(cipherTrace, "\n---\n");
        fflush(cipherTrace);

        cipherPending = FALSE;
    }
    PIN_ReleaseLock(&cipherLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    UINT32 a = (UINT32)addr;

    // Dispatch step3: also serves as "after" hook for cipher handler
    if (a == 0x468461d) {
        // First: record cipher after-state (if handler 0x046a4324 just ran)
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordCipherAfter,
                       IARG_INST_PTR, IARG_CONTEXT, IARG_END);
        // Then: normal dispatch recording
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDispatch,
                       IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }

    // Cipher handler 0x046a4324: special full capture (BEFORE state)
    if (a == CIPHER_HANDLER_ADDR) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordCipherHandler,
                       IARG_INST_PTR, IARG_CONTEXT, IARG_END);
        // Also do normal handler recording
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordHandler,
                       IARG_INST_PTR, IARG_CONTEXT, IARG_END);
        return;
    }

    // Handler entries (all others)
    for (int i = 0; i < NUM_HANDLERS; i++) {
        if (a == handlerAddrs[i]) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordHandler,
                           IARG_INST_PTR, IARG_CONTEXT, IARG_END);
            return;
        }
    }
}

VOID Fini(INT32 code, VOID* v) {
    fprintf(trace, "#eof total=%llu\n", totalHits);
    fclose(trace);
    fprintf(cipherTrace, "#eof cipher_captures=%llu dispatches=%llu\n",
            (unsigned long long)cipherCaptureCount, (unsigned long long)dispatchCount);
    fclose(cipherTrace);
}

int main(int argc, char* argv[])
{
    trace = fopen("vmp_context_trace.out", "w");
    if (!trace) return 1;
    cipherTrace = fopen("vmp_network_trace.out", "w");
    if (!cipherTrace) { fclose(trace); return 1; }

    fprintf(trace, "#start\n");
    fprintf(cipherTrace, "#start cipher_handler=0x%x max_captures=%d\n",
            CIPHER_HANDLER_ADDR, CIPHER_MAX_CAPTURES);
    fflush(trace);
    fflush(cipherTrace);

    PIN_InitLock(&traceLock);
    PIN_InitLock(&cipherLock);

    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
