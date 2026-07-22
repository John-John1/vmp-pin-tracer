/*
 * VMP 3.6 VM Context + Dispatch + Handler Capture
 * Tracks: handler entries, dispatch step3 (s2_eax), EDI memory dumps
 */
#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalHits = 0;
UINT64 maxHits = 500000;
ADDRINT lastEdi = 0;

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

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    UINT32 a = (UINT32)addr;

    // Dispatch step3
    if (a == 0x468461d) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDispatch,
                       IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }

    // Handler entries
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
}

int main(int argc, char* argv[])
{
    trace = fopen("vmp_context_trace.out", "w");
    if (!trace) return 1;
    fprintf(trace, "#start\n");
    fflush(trace);
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
