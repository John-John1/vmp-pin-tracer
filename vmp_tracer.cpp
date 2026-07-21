#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalHits = 0;
UINT64 maxHits = 100000;
BOOL contextDumped = FALSE;

// Handler addresses to trigger context dump and trace
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

// Dump VM context memory
VOID DumpContext(VOID* ip, CONTEXT* ctx)
{
    if (contextDumped) return;
    contextDumped = TRUE;
    
    PIN_GetLock(&traceLock, 1);
    
    // Read EDI to get VM context base
    ADDRINT edi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI);
    fprintf(trace, "CONTEXT edi=%x\n", (UINT32)edi);
    
    // Dump VM context (4KB)
    for (UINT32 offset = 0; offset < 0x1000; offset += 16) {
        fprintf(trace, "C %04x: ", offset);
        for (UINT32 i = 0; i < 16; i += 4) {
            UINT32 val;
            if (PIN_SafeCopy(&val, (void*)(edi + offset + i), 4) == 4) {
                fprintf(trace, "%08x ", val);
            } else {
                fprintf(trace, "???????? ");
            }
        }
        fprintf(trace, "\n");
    }
    
    fprintf(trace, "END_CONTEXT\n");
    PIN_ReleaseLock(&traceLock);
}

// Record handler execution
VOID RecordHandler(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalHits++;
    
    if (totalHits <= maxHits) {
        UINT32 rip = (UINT32)(ADDRINT)ip;
        UINT32 eax = (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX);
        UINT32 ebx = (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX);
        UINT32 ecx = (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX);
        UINT32 edx = (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX);
        UINT32 esi = (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI);
        UINT32 edi = (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI);
        
        fprintf(trace, "H %x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x\n",
                rip, eax, ebx, ecx, edx, esi, edi);
    }
    
    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    UINT32 a = (UINT32)addr;
    
    for (int i = 0; i < NUM_HANDLERS; i++) {
        if (a == handlerAddrs[i]) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DumpContext, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordHandler, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
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
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
