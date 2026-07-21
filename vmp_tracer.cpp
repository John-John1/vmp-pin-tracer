#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalHits = 0;
UINT64 maxHits = 50000;  // 限制记录量

// Dispatch loop region
#define DISPATCH_START 0x46845ab
#define DISPATCH_END   0x4684630

VOID RecordInsn(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalHits++;
    
    if (totalHits <= maxHits) {
        UINT32 rip = (UINT32)(ADDRINT)ip;
        fprintf(trace, "%x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x\n",
                rip,
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI));
    }
    
    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    UINT32 a = (UINT32)addr;
    
    // Only trace dispatch loop region
    if (a >= DISPATCH_START && a < DISPATCH_END) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInsn, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }
}

VOID Fini(INT32 code, VOID* v) { 
    fprintf(trace, "#eof total=%llu\n", totalHits); 
    fclose(trace); 
}

int main(int argc, char* argv[])
{
    trace = fopen("vmp_full_trace.out", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
