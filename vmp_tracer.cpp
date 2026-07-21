#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalInsns = 0;

VOID RecordInsn(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalInsns++;
    fprintf(trace, "%x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x esp=%x ebp=%x\n",
            (UINT32)(ADDRINT)ip,
            (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX),
            (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX),
            (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX),
            (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX),
            (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI),
            (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI),
            (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESP),
            (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBP));
    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    // Only trace handler region 0x4600000 - 0x4700000
    if (addr >= 0x4600000 && addr < 0x4700000) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInsn, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }
}

VOID Fini(INT32 code, VOID* v) { fprintf(trace, "#eof %llu\n", totalInsns); fclose(trace); }

int main(int argc, char* argv[])
{
    trace = fopen("vmp_handler_trace.out", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
