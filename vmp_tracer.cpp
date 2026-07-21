#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalHits = 0;

// Dispatch loop addresses (key instructions)
static UINT32 dispatchAddrs[] = {
    0x46845ab,  // add eax, 0x4350ab0 (start of dispatch)
    0x46845ba,  // ret (jump to handler)
    0x46845fb,  // mov [edi+eax], ecx (write to table)
    0x4684603,  // mov eax, [esi] (read bytecode)
    0x468460f,  // ror eax, 0x17 (decrypt)
    0x468461d,  // sub ebx, eax (modify EBX)
    0x4684622,  // lea eax, [eax+0x204774de] (compute next handler)
    0x468462c,  // jmp 0x46845ab (loop)
};
#define NUM_DISPATCH (sizeof(dispatchAddrs)/sizeof(dispatchAddrs[0]))

VOID RecordDispatch(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalHits++;
    
    UINT32 rip = (UINT32)(ADDRINT)ip;
    fprintf(trace, "%x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x esp=%x ebp=%x\n",
            rip,
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
    UINT32 a = (UINT32)addr;
    
    for (int i = 0; i < NUM_DISPATCH; i++) {
        if (a == dispatchAddrs[i]) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDispatch, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
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
    trace = fopen("vmp_dispatch_trace.out", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
