#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalCalls = 0;

// Dispatch loop range
#define DISPATCH_START 0x4684500
#define DISPATCH_END   0x4684700

// Record when execution leaves dispatch loop (handler call)
VOID RecordHandler(VOID* target, VOID* from)
{
    PIN_GetLock(&traceLock, 1);
    totalCalls++;
    fprintf(trace, "call %x from %x\n", (UINT32)(ADDRINT)target, (UINT32)(ADDRINT)from);
    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    
    // If this instruction is at the end of dispatch loop range,
    // and it's a jump/call, record the target
    if (addr >= DISPATCH_START && addr < DISPATCH_END) {
        // Check if this is a jump or call instruction
        if (INS_IsBranchOrCall(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordHandler,
                IARG_BRANCH_TARGET_ADDR,
                IARG_INST_PTR,
                IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID* v) { 
    fprintf(trace, "#eof total_calls=%llu\n", totalCalls); 
    fclose(trace); 
}

int main(int argc, char* argv[])
{
    trace = fopen("vmp_dispatch.out", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
