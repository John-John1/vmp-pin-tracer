#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
BOOL dumped = FALSE;

// Handler addresses to trigger dump
static UINT32 handlerAddrs[] = {
    0x466f330, 0x46828cb, 0x468e838, 0x467b3f8, 0x4678829, 0x46822e2,
    0x469479b, 0x468f10b, 0x46a2aed, 0x466d0d2, 0x46a5502, 0x469b3ec,
    0x4672be7, 0x46a137e, 0x468875e, 0x46701f3, 0x468edf8, 0x466e344,
    0x46a4324, 0x468c835, 0x46a010f, 0x468d492, 0x46830b0, 0x46801fe,
};
#define NUM_HANDLERS (sizeof(handlerAddrs)/sizeof(handlerAddrs[0]))

VOID DumpBytecode(VOID* ip)
{
    if (dumped) return;
    dumped = TRUE;
    
    PIN_GetLock(&traceLock, 1);
    
    // Bytecode region
    UINT32 bc_start = 0x048183df;
    UINT32 bc_end = 0x0483b8e3;
    UINT32 size = bc_end - bc_start;
    
    fprintf(trace, "BYTECODE %x %x\n", bc_start, bc_end);
    
    // Dump in hex
    for (UINT32 offset = 0; offset < size; offset += 16) {
        fprintf(trace, "%08x: ", bc_start + offset);
        for (UINT32 i = 0; i < 16 && (offset + i) < size; i++) {
            UINT8 byte;
            if (PIN_SafeCopy(&byte, (void*)(bc_start + offset + i), 1) == 1) {
                fprintf(trace, "%02x ", byte);
            } else {
                fprintf(trace, "?? ");
            }
        }
        fprintf(trace, "\n");
    }
    
    fprintf(trace, "END\n");
    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    UINT32 a = (UINT32)addr;
    
    // Trigger dump when any handler is executed
    for (int i = 0; i < NUM_HANDLERS; i++) {
        if (a == handlerAddrs[i]) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DumpBytecode, IARG_INST_PTR, IARG_END);
            return;
        }
    }
}

VOID Fini(INT32 code, VOID* v) { fclose(trace); }

int main(int argc, char* argv[])
{
    trace = fopen("vmp_bytecode.bin", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
