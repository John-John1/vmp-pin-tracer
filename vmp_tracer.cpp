#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
BOOL dumped = FALSE;

// Bytecode region from trace analysis
#define BC_START 0x048183df
#define BC_END   0x0483b8e3

VOID DumpBytecode(VOID* ip)
{
    if (dumped) return;
    dumped = TRUE;
    
    PIN_GetLock(&traceLock, 1);
    
    fprintf(trace, "BYTECODE %x %x\n", BC_START, BC_END);
    
    // Dump bytecode region in hex
    UINT32 size = BC_END - BC_START;
    for (UINT32 offset = 0; offset < size; offset += 16) {
        fprintf(trace, "%08x: ", BC_START + offset);
        for (UINT32 i = 0; i < 16 && (offset + i) < size; i++) {
            UINT8 byte;
            if (PIN_SafeCopy(&byte, (void*)(BC_START + offset + i), 1) == 1) {
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
    // Trigger dump when execution enters bytecode region
    if ((UINT32)addr >= BC_START && (UINT32)addr < BC_END) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DumpBytecode, IARG_INST_PTR, IARG_END);
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
