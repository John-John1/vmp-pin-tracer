#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;

// Handler addresses to dump
static UINT32 handlerAddrs[] = {
    0x466f330, 0x46828cb, 0x468e838, 0x467b3f8, 0x4678829, 0x46822e2,
    0x469479b, 0x468f10b, 0x46a2aed, 0x466d0d2, 0x46a5502, 0x469b3ec,
    0x4672be7, 0x46a137e, 0x468875e, 0x46701f3, 0x468edf8, 0x466e344,
    0x46a4324, 0x468c835, 0x46a010f, 0x468d492, 0x46830b0, 0x46801fe,
    0x46a0bcb, 0x46772b7, 0x467d7a3, 0x469b885, 0x466e90f, 0x4685f41,
    0x468c119, 0x46975f2, 0x467a5f0, 0x4688e97, 0x46741fe, 0x46992c2,
    0x46916c0, 0x468cb70, 0x4699b85, 0x46a16ac, 0x467233c, 0x467db00,
    0x468c6e6, 0x468b70b, 0x4692817, 0x4699632, 0x4690b73, 0x46a5b32,
    0x4681cbb, 0x4685977, 0x468e1f2, 0x4687b70, 0x469d191, 0x469cae2,
    0x4699a1e, 0x4692c75, 0x4688032, 0x46705d8, 0x4690b73,
};
#define NUM_HANDLERS (sizeof(handlerAddrs)/sizeof(handlerAddrs[0]))

BOOL dumped = FALSE;

VOID DumpHandlers(VOID* ip, CONTEXT* ctx)
{
    if (dumped) return;
    dumped = TRUE;
    
    PIN_GetLock(&traceLock, 1);
    
    for (int i = 0; i < NUM_HANDLERS; i++) {
        UINT32 addr = handlerAddrs[i];
        // Read 64 bytes at handler address
        fprintf(trace, "HANDLER %x ", addr);
        for (int j = 0; j < 64; j++) {
            UINT8 byte;
            if (PIN_SafeCopy(&byte, (void*)(addr + j), 1) == 1) {
                fprintf(trace, "%02x", byte);
            } else {
                fprintf(trace, "??");
            }
        }
        fprintf(trace, "\n");
    }
    
    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    // Trigger dump when we hit any handler address
    for (int i = 0; i < NUM_HANDLERS; i++) {
        if ((UINT32)addr == handlerAddrs[i]) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DumpHandlers, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
            return;
        }
    }
}

VOID Fini(INT32 code, VOID* v) { fclose(trace); }

int main(int argc, char* argv[])
{
    trace = fopen("vmp_handler_code.bin", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
