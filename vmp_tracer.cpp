#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalHits = 0;
UINT64 maxHits = 50000;
BOOL bytecodeDumped = FALSE;

// Handler addresses to trigger bytecode dump
static UINT32 handlerAddrs[] = {
    0x466f330, 0x46828cb, 0x468e838, 0x467b3f8, 0x4678829, 0x46822e2,
    0x469479b, 0x468f10b, 0x46a2aed, 0x466d0d2, 0x46a5502, 0x469b3ec,
    0x4672be7, 0x46a137e, 0x468875e, 0x46701f3, 0x468edf8, 0x466e344,
    0x46a4324, 0x468c835, 0x46a010f, 0x468d492, 0x46830b0, 0x46801fe,
};
#define NUM_HANDLERS (sizeof(handlerAddrs)/sizeof(handlerAddrs[0]))

// Dispatch loop addresses
static UINT32 dispatchAddrs[] = {
    0x46845ba,  // ret (jump to handler)
    0x46845fb,  // mov [edi+eax], ecx (write to table)
    0x4684603,  // mov eax, [esi] (read bytecode)
    0x468461d,  // sub ebx, eax (modify EBX)
};
#define NUM_DISPATCH (sizeof(dispatchAddrs)/sizeof(dispatchAddrs[0]))

// Dump bytecode region
VOID DumpBytecode(VOID* ip)
{
    if (bytecodeDumped) return;
    bytecodeDumped = TRUE;
    
    PIN_GetLock(&traceLock, 1);
    
    // Bytecode region from previous analysis
    UINT32 bc_start = 0x048183df;
    UINT32 bc_end = 0x0483b8e3;
    UINT32 size = bc_end - bc_start;
    
    fprintf(trace, "BYTECODE %x %x\n", bc_start, bc_end);
    
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
    
    fprintf(trace, "END_BYTECODE\n");
    PIN_ReleaseLock(&traceLock);
}

// Record dispatch loop execution
VOID RecordDispatch(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalHits++;
    
    if (totalHits <= maxHits) {
        UINT32 rip = (UINT32)(ADDRINT)ip;
        fprintf(trace, "D %x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x\n",
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
    
    // Check if this is a handler address (trigger bytecode dump)
    for (int i = 0; i < NUM_HANDLERS; i++) {
        if (a == handlerAddrs[i]) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DumpBytecode, IARG_INST_PTR, IARG_END);
            break;
        }
    }
    
    // Check if this is a dispatch loop address (record trace)
    for (int i = 0; i < NUM_DISPATCH; i++) {
        if (a == dispatchAddrs[i]) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDispatch, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
            break;
        }
    }
}

VOID Fini(INT32 code, VOID* v) { 
    fprintf(trace, "#eof total=%llu\n", totalHits); 
    fclose(trace); 
}

int main(int argc, char* argv[])
{
    trace = fopen("vmp_combined.out", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
