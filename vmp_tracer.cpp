#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalHits = 0;

// Core handler addresses from dispatch analysis
struct Handler {
    UINT32 addr;
    const char* name;
};

static Handler handlers[] = {
    {0x466f330, "H1"}, {0x46828cb, "H2"}, {0x468e838, "H3"}, {0x467b3f8, "H4"},
    {0x4678829, "H5"}, {0x46822e2, "H6"}, {0x469479b, "H7"}, {0x468f10b, "H8"},
    {0x46a2aed, "H9"}, {0x466d0d2, "H10"}, {0x46a5502, "H11"}, {0x469b3ec, "H12"},
    {0x4672be7, "H13"}, {0x46a137e, "H14"}, {0x468875e, "H15"}, {0x46701f3, "H16"},
    {0x468edf8, "H17"}, {0x466e344, "H18"}, {0x46a4324, "H19"}, {0x468c835, "H20"},
    {0x46a010f, "H21"}, {0x468d492, "H22"}, {0x46830b0, "H23"}, {0x46801fe, "H24"},
    {0x46a0bcb, "H25"}, {0x46772b7, "H26"}, {0x467d7a3, "H27"}, {0x469b885, "H28"},
    {0x466e90f, "H29"}, {0x467b3f8, "H30"}, {0x4685f41, "H31"}, {0x468c119, "H32"},
    {0x46975f2, "H33"}, {0x467a5f0, "H34"}, {0x4688e97, "H35"}, {0x46741fe, "H36"},
    {0x46992c2, "H37"}, {0x46916c0, "H38"}, {0x468cb70, "H39"}, {0x4699b85, "H40"},
    {0x46a16ac, "H41"}, {0x467233c, "H42"}, {0x467db00, "H43"}, {0x468c6e6, "H44"},
    {0x468b70b, "H45"}, {0x4692817, "H46"}, {0x4699632, "H47"}, {0x4690b73, "H48"},
    {0x46a5b32, "H49"}, {0x4681cbb, "H50"}, {0x4685977, "H51"}, {0x468e1f2, "H52"},
    {0x4687b70, "H53"}, {0x469d191, "H54"}, {0x469cae2, "H55"}, {0x46822e2, "H56"},
    {0x4699a1e, "H57"}, {0x4692c75, "H58"}, {0x4688032, "H59"}, {0x46705d8, "H60"},
};

#define NUM_HANDLERS (sizeof(handlers)/sizeof(handlers[0]))

const char* findHandler(UINT32 addr) {
    for (int i = 0; i < NUM_HANDLERS; i++) {
        if (handlers[i].addr == addr) return handlers[i].name;
    }
    return NULL;
}

VOID RecordHit(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalHits++;
    UINT32 rip = (UINT32)(ADDRINT)ip;
    const char* name = findHandler(rip);
    if (name) {
        fprintf(trace, "%s %x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x esp=%x ebp=%x\n",
                name, rip,
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESP),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBP));
    }
    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    UINT32 a = (UINT32)addr;
    
    // Check if this address is one of our handlers
    if (findHandler(a)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordHit, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }
}

VOID Fini(INT32 code, VOID* v) { 
    fprintf(trace, "#eof total=%llu\n", totalHits); 
    fclose(trace); 
}

int main(int argc, char* argv[])
{
    trace = fopen("vmp_handlers.out", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
