/*
 * VMP Tracer - Traces VMProtect handler execution (IA-32)
 * Records RIP and register values for offline analysis
 */

#include <stdio.h>
#include <string.h>
#include "pin.H"

FILE* trace;
PIN_LOCK traceLock;

ADDRINT appBase = 0;
ADDRINT appEnd = 0;

UINT64 totalInsns = 0;

VOID RecordInsn(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalInsns++;

    ADDRINT rip = (ADDRINT)ip;
    ADDRINT eax = PIN_GetContextReg(ctx, REG_EAX);
    ADDRINT ebx = PIN_GetContextReg(ctx, REG_EBX);
    ADDRINT ecx = PIN_GetContextReg(ctx, REG_ECX);
    ADDRINT edx = PIN_GetContextReg(ctx, REG_EDX);
    ADDRINT esi = PIN_GetContextReg(ctx, REG_ESI);
    ADDRINT edi = PIN_GetContextReg(ctx, REG_EDI);
    ADDRINT esp = PIN_GetContextReg(ctx, REG_ESP);
    ADDRINT ebp = PIN_GetContextReg(ctx, REG_EBP);

    fprintf(trace, "%x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x esp=%x ebp=%x\n",
            (UINT32)rip, (UINT32)eax, (UINT32)ebx, (UINT32)ecx,
            (UINT32)edx, (UINT32)esi, (UINT32)edi, (UINT32)esp,
            (UINT32)ebp);

    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    if (addr >= appBase && addr < appEnd) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInsn,
                       IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }
}

VOID ImageLoad(IMG img, VOID* v)
{
    if (IMG_IsMainExecutable(img)) {
        appBase = IMG_LowAddress(img);
        appEnd = IMG_HighAddress(img);
        fprintf(trace, "# Module base=%x end=%x\n",
                (UINT32)appBase, (UINT32)appEnd);
        fflush(trace);
    }
}

VOID Fini(INT32 code, VOID* v)
{
    fprintf(trace, "# Total: %llu\n", totalInsns);
    fprintf(trace, "#eof\n");
    fclose(trace);
}

INT32 Usage()
{
    PIN_ERROR("VMP Tracer for IA-32\n");
    return -1;
}

int main(int argc, char* argv[])
{
    trace = fopen("vmp_trace.out", "w");
    if (!trace) return 1;

    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return Usage();

    INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
