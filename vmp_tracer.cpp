/*
 * VMP 3.6 VM Context + Dispatch + Handler + Network Capture
 * Tracks: handler entries, dispatch step3 (s2_eax), EDI memory dumps,
 *         ws2_32!send and ws2_32!recv buffer contents
 */
#include "pin.H"
#include <stdio.h>

FILE* trace;
PIN_LOCK traceLock;
UINT64 totalHits = 0;
UINT64 maxHits = 100000;
UINT64 dispatchCount = 0;
ADDRINT lastEdi = 0;

// Handler addresses (54 known)
static UINT32 handlerAddrs[] = {
    0x466f330, 0x46828cb, 0x468e838, 0x467b3f8, 0x4678829, 0x46822e2,
    0x469479b, 0x468f10b, 0x46a2aed, 0x466d0d2, 0x46a5502, 0x469b3ec,
    0x4672be7, 0x46a137e, 0x468875e, 0x46701f3, 0x468edf8, 0x466e344,
    0x46a4324, 0x468c835, 0x46a010f, 0x468d492, 0x46830b0, 0x46801fe,
    0x46a0bcb, 0x46772b7, 0x467d7a3, 0x469b885, 0x466e90f, 0x4685977,
    0x4685f41, 0x4687b70, 0x4692817, 0x46975f2, 0x46992c2, 0x46916c0,
    0x468cb70, 0x4699b85, 0x467233c, 0x467db00, 0x468c6e6, 0x468b70b,
    0x4692c75, 0x4699632, 0x4690b73, 0x46a5b32, 0x4681cbb, 0x468e1f2,
    0x4688e97, 0x46741fe, 0x469d191, 0x469cae2, 0x4699a1e, 0x4688032,
};
#define NUM_HANDLERS (sizeof(handlerAddrs)/sizeof(handlerAddrs[0]))

// Dispatch step3 (0x468461d): s2_eax loaded
VOID RecordDispatch(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    dispatchCount++;
    ADDRINT edi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI);
    ADDRINT eax = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX);
    ADDRINT ebx = PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX);
    ADDRINT esi = PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI);

    fprintf(trace, "D %llu %x eax=%x ebx=%x esi=%x edi=%x\n",
            dispatchCount, (UINT32)(ADDRINT)ip, (UINT32)eax, (UINT32)ebx,
            (UINT32)esi, (UINT32)edi);

    // Dump EDI memory on change
    if (edi != lastEdi) {
        fprintf(trace, "EDI %x\n", (UINT32)edi);
        for (UINT32 off = 0; off < 0x1000; off += 4) {
            UINT32 val;
            if (PIN_SafeCopy(&val, (void*)(edi + off), 4) == 4) {
                fprintf(trace, "M %04x %08x\n", off, val);
            }
        }
        fprintf(trace, "END_EDI\n");
        lastEdi = edi;
    }
    PIN_ReleaseLock(&traceLock);
}

// Handler entry
VOID RecordHandler(VOID* ip, CONTEXT* ctx)
{
    PIN_GetLock(&traceLock, 1);
    totalHits++;
    if (totalHits <= maxHits) {
        fprintf(trace, "H %llu %x eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x\n",
                dispatchCount, (UINT32)(ADDRINT)ip,
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EAX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EBX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ECX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDX),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_ESI),
                (UINT32)PIN_GetContextReg(ctx, LEVEL_BASE::REG_EDI));
    }
    PIN_ReleaseLock(&traceLock);
}

// Network: send() - capture outbound data
// int send(SOCKET s, const char* buf, int len, int flags);
VOID RecordSendBefore(VOID* ip, CONTEXT* ctx, ADDRINT bufAddr, ADDRINT len)
{
    PIN_GetLock(&traceLock, 1);
    UINT32 bufLen = (UINT32)len;
    if (bufLen > 8192) bufLen = 8192;  // cap at 8KB

    fprintf(trace, "SEND %llu len=%u\n", dispatchCount, bufLen);

    // Dump buffer contents
    if (bufLen > 0 && bufLen <= 8192) {
        UINT8* buf = new UINT8[bufLen];
        size_t copied = PIN_SafeCopy(buf, (void*)bufAddr, bufLen);
        fprintf(trace, "HEX ");
        for (size_t i = 0; i < copied; i++) {
            fprintf(trace, "%02x", buf[i]);
        }
        fprintf(trace, "\n");
        delete[] buf;
    }
    PIN_ReleaseLock(&traceLock);
}

// Network: recv() - capture inbound data
// int recv(SOCKET s, char* buf, int len, int flags);
// We record AFTER recv returns, so we need the return value
VOID RecordRecvAfter(VOID* ip, CONTEXT* ctx, ADDRINT retVal, ADDRINT bufAddr, ADDRINT len)
{
    PIN_GetLock(&traceLock, 1);
    INT32 recvLen = (INT32)retVal;
    if (recvLen <= 0 || recvLen > 8192) {
        PIN_ReleaseLock(&traceLock);
        return;
    }

    fprintf(trace, "RECV %llu len=%u\n", dispatchCount, recvLen);

    // Dump received data
    UINT8* buf = new UINT8[recvLen];
    size_t copied = PIN_SafeCopy(buf, (void*)bufAddr, recvLen);
    fprintf(trace, "HEX ");
    for (size_t i = 0; i < copied; i++) {
        fprintf(trace, "%02x", buf[i]);
    }
    fprintf(trace, "\n");
    delete[] buf;
    PIN_ReleaseLock(&traceLock);
}

VOID Instruction(INS ins, VOID* v)
{
    ADDRINT addr = INS_Address(ins);
    UINT32 a = (UINT32)addr;

    // Dispatch step3
    if (a == 0x468461d) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDispatch,
                       IARG_INST_PTR, IARG_CONTEXT, IARG_END);
    }

    // Handler entries
    for (int i = 0; i < NUM_HANDLERS; i++) {
        if (a == handlerAddrs[i]) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordHandler,
                           IARG_INST_PTR, IARG_CONTEXT, IARG_END);
            return;
        }
    }
}

// Image load callback - hook ws2_32.dll exports
VOID ImageLoad(IMG img, VOID* v)
{
    const char* imgName = IMG_Name(img).c_str();

    // Only hook ws2_32.dll
    if (IMG_Name(img).find("ws2_32") == std::string::npos &&
        IMG_Name(img).find("WS2_32") == std::string::npos) {
        return;
    }

    fprintf(trace, "#loaded %s base=%x\n", imgName, (UINT32)IMG_StartAddress(img));

    // Hook send()
    RTN sendRtn = RTN_FindByName(img, "send");
    if (RTN_Valid(sendRtn)) {
        fprintf(trace, "#hook send at %x\n", (UINT32)RTN_Address(sendRtn));
        RTN_Open(sendRtn);
        // send(SOCKET s, const char* buf, int len, int flags)
        // arg0=socket, arg1=buf, arg2=len
        INS_InsertCall(RTN_InsHead(sendRtn), IPOINT_BEFORE, (AFUNPTR)RecordSendBefore,
                       IARG_INST_PTR, IARG_CONTEXT,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                       IARG_END);
        RTN_Close(sendRtn);
    }

    // Hook recv() - need to capture AFTER it returns
    RTN recvRtn = RTN_FindByName(img, "recv");
    if (RTN_Valid(recvRtn)) {
        fprintf(trace, "#hook recv at %x\n", (UINT32)RTN_Address(recvRtn));
        RTN_Open(recvRtn);
        // recv(SOCKET s, char* buf, int len, int flags)
        // We need return value (bytes received) and buf address
        INS_InsertCall(RTN_InsHead(recvRtn), IPOINT_AFTER, (AFUNPTR)RecordRecvAfter,
                       IARG_INST_PTR, IARG_CONTEXT,
                       IARG_FUNCRET_EXITPOINT_VALUE,     // return value
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                       IARG_END);
        RTN_Close(recvRtn);
    }
}

VOID Fini(INT32 code, VOID* v) {
    fprintf(trace, "#eof total=%llu dispatches=%llu\n", totalHits, dispatchCount);
    fclose(trace);
}

int main(int argc, char* argv[])
{
    trace = fopen("vmp_network_trace.out", "w");
    if (!trace) return 1;
    PIN_InitLock(&traceLock);
    if (PIN_Init(argc, argv)) return -1;
    INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
