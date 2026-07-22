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
UINT64 maxHits = 200000;
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

// Network: connect() - trace connection attempts
// int connect(SOCKET s, const struct sockaddr* name, int namelen);
VOID RecordConnectBefore(VOID* ip, CONTEXT* ctx, ADDRINT nameAddr, ADDRINT namelen)
{
    PIN_GetLock(&traceLock, 1);
    // sockaddr_in: family(2) + port(2) + addr(4) + pad(8)
    UINT8 addrBuf[16];
    if (namelen >= 16 && PIN_SafeCopy(addrBuf, (void*)nameAddr, 16) == 16) {
        UINT16 family = *(UINT16*)addrBuf;
        UINT16 port = *(UINT16*)(addrBuf + 2);
        UINT32 ipAddr = *(UINT32*)(addrBuf + 4);
        port = ((port >> 8) & 0xff) | ((port & 0xff) << 8); // ntohs
        fprintf(trace, "CONN %llu family=%u port=%u addr=%u.%u.%u.%u\n",
                dispatchCount, family, port,
                ipAddr & 0xff, (ipAddr >> 8) & 0xff,
                (ipAddr >> 16) & 0xff, (ipAddr >> 24) & 0xff);
    }
    PIN_ReleaseLock(&traceLock);
}

// Try to hook a function by name in an image
BOOL TryHookFunc(IMG img, const char* funcName, BOOL isRecv)
{
    RTN rtn = RTN_FindByName(img, funcName);
    if (!RTN_Valid(rtn)) return FALSE;

    fprintf(trace, "#hook %s at %x\n", funcName, (UINT32)RTN_Address(rtn));
    RTN_Open(rtn);

    if (isRecv) {
        // recv: capture after return, need ret val + buf + len
        INS_InsertCall(RTN_InsHead(rtn), IPOINT_AFTER, (AFUNPTR)RecordRecvAfter,
                       IARG_INST_PTR, IARG_CONTEXT,
                       IARG_FUNCRET_EXITPOINT_VALUE,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                       IARG_END);
    } else {
        // send: capture before call, need buf + len
        INS_InsertCall(RTN_InsHead(rtn), IPOINT_BEFORE, (AFUNPTR)RecordSendBefore,
                       IARG_INST_PTR, IARG_CONTEXT,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                       IARG_END);
    }
    RTN_Close(rtn);
    return TRUE;
}

// Image load callback - hook network functions
VOID ImageLoad(IMG img, VOID* v)
{
    // Log all loaded DLLs
    fprintf(trace, "#dll %s base=%x size=%x\n",
            IMG_Name(img).c_str(),
            (UINT32)IMG_StartAddress(img),
            (UINT32)IMG_SizeMapped(img));

    std::string imgLower = IMG_Name(img);
    // Convert to lowercase for comparison
    for (auto& c : imgLower) c = tolower(c);

    // Hook ws2_32.dll - by address from PE export table
    if (imgLower.find("ws2_32") != std::string::npos) {
        ADDRINT base = IMG_StartAddress(img);
        fprintf(trace, "#loaded ws2_32 base=%x size=%x\n",
                (UINT32)base, (UINT32)IMG_SizeMapped(img));

        struct { const char* name; UINT32 rva; BOOL isRecv; BOOL isConn; } targets[] = {
            {"send",    0x176b0, FALSE, FALSE},
            {"recv",    0x16e00, TRUE,  FALSE},
            {"connect", 0x17840, FALSE, TRUE},
            {"WSASend", 0x10ab0, FALSE, FALSE},
            {"WSARecv", 0x11460, TRUE,  FALSE},
            {NULL, 0, FALSE, FALSE}
        };

        for (int i = 0; targets[i].name; i++) {
            ADDRINT funcAddr = base + targets[i].rva;
            fprintf(trace, "#target %s RVA=%x abs=%x\n",
                    targets[i].name, targets[i].rva, (UINT32)funcAddr);

            RTN rtn = RTN_CreateAt(funcAddr, targets[i].name);
            if (RTN_Valid(rtn)) {
                fprintf(trace, "#hook %s at %x\n", targets[i].name, (UINT32)funcAddr);
                RTN_Open(rtn);
                if (targets[i].isConn) {
                    INS_InsertCall(RTN_InsHead(rtn), IPOINT_BEFORE, (AFUNPTR)RecordConnectBefore,
                                   IARG_INST_PTR, IARG_CONTEXT,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                   IARG_END);
                } else if (targets[i].isRecv) {
                    INS_InsertCall(RTN_InsHead(rtn), IPOINT_AFTER, (AFUNPTR)RecordRecvAfter,
                                   IARG_INST_PTR, IARG_CONTEXT,
                                   IARG_FUNCRET_EXITPOINT_VALUE,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                   IARG_END);
                } else {
                    INS_InsertCall(RTN_InsHead(rtn), IPOINT_BEFORE, (AFUNPTR)RecordSendBefore,
                                   IARG_INST_PTR, IARG_CONTEXT,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                   IARG_END);
                }
                RTN_Close(rtn);
            } else {
                fprintf(trace, "#fail %s at %x\n", targets[i].name, (UINT32)funcAddr);
            }
        }
    }

    // Hook wininet.dll - program may use WinINet for networking
    if (imgLower.find("wininet") != std::string::npos) {
        ADDRINT base = IMG_StartAddress(img);
        fprintf(trace, "#loaded wininet base=%x size=%x\n",
                (UINT32)base, (UINT32)IMG_SizeMapped(img));

        // WinINet send/recv equivalents
        struct { const char* name; UINT32 rva; BOOL isRecv; } winTargets[] = {
            {"HttpSendRequestA",  0x0, FALSE},
            {"HttpSendRequestW",  0x0, FALSE},
            {"InternetReadFile",  0x0, TRUE},
            {"InternetWriteFile", 0x0, FALSE},
            {"HttpOpenRequestA",  0x0, FALSE},
            {"HttpOpenRequestW",  0x0, FALSE},
            {NULL, 0, FALSE}
        };

        // Try by name since we don't have RVAs for wininet
        for (int i = 0; winTargets[i].name; i++) {
            RTN rtn = RTN_FindByName(img, winTargets[i].name);
            if (RTN_Valid(rtn)) {
                fprintf(trace, "#hook_wininet %s at %x\n", winTargets[i].name, (UINT32)RTN_Address(rtn));
                RTN_Open(rtn);
                if (winTargets[i].isRecv) {
                    INS_InsertCall(RTN_InsHead(rtn), IPOINT_AFTER, (AFUNPTR)RecordRecvAfter,
                                   IARG_INST_PTR, IARG_CONTEXT,
                                   IARG_FUNCRET_EXITPOINT_VALUE,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                   IARG_END);
                } else {
                    INS_InsertCall(RTN_InsHead(rtn), IPOINT_BEFORE, (AFUNPTR)RecordSendBefore,
                                   IARG_INST_PTR, IARG_CONTEXT,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                   IARG_END);
                }
                RTN_Close(rtn);
            }
        }
    }

    // Hook HPSocket4C.dll
    if (imgLower.find("hpsocket") != std::string::npos) {
        fprintf(trace, "#loaded HPSocket base=%x\n", (UINT32)IMG_StartAddress(img));
        // Try common HPSocket send/recv functions
        const char* sendFuncs[] = {
            "HP_Client_Send", "HP_Client_SendPart", "HP_Client_SendPackets",
            "HP_Agent_Send", "HP_Agent_SendPart", "HP_Agent_SendPackets",
            "HP_Server_Send", "HP_Server_SendPart", "HP_Server_SendPackets",
            NULL
        };
        const char* recvFuncs[] = {
            "HP_Client_Receive", "HP_Agent_Receive", "HP_Server_Receive",
            NULL
        };
        for (int i = 0; sendFuncs[i]; i++) {
            TryHookFunc(img, sendFuncs[i], FALSE);
        }
        for (int i = 0; recvFuncs[i]; i++) {
            TryHookFunc(img, recvFuncs[i], TRUE);
        }
    }

    // Hook any DLL that might do network I/O
    // Also hook kernel32 WriteFile/ReadFile for pipe-based IPC
    if (imgLower.find("kernel32") != std::string::npos) {
        TryHookFunc(img, "WriteFile", FALSE);
        TryHookFunc(img, "ReadFile", TRUE);
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
