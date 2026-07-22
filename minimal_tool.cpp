/*
 * Minimal Pin tool - just log DLL loads
 */
#include "pin.H"
#include <stdio.h>

FILE* logFile;

VOID ImageLoad(IMG img, VOID* v)
{
    fprintf(logFile, "DLL: %s base=%x\n",
            IMG_Name(img).c_str(), (UINT32)IMG_StartAddress(img));
    fflush(logFile);
}

VOID Fini(INT32 code, VOID* v)
{
    fprintf(logFile, "FINI: code=%d\n", code);
    fclose(logFile);
}

int main(int argc, char* argv[])
{
    logFile = fopen("minimal_tool.log", "w");
    if (!logFile) return 1;
    fprintf(logFile, "START\n");
    fflush(logFile);

    if (PIN_Init(argc, argv)) return -1;
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
