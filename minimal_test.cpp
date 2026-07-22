/*
 * Minimal Pin tool - just to test if Pin can load the DLL
 */
#include "pin.H"
#include <stdio.h>

FILE* trace;

VOID Fini(INT32 code, VOID* v) {
    fprintf(trace, "#eof\n");
    fclose(trace);
}

int main(int argc, char* argv[])
{
    trace = fopen("minimal_test.out", "w");
    if (!trace) return 1;
    fprintf(trace, "#start\n");
    fflush(trace);
    if (PIN_Init(argc, argv)) return -1;
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
