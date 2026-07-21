# VMP Tracer

Pintool for tracing VMProtect handler execution on IA-32.

## Build

GitHub Actions builds automatically. Download `vmp_tracer.dll` from artifacts.

## Usage

```
pin.exe -t vmp_tracer.dll -- app.exe
```

Output: `vmp_trace.out` with register values at each instruction.
