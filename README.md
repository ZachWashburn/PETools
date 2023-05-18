# PETools
 Rebuilt Windows Loader/Kernel32 Functionality

## Introduction

During a red-team/blue-team skirmish, I found myself needing a way to bypass AV hueristics and discourage static analysis.

PETools was written quickly to satisfy these requirements, while fully functional the code can be a tad messy. 

## Features

This library supports manually mapping PE files into memory, process hallowing, compiling as shellcode without imports, optional linking to the windows PEB link ldr structs, and calling syscalls directly through indirection through the NTTestAlert function which calls into the x86->x64 Heavens Gate. All (optional) imports and dynamic syscall number acquisition is done through the use of FNV hashes to discourage static analysis. Windows DLL loading search spaces are additionally manually implemented.
