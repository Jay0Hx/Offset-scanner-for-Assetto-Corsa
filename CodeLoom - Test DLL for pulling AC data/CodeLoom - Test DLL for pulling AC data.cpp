#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <psapi.h>
#include <ctime>

void WritePatternInfoToFile(const std::string& info) {
    std::string logFileName = "C:\\Users\\james\\Desktop\\CodeLoom\\predatorv1_log.txt";

    std::ofstream outputFile(logFileName, std::ios::app);
    if (outputFile.is_open()) {
        outputFile << info << std::endl;
        outputFile.close();
    }
}

void ScanMemoryForPattern(DWORD_PTR dwStartAddress, DWORD_PTR dwEndAddress, const BYTE* pattern, size_t patternSize) {
    for (DWORD_PTR dwCurrentAddress = dwStartAddress; dwCurrentAddress < dwEndAddress; dwCurrentAddress++) {
        bool found = true;
        for (size_t i = 0; i < patternSize; i++) {
            BYTE byte;
            ReadProcessMemory(GetCurrentProcess(), (LPVOID)(dwCurrentAddress + i), &byte, sizeof(BYTE), nullptr);
            if (byte != pattern[i]) {
                found = false;
                break;
            }
        }
        if (found) {
            // Pull the value for the offset off_180E15898
            DWORD_PTR off_180E15898_value = 0;
            ReadProcessMemory(GetCurrentProcess(), (LPCVOID)0x180E15898, &off_180E15898_value, sizeof(DWORD_PTR), nullptr);
            std::stringstream ss;
            ss << "Value at offset off_180E15898: 0x" << std::hex << off_180E15898_value;
            WritePatternInfoToFile(ss.str());
            break;
        }
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    DWORD_PTR dwStartAddress = 0;
    DWORD_PTR dwEndAddress = 0;
    size_t patternSize = 0;
    BYTE pattern[] = { 0x48, 0x89, 0x41, 0x08 }; // Pattern to search for
    MODULEINFO moduleInfo;
    DWORD_PTR dwModuleBase = 0;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO));
        dwModuleBase = (DWORD_PTR)moduleInfo.lpBaseOfDll;
        patternSize = sizeof(pattern);
        dwStartAddress = dwModuleBase;
        dwEndAddress = dwModuleBase + moduleInfo.SizeOfImage;
        ScanMemoryForPattern(dwStartAddress, dwEndAddress, pattern, patternSize);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}