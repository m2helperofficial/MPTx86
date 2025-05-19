#include <windows.h>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <thread>
#include <chrono>

namespace {

struct MemoryRegion {
    uint8_t* base;
    SIZE_T size;
    uint64_t hash;
};

std::vector<MemoryRegion> g_regions;
std::mutex g_mutex;
bool g_running = false;
HANDLE g_thread = nullptr;
FILE* g_log = nullptr;

constexpr uint64_t fnv_offset_basis = 0xcbf29ce484222325ULL;
constexpr uint64_t fnv_prime = 0x100000001b3ULL;

uint64_t fnv1a64(const uint8_t* data, SIZE_T size) {
    uint64_t hash = fnv_offset_basis;
    for (SIZE_T i = 0; i < size; ++i) {
        hash ^= data[i];
        hash *= fnv_prime;
    }
    return hash;
}

void log_change(void* addr, SIZE_T size, uint64_t old_hash, uint64_t new_hash) {
    if (!g_log) {
        return;
    }
    fprintf(g_log, "addr=%p size=%zu old=%016llx new=%016llx\n",
            addr, size,
            static_cast<unsigned long long>(old_hash),
            static_cast<unsigned long long>(new_hash));
    fflush(g_log);
}

bool confirm_change(MemoryRegion& region, uint64_t observed) {
    Sleep(50);
    uint64_t second = fnv1a64(region.base, region.size);
    if (second == observed && second != region.hash) {
        return true;
    }
    region.hash = second;
    return false;
}

void snapshot_memory() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION mbi;

    uint8_t* addr = reinterpret_cast<uint8_t*>(si.lpMinimumApplicationAddress);
    uint8_t* end = reinterpret_cast<uint8_t*>(si.lpMaximumApplicationAddress);

    std::lock_guard<std::mutex> lock(g_mutex);
    g_regions.clear();

    while (addr < end && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
            (mbi.Protect & PAGE_NOACCESS) == 0) {
            MemoryRegion region;
            region.base = static_cast<uint8_t*>(mbi.BaseAddress);
            region.size = mbi.RegionSize;
            region.hash = fnv1a64(region.base, region.size);
            g_regions.push_back(region);
        }
        addr += mbi.RegionSize;
    }
}

void monitor_loop() {
    while (g_running) {
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            for (auto& region : g_regions) {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery(region.base, &mbi, sizeof(mbi)) != sizeof(mbi) ||
                    mbi.State != MEM_COMMIT ||
                    (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                    continue;
                }

                uint64_t current = fnv1a64(region.base, region.size);
                if (current != region.hash && confirm_change(region, current)) {
                    log_change(region.base, region.size, region.hash, current);
                    region.hash = current;
                }
            }
        }
        Sleep(1000);
    }
}

DWORD WINAPI thread_proc(LPVOID) {
    // allow the process to initialize before taking the first snapshot
    std::this_thread::sleep_for(std::chrono::seconds(5));
    snapshot_memory();
    monitor_loop();
    return 0;
}

} // anonymous namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_running = true;
        g_log = fopen("log.txt", "w");
        g_thread = CreateThread(nullptr, 0, thread_proc, nullptr, 0, nullptr);
        if (!g_thread) {
            if (g_log) {
                fclose(g_log);
                g_log = nullptr;
            }
            g_running = false;
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        if (g_running) {
            g_running = false;
            WaitForSingleObject(g_thread, INFINITE);
            CloseHandle(g_thread);
        }
        if (g_log) {
            fclose(g_log);
            g_log = nullptr;
        }
        break;
    }
    return TRUE;
}

