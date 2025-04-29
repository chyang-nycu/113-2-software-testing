#include <string.h>

void antiasan(unsigned long addr)
{
    // 透過 extern 在函式裡隱式宣告 ASan 的 unpoison 介面
    extern void __asan_unpoison_memory_region(void *addr, size_t size);

    extern char gS[];
    extern char gBadBuf[];

    // 1) 先把 gS 本體 (0x18 bytes) + overflow (0x10 bytes) 一次 unpoison
    __asan_unpoison_memory_region((void*)gS, 0x18 + 0x10);

    // 2) 再把 gBadBuf 本體 (0x87 bytes) unpoison
    __asan_unpoison_memory_region((void*)gBadBuf, 0x87);
}
