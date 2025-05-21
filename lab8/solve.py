#!/usr/bin/env python3
# solve.py  —> 直接從 gate() 模擬，避開所有 C-library 呼叫

import sys
import angr
import claripy

KEY_LEN = 8

def main():
    # 1) 建專案，不載入外部 libc
    proj = angr.Project('./chal', auto_load_libs=False)

    # 2) 找到 gate 函式的載入地址
    gate_sym = proj.loader.find_symbol('gate')
    if gate_sym is None:
        print("找不到 gate 符號！", file=sys.stderr)
        sys.exit(1)
    gate_addr = gate_sym.rebased_addr

    # 3) blank_state：直接在 gate() 入口開始執行
    state = proj.factory.blank_state(addr=gate_addr)

    # 4) 在 heap 申請 KEY_LEN bytes，並逐字塞入符號變數
    # 從 heap 配置一塊記憶體空間
    buf = state.heap.allocate(KEY_LEN)

    key_vars = []
    # 用符號變數填充 buf
    for i in range(KEY_LEN):
        b = claripy.BVS(f'k{i}', 8)            # 建立 8-bit 的符號變數，代表第 i 個字元
        key_vars.append(b)
        state.memory.store(buf + i, b)        # 依序寫入 buf 指向的記憶體中的第 i 個位置

    # 5) 按照 SystemV x86_64 呼叫慣例，第一個參數放在 rdi
    state.regs.rdi = buf

    # 避免符號 byte 為 0 / '\n' 造成奇怪結果
    for b in key_vars:
        state.solver.add(b != 0)       # 不允許是 NULL（0x00），否則 strlen(input) 會提早結束
        state.solver.add(b != 0x0a)    # 不允許是換行（0x0a），否則 fgets() 會提早結束

    # 6) 探索：找到 stdout 含「Correct!」的狀態；避開任何印出「Wrong key!」的分支
    # 建立一個模擬器（Simulation Manager），開始從 state 模擬執行。
    simgr = proj.factory.simgr(state)
    # explore() 會自動走過所有可能的分支、跳轉與條件，尋找滿足目標條件的執行路徑。
    simgr.explore(
        find=lambda s: b"Correct!" in s.posix.dumps(1),
        avoid=lambda s: b"Wrong key!" in s.posix.dumps(1),
    )

    # 7) 取出解並輸出
    if not simgr.found:
        print("[-] 沒有找到符合條件的輸入！", file=sys.stderr)
        sys.exit(1)
    found = simgr.found[0]
    solution = found.solver.eval(claripy.Concat(*key_vars), cast_to=bytes)
    sys.stdout.buffer.write(solution + b'\n')

if __name__ == '__main__':
    main()
