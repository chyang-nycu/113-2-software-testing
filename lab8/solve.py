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

    # 3) 準備一個 8 字元的符號向量
    sym_in = claripy.BVS('in', KEY_LEN * 8)

    # 4) 取一塊 .bss 作為輸入緩衝區，並把符號寫進去
    bss_addr = proj.loader.main_object.sections_map['.bss'].min_addr
    # blank_state 只用來寫記憶體
    tmp_state = proj.factory.blank_state()
    tmp_state.memory.store(bss_addr, sym_in)

    # 5) 用 call_state 直接呼 gate(bss_addr)
    #    注意這裡的 API：call_state(addr, *args)
    state = proj.factory.call_state(gate_addr, bss_addr, base_state=tmp_state)

    # 6) 加入避免 strlen/fgets 斷掉的約束
    for i in range(KEY_LEN):
        byte = claripy.Extract(i * 8 + 7, i * 8, sym_in)
        state.solver.add(byte != 0)     # 不允許 0x00
        state.solver.add(byte != 0x0a)  # 不允許 '\n'

    # 7) 探索：stdout 含 "Correct!" 停止；含 "Wrong key!" 的路徑避開
    simgr = proj.factory.simgr(state)
    simgr.explore(
        find = lambda s: b"Correct!" in s.posix.dumps(1),
        avoid= lambda s: b"Wrong key!" in s.posix.dumps(1),
    )

    if not simgr.found:
        print("[-] 沒找到符合條件的輸入！", file=sys.stderr)
        sys.exit(1)

    # 8) 取出解並輸出
    sol = simgr.found[0].solver.eval(sym_in, cast_to=bytes)
    sys.stdout.buffer.write(sol + b'\n')

if __name__ == '__main__':
    main()
