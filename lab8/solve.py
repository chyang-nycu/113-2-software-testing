#!/usr/bin/env python3

import angr
import sys

def main():
    # 創建一個新的 angr 專案
    proj = angr.Project('./chal', auto_load_libs=False)
    
    # 創建一個符號輸入
    state = proj.factory.entry_state()
    input_str = state.solver.BVS('input', 8 * 8)  # 8 bytes, 8 bits each
    
    # 將輸入寫入 stdin
    state.posix.stdin.write(input_str)
    
    # 創建一個模擬管理器
    simgr = proj.factory.simulation_manager(state)
    
    # 尋找成功路徑（找到 "Correct!" 字串）
    simgr.explore(find=lambda s: b"Correct!" in s.posix.dumps(1))
    
    if len(simgr.found) > 0:
        # 獲取找到的狀態
        found_state = simgr.found[0]
        # 獲取輸入值
        secret_key = found_state.posix.stdin.read(0, 8)
        # 求解具體值
        secret_key = found_state.solver.eval(secret_key, cast_to=bytes)
        # 輸出結果
        sys.stdout.buffer.write(secret_key)
    else:
        print("No solution found", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
