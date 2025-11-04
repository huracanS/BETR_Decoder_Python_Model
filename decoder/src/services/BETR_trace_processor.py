# src/services/BETR_trace_processor.py
from .instruction_logger import log_instruction
from src.domain.trace_processor_model import TraceState
from .trace_processor_utils import get_instr, instruction_size, is_branch, report_pc

def process_te_inst(te_inst, state: TraceState):
    """处理 BETR 数据包（inst_cnt 单位：16bit）"""
    
    branch_addr = te_inst.branch_addr
    inst_cnt = te_inst.inst_cnt
    br_tkn = te_inst.br_tkn
    extend = te_inst.extend
    
    print(f"\033[94m+++++++++++++++++++++++++++++\033[0m")
    print(f"\033[94m===Processing BETR packet:===\033[0m")
    print(f"\033[94m  Branch Address: 0x{branch_addr:08x}\033[0m")
    print(f"\033[94m  Instruction Count: {inst_cnt}\033[0m")
    print(f"\033[94m  Branch Token: 0b{br_tkn:032b}\033[0m")
    print(f"\033[94m  Extend: {extend}\033[0m")
    print(f"\033[94m+++++++++++++++++++++++++++++\033[0m")
    
    current_pc = branch_addr
    remaining_cnt = inst_cnt

    while remaining_cnt > 0:
        instr = get_instr(current_pc, state)
        if not instr:
            print(f"No instruction at PC: 0x{current_pc:08X}")
            break

        report_pc(current_pc, state)
        instr_len = instruction_size(instr)  # 返回单位：字节

        # 每条指令扣减对应的16bit数量
        if instr_len == 2:
            remaining_cnt -= 1
        elif instr_len == 4:
            remaining_cnt -= 2
        else:
            print(f"⚠️ Unknown instruction size {instr_len} at PC 0x{current_pc:08X}")
            break
        print(f"instr_len:{instr_len} at PC 0x{current_pc:08X}")

        # 分支逻辑
        if is_branch(instr):
            taken = (br_tkn & 1) == 1
            br_tkn >>= 1
            if taken:
                current_pc += int(instr.imm, 0)
                continue  # 跳转后继续

        # 普通指令，PC递增
        current_pc += instr_len

        print(f"  [DEBUG] PC=0x{current_pc:08X}, remaining_cnt={remaining_cnt}")

    if extend:
        print(f"TRAP/Exception detected!")
