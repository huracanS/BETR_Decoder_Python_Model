# src/services/BETR_trace_processor.py
from .instruction_logger import log_instruction
from src.domain.trace_processor_model import TraceState
from .trace_processor_utils import get_instr, instruction_size, is_branch ,report_pc

def process_te_inst(te_inst, state: TraceState):
    """处理 BETR 数据包，严格按原版逻辑"""
    
    branch_addr = te_inst.branch_addr
    inst_cnt = te_inst.inst_cnt
    br_tkn = te_inst.br_tkn
    extend = te_inst.extend
    
    print(f"\033[94m+++++++++++++++++++++++++++++\033[0m")
    print(f"\033[94m===Processing BETR packet:===\033[0m")
    print(f"\033[94m  Branch Address: 0x{branch_addr:08x}\033[0m")
    print(f"\033[94m  Instruction Count: {inst_cnt}\033[0m")
    print(f"\033[94m  Branch Token: 0x{br_tkn:32b}\033[0m")
    print(f"\033[94m  Extend: {extend}\033[0m")
    print(f"\033[94m+++++++++++++++++++++++++++++\033[0m")
    
    # 起始 PC
    current_pc = branch_addr
    
    remaining_cnt = inst_cnt

    while remaining_cnt > 0:
        instr = get_instr(current_pc, state)
        if not instr:
            print(f"No instruction at PC: 0x{current_pc:08X}")
            break

        report_pc(current_pc, state)

        # 分支判断逻辑
        if is_branch(instr):
            taken = (br_tkn & 1) == 1
            br_tkn >>= 1
            if taken:
                if instr.opcode.startswith("c."):
                    current_pc += int(instr.imm, 0)
                else:
                    current_pc = int(instr.imm, 0)
                # 即便跳转了，inst_cnt 仍然扣减对应长度
                remaining_cnt -= instruction_size(instr) // 2
                continue

        print(f"remaining_cnt：{remaining_cnt}")
        print(f"instruction_size：{instruction_size(instr)}")

        # 非跳转情况
        current_pc += instruction_size(instr)
        remaining_cnt -= instruction_size(instr) // 2  # ⚠️ 每 16bit 扣 1
        print(f"remaining_cnt：0x{current_pc:08x}")
        print(f"instruction_size：{remaining_cnt}")