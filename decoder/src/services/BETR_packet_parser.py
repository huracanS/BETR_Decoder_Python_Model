# src/services/betr_packet_parser.py

class BETRPacket:
    """BETR编码器数据包 - 75位格式"""
    
    def __init__(self):
        self.branch_addr = 0  # 32-bit
        self.inst_cnt = 0     # 10-bit  
        self.br_tkn = 0       # 32-bit
        self.extend = 0       # 1-bit
    
    def __str__(self):
        return (f"BETRPacket(branch_addr=0x{self.branch_addr:08X}, "
                f"inst_cnt={self.inst_cnt}, br_tkn=0x{self.br_tkn:08X}, "
                f"extend={self.extend})")


def parse_packets(path: str) -> list[BETRPacket]:
    """
    解析BETR编码器生成的数据包文件
    输入格式: trace_valid trace_data(hex)
    """
    packets = []
    
    print(f"📖 Reading BETR packets from: {path}")
    
    with open(path, "r") as file:
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if not line:
                continue
                
            parts = line.split()
            if len(parts) == 2:
                trace_valid = int(parts[0])
                trace_data = int(parts[1], 16)  # 十六进制数据
                
                if trace_valid == 1:
                    packet = _parse_betr_packet(trace_data)
                    packets.append(packet)
                    print(f"  ✅ Packet {len(packets)}: {packet}")
                else:
                    print(f"  ⚠️  Line {line_num}: trace_valid=0, skipped")
            else:
                print(f"  ❌ Line {line_num}: invalid format '{line}'")
    
    print(f"🎯 Total parsed {len(packets)} BETR packets")
    return packets


def _parse_betr_packet(trace_data: int) -> BETRPacket:
    """
    解析75位BETR数据包
    Format: Branch_addr[31:0] + inst_cnt[9:0] + Br_tkn[31:0] + extend[0]
    """
    packet = BETRPacket()
    
    # 直接提取字段
    packet.extend = trace_data & 0x1
    packet.br_tkn = (trace_data >> 1) & 0xFFFFFFFF
    packet.inst_cnt = (trace_data >> 33) & 0x3FF  # 1+32=33
    packet.branch_addr = (trace_data >> 43) & 0xFFFFFFFF  # 1+32+10=43
    
    return packet