import sys
from collections import defaultdict
from datetime import datetime
from scapy.all import PcapReader, Ether, IP

def format_bytes(size_in_bytes):
    """将字节数格式化为可读的 KB, MB, GB 等。"""
    if size_in_bytes is None:
        return "0 B"
    # 1 MB
    if size_in_bytes > 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    # 1 KB
    if size_in_bytes > 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    return f"{size_in_bytes} B"

def format_bits(size_in_bytes):
    size_in_bits = size_in_bytes << 3
    if size_in_bits is None:
        return "0 B"
    # 1 MB
    if size_in_bits > 1024 * 1024:
        return f"{size_in_bits / (1024 * 1024):.2f} Mb"
    # 1 KB
    if size_in_bits > 1024:
        return f"{size_in_bits / 1024:.2f} Kb"
    return f"{size_in_bits} b"

def analyze_pcap_traffic(pcap_file, target_mac):
    """
    分析 pcap 文件，计算并打印每秒发送到目标 MAC 地址的流量。

    :param pcap_file: pcap 文件的路径。
    :param target_mac: 目标 MAC 地址，发往此地址的流量被视为“发送”。
    """
    # 使用 defaultdict(int) 可以方便地对每秒的流量进行累加
    # 键是整数类型的时间戳（秒），值是该秒内的总字节数
    upload_per_second = defaultdict(int)
    download_per_second = defaultdict(int)
    upload_default_per_second = defaultdict(int)
    upload_alias_per_second = defaultdict(int)

    print(f"[*] 正在分析文件: {pcap_file}")
    print(f"[*] 目标 MAC (发送方向): {target_mac}")
    
    packet_count = 0
    matched_packet_count = 0
    file = open("res.txt", "w")
    # 使用 PcapReader 逐包读取，避免将大文件一次性加载到内存
    with PcapReader(pcap_file) as pcap_reader:
        last_second = 0
        for packet in pcap_reader:
            packet_count += 1
            # 确保数据包有以太网层
            if not packet.haslayer(Ether):
                continue

            # 获取以太网层的目标 MAC 地址
            dst_mac = packet[Ether].dst
            src_mac = packet[Ether].src
            upload_speed = 0
            download_speed = 0
            upload_speed_default = 0
            upload_speed_alias = 0
                                
            # 获取数据包的时间戳 (浮点数)
            timestamp = packet.time
            
            # 将时间戳转换为整数秒，作为分组的键
            second_bucket = int(timestamp)
            if second_bucket != last_second:
                upload_traffic = format_bits(upload_per_second[last_second])
                upload_alias_traffic = format_bits(upload_alias_per_second[last_second])
                upload_default_traffic = format_bits(upload_default_per_second[last_second])
                download_traffic = format_bits(download_per_second[last_second])
                res = f"Seconds: {last_second}  upload:{upload_traffic}/s default {upload_default_traffic}/s alias {upload_alias_traffic}/s, download {download_traffic}/s"
                print(res)
                file.write(res)
                file.write("\n")
                last_second = second_bucket  
                packet_size = 0
            # 检查目标 MAC 是否是我们关注的地址（不区分大小写）
            if dst_mac and dst_mac.lower() == target_mac:
                matched_packet_count += 1       
                if packet.haslayer(IP):
                    # 如果数据包被截断，len(packet) 是错误的。
                    # 我们必须使用 IP 头的 'len' 字段，它包含了 IP 头的总长度。
                    # 这代表了 IP 层的实际流量大小。
                    packet_size = packet[IP].len
                    if packet[IP].src == "172.20.1.150" or packet[IP].src == "172.20.1.158":
                        upload_alias_per_second[second_bucket] += packet_size
                    else:
                        upload_default_per_second[second_bucket] += packet_size
                else:
                    # 对于非 IP 包（如 ARP），它们通常很小，不会被截断。
                    # 使用 len(packet) 作为备用方案是安全的。
                    packet_size = len(packet)
                    upload_default_per_second[second_bucket] += packet_size
                # 累加该数据包的大小（整个帧的长度）
                upload_per_second[second_bucket] += packet_size
            elif src_mac and src_mac.lower() == target_mac:
                if packet.haslayer(IP):
                    download_per_second[second_bucket] += packet[IP].len
                else:
                    download_per_second[second_bucket] += len(packet)

    res = f"\n[*] 分析完成。总共处理了 {packet_count} 个数据包，其中 {matched_packet_count} 个upload匹配目标。"
    print(res)
    file.write(res)
    file.write("\n")
    file.close()

if __name__ == "__main__":
    # 检查命令行参数是否足够
    if len(sys.argv) != 2:
        print("用法: python analyze_traffic.py <pcap_file_path>")
        sys.exit(1)

    # 从命令行获取 pcap 文件路径
    pcap_file_path = sys.argv[1]
    
    # 定义你的目标 MAC 地址
    TARGET_DESTINATION_MAC = "02:00:00:00:10:2c"
    
    analyze_pcap_traffic(pcap_file_path, TARGET_DESTINATION_MAC.lower())
