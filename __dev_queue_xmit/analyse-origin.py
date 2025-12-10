import re
import os
from collections import defaultdict, Counter
import csv
import json
path =  os.path.dirname(os.path.abspath(__file__))
from datetime import datetime, timedelta

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap


#错误字典
error_map = {
    "NORMAL" : 0,
    "Data Abort": 1,
    "Instruction Abort": 2,
    "Kernel": 3,
    "Oops": 4,
    "BUG: scheduling while atomic": 5,
    "Internal error: ptrace BRK handler": 6,
    "RCU" : 7,
    
    "Errno0: error" : 8,
    "Errno1: Operation not permitted" : 9,
    "Errno11: Resource temporarily unavailable" : 10,
    "Errno14: Bad address" : 11,
    "Errno19: No such device" : 12,
    "Errno22: invalid argument" : 13,
    "Errno95: Operation not supported" : 14,
    "Errno97: Address family not supported by protocol" : 15,
    "Errno32: Broken pipe" : 16,
    "Errno512: unknown error" : 17,

    "Errno89: Destination address required" : 18,
    "Errno90: Message too long" : 19,
    "Errno105: No buffer space available" : 20,
    "IPv4: Attempt to release alive inet socket": 21,
    "Tx Unit Hang" : 22,
    "Network TimeOut" : 23,
    "Error Port" : 24,

    "SDC" : 25
}

pattern = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}), '
    r'Instruction: (?P<instruction>0x[0-9a-fA-F]+), '
    r'Mem: (?P<mem>\d+), '
    r'Flipped bit (?P<flipped_bit>\d+), '
    r'Flipped \d+, '
    r'\[!\] Exception detected! (?P<json_like>\[.*\])'
)

received_data_log = "received_data.log"  # 日志文件名（请根据实际路径修改）
target_msg = "Hello, UDP Server!"
received_pattern = re.compile(
    r"\[(.*?)\]\s+From\s+\('([^']+)',\s*(\d+)\):\s*(.*)"
)

normal_pattern = re.compile(
   r'(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
)

abnormal_times = []
abnormal_ports = [] #Time
ports_by_time = defaultdict(set)  # 同一秒 -> 端口集合
last_time = datetime.strptime('2025-08-22 14:54:39', "%Y-%m-%d %H:%M:%S")
last_port = '47848'
flag = 0


error_array = []

#客户端接收数据情况
with open(path + "/received_data.log" , "r", encoding="utf-8") as f:
    for line in f:
        m = received_pattern.search(line)
        if not m:
            continue

        timestamp = m.group(1).strip()
        message = m.group(4).strip()
        port = m.group(3).strip()

        timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

        # 判断是否为异常消息
        if message != target_msg:
            if timestamp not in abnormal_times:
                abnormal_times.append(timestamp)

        ports_by_time[timestamp].add(port)

        if flag == 0:
            if 0 < abs((timestamp - last_time).total_seconds()) <= 1 and port != last_port:
                abnormal_ports.append(timestamp)
                flag = 1
                #print(timestamp)
        elif port == last_port:
            abnormal_ports.append(timestamp)
            #print(timestamp)
        else:
            flag = 0
        last_port, last_time = port, timestamp
for t, ports in ports_by_time.items():
    if len(ports) > 1:
        abnormal_ports.append(t)

# print(abnormal_times)
# print(abnormal_ports)


#函数中各指令及其地址对应情况
addr_to_instr = {}
with open(path + "\\addr_instruction.json" , 'r') as f:
    data = json.load(f)
    for addr, instr in zip(data["instr_addrs"], data["instructions"]):
        cleaned = instr.replace('\t', ' ')
        cleaned = re.sub(r'//.*$', '', cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned)
        cleaned = cleaned.strip()
        addr_to_instr[addr] = cleaned

#函数实际运行的指令
execution_addr = []
with open(path + "\\instruction_trace.json" , 'r') as f:
    trace_data = json.load(f)
    for data in trace_data:
        pc = data.get("pc")
        if pc in addr_to_instr and pc not in execution_addr:
            execution_addr.append(pc)

# print(len(execution_addr))
# exit()


# print(addr_to_instr)
# exit()


def analyze_error_log(file_content):
    # 解析日志行
    lines = file_content.strip().split('\n')
    
    # 存储统计结果
    instruction_stats = defaultdict(lambda: {
        'total_flips': 0,
        'bit_errors': defaultdict(list),
        'error_types': Counter(),
        'normal_count': 0,
        'error_count': 0
    })
    
    
    # 解析每行日志
    number = 0
    for line in lines:
        # 提取基本信息
        instruction_match = re.search(r'Instruction: (0x[0-9a-f]+)', line)
        bit_match = re.search(r'Flipped bit (\d+)', line)
        
        if not instruction_match or not bit_match:
            continue
            
        instruction = instruction_match.group(1)
        bit = int(bit_match.group(1))
        
        # 判断系统状态
        if '[+] System running normally' in line:
            instruction_stats[instruction]['total_flips'] += 1
            match = normal_pattern.search(line)
            time_str = match.group("time")
            time_str = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            start_time = time_str - timedelta(seconds=2)
            end_time = time_str + timedelta(seconds=3)

            # 判断是否存在异常时间在该窗口内
            found_SDC = any(start_time <= t <= end_time for t in abnormal_times)
            found_port = any(start_time <= t <= end_time for t in abnormal_ports)

            if found_SDC:
                error_type = 'SDC'
                instruction_stats[instruction]['error_count'] += 1
                instruction_stats[instruction]['bit_errors'][bit].append(error_type)
                instruction_stats[instruction]['error_types'][error_type] += 1
            elif found_port:
                error_type = 'Error Port'
                instruction_stats[instruction]['error_count'] += 1
                instruction_stats[instruction]['bit_errors'][bit].append(error_type)
                instruction_stats[instruction]['error_types'][error_type] += 1
            else:
                instruction_stats[instruction]['normal_count'] += 1
                instruction_stats[instruction]['bit_errors'][bit].append('NORMAL')

        elif '[!] Exception detected!' in line:
            instruction_stats[instruction]['error_count'] += 1
            instruction_stats[instruction]['total_flips'] += 1
            
            # 分析错误类型 
            match = pattern.search(line)
            if not match:
                raise ValueError("Log format not recognized")
            time_str = match.group("time")
            dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S") + timedelta(seconds=2)
            time_token = dt.strftime("%Y-%m-%d_%H-%M-%S")
            mem = match.group("mem")
            json_like = match.group("json_like")

            error_only = re.fullmatch(r"\[\{'flag': 'Error'\}\]", json_like.strip())
            #print(error_only)

            error_type = None
            fault_file = None

            if error_only:
                number += 1
                fault_type = "Communication Error"
                # 将时间格式转成文件名可识别格式
                # 遍历 results 文件夹，查找包含该时间的文件

                filename = f"{time_token}.log"
                fault_file = os.path.join(path+"/results/", filename)
                file =  open(fault_file, "r")
                if file:
                    for line in file.readlines():
                        #print(line)
                        if 'BUG: scheduling while atomic' in line:
                            #print(line)
                            error_type = 'BUG: scheduling while atomic'
                            break
                        elif 'rcu' in line:
                            #print(line)
                            error_type = 'RCU'
                            break
                        elif 'IPv4: Attempt to release alive inet socket' in line:
                            #print(line)
                            error_type = 'IPv4: Attempt to release alive inet socket'
                            break
                        elif 'e1000' in line:
                            #=print(line)
                            error_type = 'Tx Unit Hang'
                            break
                        elif 'A start job is running for Raise nek interfaces'  in line or 'A start job is running for Raise nerk interfaces'  in line or 'A start job is running fork interfaces'  in line:
                            #print(line)
                            error_type = 'Network TimeOut'
                            break
                        elif 'Errno 0' in line:
                            #print(line)
                            error_type = 'Errno0: error' #底层网络栈或驱动被卡死，Python 程序的 socket 调用不断失败，异常处理逻辑反复打印 Error [Errno 0] 
                            break
                        elif 'Errno 22' in line:
                            #print(line)
                            error_type = 'Errno22: invalid argument' #某个系统调用（比如 socket(), bind(), send()）收到了非法或不被当前内核状态接受的参数。
                            break
                        elif 'Errno 89' in line:
                            #print(line)
                            error_type = 'Errno89: Destination address required' # 
                            break
                        elif 'Errno 95' in line:
                            #print(line)
                            error_type = 'Errno95: Operation not supported' # 
                            break
                        elif 'Errno 97' in line:
                            #print(line)
                            error_type = 'Errno97: Address family not supported by protocol' # 
                            break
                        elif 'Errno 90' in line:
                            #print(line)
                            error_type = 'Errno90: Message too long' # 
                            break
                        elif 'Errno 14' in line:
                            #print(line)
                            error_type = 'Errno14: Bad address' # 
                            break
                        elif 'Errno 11' in line:
                            #print(line)
                            error_type = 'Errno11: Resource temporarily unavailable' # 
                            break
                        elif 'Internal error:' in line:
                            #print(line)
                            error_type = 'Internal error: ptrace BRK handler' # 执行断点处理（BRK 指令）时发生了内部错误
                            break
                        elif 'Errno 19' in line:
                            #print(line)
                            error_type = 'Errno19: No such device' #
                            break
                        elif 'Errno 32' in line:
                            #print(line)
                            error_type = 'Errno32:  Broken pipe' #
                            break
                        elif 'Errno 512' in line:
                            #print(line)
                            error_type = 'Errno512:  Unknown error' #
                            break
                        elif 'Errno 105' in line:
                            #print(line)
                            error_type = 'Errno105:  No buffer space available' #
                            break
                        elif 'Errno 1' in line:
                            #print(line)
                            error_type = 'Errno1: Operation not permitted' #
                            break
                        else:
                            print(line)
                            print(dt, error_type)    
                            exit()
            else:
                # 提取第二个字典的 key 作为 fault_type
                fault_match = re.findall(r"\{(.*?)\}", json_like)
                #print(fault_match)
                if len(fault_match) >= 2:
                    second_dict = fault_match[1]
                    key_match = re.match(r"'([^']+)'", second_dict.strip())
                    if key_match:
                        error_type = key_match.group(1)
                        if error_type == 'ESR':
                            #print(error_type, line)
                            if '\'ESR\': \'0x860000' in line or '\'ESR\': \'0x820000' in line:
                                error_type = 'Instruction Abort'
                            elif '\'ESR\': \'0x960000' in line or '\'ESR\': \'0x560000' in line or '\'ESR\': \'0x920000' in line:  
                                error_type = 'Data Abort'
                            else:
                                print(line)
            
            instruction_stats[instruction]['bit_errors'][bit].append(error_type)
            instruction_stats[instruction]['error_types'][error_type] += 1
    #print(instruction_stats)
    print(number)
    #exit()
    return instruction_stats

# 将指令的结果输出CSV文件
output_file = path + "/fault_summary.csv"
output = open(output_file, "w", newline="", encoding="utf-8")
writer = csv.writer(output)




def print_statistics(instruction_stats):
    print("=" * 80)
    print("错误日志分析报告")
    print("=" * 80)
    
    total_instructions = len(instruction_stats)
    total_flips = 0
    total_errors = 0
    total_normal = 0
    
    print(f"\n总共检测到 {total_instructions} 个不同的指令地址")
    print("\n各指令详细统计:")
    print("-" * 80)
    
    error_number = 0
    #error_instruction = []
    for instruction, stats in sorted(instruction_stats.items()):
        row = []
        #bit_error = [0] * 32

        # print(f"\n指令: {instruction}")
        # print(f"  总翻转次数: {stats['total_flips']}")
        # print(f"  正常运行: {stats['normal_count']} 次")
        # print(f"  发生错误: {stats['error_count']} 次")
        # print(f"  错误率: {stats['error_count']/stats['total_flips']*100:.2f}%")

        if stats['error_count'] > 0:
            error_number += 1
            #error_instruction.append(instruction)
        
        row.append(instruction)
        # 错误类型统计
        # if stats['error_types']:
        #     print("  错误类型分布:")
        #     for error_type, count in stats['error_types'].most_common():
        #         print(f"    - {error_type}: {count} 次")
        
        # 位错误统计
        # print("  各位错误统计:")
        for bit in sorted(stats['bit_errors'].keys()):
            type = 'NORMAL'
            errors = stats['bit_errors'][bit]
            error_count = len([e for e in errors if e != 'NORMAL'])
            normal_count = len([e for e in errors if e == 'NORMAL'])
            error_types = Counter([e for e in errors if e != 'NORMAL'])
            
            # print(f"    位 {bit:2d}: 翻转 {len(errors)} 次, "
            #       f"错误 {error_count} 次, "
            #       f"正常 {normal_count} 次")
            
            
            
            if error_types:
                type_str = ", ".join([f"{k}({v})" for k, v in error_types.items()])
                type = errors[0]
                # print(f"          错误类型: {type_str}")
            row.append(error_map.get(type, 0)) 
        writer.writerow(row)

        #print(row)
        # exit()
        
        total_flips += stats['total_flips']
        total_errors += stats['error_count']
        total_normal += stats['normal_count']
    
    # 总体统计
    print("\n" + "=" * 80)
    print("总体统计:")
    print("-" * 80)
    print(f"总翻转次数: {total_flips}")
    print(f"总正常运行次数: {total_normal}")
    print(f"总错误次数: {total_errors}")
    print(f"总体错误率: {total_errors/total_flips*100:.2f}%")
    print(f"错误指令数：{error_number}")
    
    # 全局错误类型统计
    global_error_types = Counter()
    for stats in instruction_stats.values():
        global_error_types.update(stats['error_types'])
    
    if global_error_types:
        print("\n全局错误类型分布:")
        for error_type, count in global_error_types.most_common():
            percentage = count / total_errors * 100
            print(f"  {error_type}: {count} 次 ({percentage:.1f}%)")


def has_fault(fault_types):
    """检查故障类型列表是否不全为0"""
    return any(fault != 0 for fault in fault_types)


error_instruction = {}
instruction_faults = defaultdict(lambda: defaultdict(int))
instruction_counts = defaultdict(int)

def draw_graph(instruction_fault):
    matrix = np.array(instruction_fault)

    # 转置，使横轴为指令、纵轴为bit位
    matrix_t = matrix.T   # shape: (32, 219)

    matrix_t = np.flipud(matrix_t)


    # 统一色调（蓝色）不同深浅
    cmap = ListedColormap([
        "#ffffffff",  # very light orange
        "#f1ebe3ff",  # light orange
        "#e2b56dff",  # medium orange
        "#e97603eb",  # deep orange
    ])


    plt.figure(figsize=(5, 2))

    # 绘制热力图
    plt.imshow(matrix_t, cmap=cmap, aspect='auto', interpolation='nearest')

    # 坐标轴标签
    plt.xlabel("Instruction Index", fontsize=8)
    plt.ylabel("Bit", fontsize=8)
    #plt.title("Fault Type Heatmap (Single Color Tone with Depth Levels)", fontsize=16)

    # -------- 关键部分：纵轴从下到上为 bit 0 → 31 --------
    #plt.gca().invert_yaxis()                       # 翻转 y 轴
    plt.yticks(ticks=np.arange(0, 32, 15), labels=[31 - t for t in np.arange(0, 32, 15)], fontsize=8)  # 下→上递增
    plt.xticks(fontsize=8)  

    # 颜色图例
    # cbar = plt.colorbar()
    # cbar.set_ticks([0, 1, 2, 3, 4])
    # cbar.set_ticklabels(["True", "System", "Syscall", "Network", "SDC"])
    # cbar.ax.tick_params(labelsize=8) 

    plt.tight_layout()
    plt.show()


def get_instructions():
    total_instructions = 0
    total_faults = 0
    #print("1111")
    #print(path + "\\fault_summary1.csv")
    with open(path + "\\fault_summary1.csv", 'r') as f:
        reader = csv.reader(f)
        all_number = []
        for row in reader:
            #print("111")
            instruction_number = [0]*32
            if not row:
                continue 
            addr = row[0]
            temp_array = row[1:]
            for i in range(len(temp_array)):
                if int(temp_array[i]) in range(1,8):
                    instruction_number[i] = 1
                elif int(temp_array[i]) in range(8, 18):
                    instruction_number[i] = 2
                elif int(temp_array[i]) in range(18, 25):
                    instruction_number[i] = 3
                elif int(temp_array[i]) == 25:
                    instruction_number[i] = 4
                    #print(addr)
            #print(instruction_number)
            
            fault_types = [int(x) for x in row[1:]]
            if addr in execution_addr or has_fault(fault_types):
                all_number.append(instruction_number)
                print(instruction_number)
                error_instruction[addr] = fault_types
                total_instructions += 1
                total_faults += len([f for f in fault_types if f != 0])
        #print(all_number)
        # draw_graph(all_number)
        # exit()

        instruction_types = {}
        index_number = 0
        for addr, faults in error_instruction.items():
            if addr not in addr_to_instr:
                continue
            
            instruction = addr_to_instr[addr]
            # 提取指令类型（第一个单词）
            instr_type = instruction.split()[0] if ' ' in instruction else instruction
        
            instruction_counts[instr_type] += 1
        
            # # 统计每种故障类型的数量
            # for fault_type in faults:
            #     instruction_faults[instr_type][fault_type] += 1
            
            if instr_type not in instruction_types:
                instruction_types[instr_type] = {
                    "addr": [],
                    "faults": []
                }

            instruction_types[instr_type]['addr'].append(addr)
            instruction_types[instr_type]['faults'].append(all_number[index_number])
            index_number += 1

        json_path = "\error_instruction.json"
        with open(path+json_path, "a", encoding="utf-8") as jf:
            json.dump(instruction_types, jf, indent=2, ensure_ascii=False)
        exit()
        for instr_types, value in instruction_types.items():
            print(instr_types)
            addr = value['addr']
            faults = value['faults']
            fault_num = 0
            total_num = 0
            for i in range(len(addr)):
                total_num += len(faults[i])
                fault_num += len([f for f in faults[i] if f != 0])
            print("Error Rate: ", fault_num / total_num)
                #print(addr[i], faults[i])
        #exit()


            # 计算统计信息
        stats = {
            'total_instructions': total_instructions,
            'total_faults': total_faults,
            'fault_rate': total_faults / (total_instructions * 32) if total_instructions > 0 else 0,  # 假设32位指令
            'instruction_types': {},
            'fault_type_summary': defaultdict(int)
        }

        # 计算每种指令类型的故障分布
        for instr_type, faults_dict in instruction_faults.items():
            total_faults_for_type = sum(faults_dict.values())
            count = instruction_counts[instr_type]

            stats['instruction_types'][instr_type] = {
                'count': count,
                'percentage': count / total_instructions * 100 if total_instructions > 0 else 0,
                'total_faults': total_faults_for_type,
                'fault_rate': total_faults_for_type / (count * 32) if count > 0 else 0,  # 假设32位指令
                'fault_breakdown': dict(faults_dict)
            }

            # 汇总所有故障类型
            for fault_type, fault_count in faults_dict.items():
                stats['fault_type_summary'][fault_type] += fault_count
    return stats
    
def print_fault_analysis(stats):
    """
    打印故障分析结果
    
    Args:
        stats (dict): 故障统计信息
    """
    if not stats:
        print("没有可用的统计数据")
        return
    
    print("\n=== 故障分析汇总 ===")
    print(f"总指令数: {stats['total_instructions']}")
    print(f"总故障数: {stats['total_faults']}")
    print(f"总体故障率: {stats['fault_rate']:.6f}")
    
    print("\n=== 故障类型分布 ===")
    for fault_type, count in sorted(stats['fault_type_summary'].items()):
        percentage = count / stats['total_faults'] * 100 if stats['total_faults'] > 0 else 0
        print(f"  故障类型 {fault_type}: {count} 次 ({percentage:.2f}%)")
    
    print("\n=== 按指令类型的故障分布 ===")
    for instr_type, data in sorted(stats['instruction_types'].items(), 
                                  key=lambda x: x[1]['total_faults'], reverse=True):
        print(f"\n指令类型: {instr_type}")
        print(f"  出现次数: {data['count']} ({data['percentage']:.2f}%)")
        print(f"  总故障数: {data['total_faults']}")
        print(f"  故障率: {data['fault_rate']:.6f}")
        print(f"  故障类型分布:")
        for fault_type, count in sorted(data['fault_breakdown'].items()):
            percentage = count / data['total_faults'] * 100 if data['total_faults'] > 0 else 0
            print(f"    类型 {fault_type}: {count} 次 ({percentage:.2f}%)")


# 使用示例
if __name__ == "__main__":
    # 这里假设文件内容已经读取到 file_content 变量中
    # 在实际使用中，你需要从文件中读取内容
    
    # 示例用法：
    with open( path + '/error.log', 'r') as f:
        file_content = f.read()
    
    # 使用提供的文件内容进行分析
    stats = analyze_error_log(file_content)
    # print(stats)
    # exit()
    print_statistics(stats)
    instructions = get_instructions()
    print_fault_analysis(instructions)
  