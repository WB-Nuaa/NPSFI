import re
import os
from collections import defaultdict, Counter
import csv
path =  os.path.dirname(os.path.abspath(__file__))
from datetime import datetime, timedelta

#错误字典
error_map = {
    "NORMAL" : 0,
    "Data Abort": 1,
    "Instruction Abort": 2,
    "Kernel": 3,
    "Oops": 4,
    "Errno14: Bad address" :5,
    "Errno1: Operation not permitted" : 6,
    "Errno19: No such device" : 7,
    "Errno22: invalid argument" : 8,
    "Errno97: Address family not supported by protocol" : 9,
    "Errno90: Message too long" : 10,
    "Errno95: Operation not supported" : 11,
    "Errno89: Destination address required" : 12,
    "Errno0: error" : 13,
    "Errno11: Resource temporarily unavailable" : 14,
    "RCU" : 15,
    "IPv4: Attempt to release alive inet socket": 16,
    "Tx Unit Hang" : 17,
    "Internal error: ptrace BRK handler": 18,
    "Network TimeOut" : 19,
    "BUG: scheduling while atomic" : 20,
    "SDC" : 21, 
    "Error Port" : 22
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

print(abnormal_times)
print(abnormal_ports)



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
    
    for instruction, stats in sorted(instruction_stats.items()):
        row = []
        #bit_error = [0] * 32

        print(f"\n指令: {instruction}")
        print(f"  总翻转次数: {stats['total_flips']}")
        print(f"  正常运行: {stats['normal_count']} 次")
        print(f"  发生错误: {stats['error_count']} 次")
        print(f"  错误率: {stats['error_count']/stats['total_flips']*100:.2f}%")
        
        row.append(instruction)
        # 错误类型统计
        if stats['error_types']:
            print("  错误类型分布:")
            for error_type, count in stats['error_types'].most_common():
                print(f"    - {error_type}: {count} 次")
        
        # 位错误统计
        print("  各位错误统计:")
        for bit in sorted(stats['bit_errors'].keys()):
            type = 'NORMAL'
            errors = stats['bit_errors'][bit]
            error_count = len([e for e in errors if e != 'NORMAL'])
            normal_count = len([e for e in errors if e == 'NORMAL'])
            error_types = Counter([e for e in errors if e != 'NORMAL'])
            
            print(f"    位 {bit:2d}: 翻转 {len(errors)} 次, "
                  f"错误 {error_count} 次, "
                  f"正常 {normal_count} 次")
            
            
            
            if error_types:
                type_str = ", ".join([f"{k}({v})" for k, v in error_types.items()])
                type = errors[0]
                print(f"          错误类型: {type_str}")
            row.append(error_map.get(type, 0)) 
        writer.writerow(row)

        #print(row)
        #exit()
        
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
    
    # 全局错误类型统计
    global_error_types = Counter()
    for stats in instruction_stats.values():
        global_error_types.update(stats['error_types'])
    
    if global_error_types:
        print("\n全局错误类型分布:")
        for error_type, count in global_error_types.most_common():
            percentage = count / total_errors * 100
            print(f"  {error_type}: {count} 次 ({percentage:.1f}%)")

# 使用示例
if __name__ == "__main__":
    # 这里假设文件内容已经读取到 file_content 变量中
    # 在实际使用中，你需要从文件中读取内容
    
    # 示例用法：
    with open( path + '/error.log', 'r') as f:
        file_content = f.read()
    
    # 使用提供的文件内容进行分析
    stats = analyze_error_log(file_content)
    print_statistics(stats)
    
  