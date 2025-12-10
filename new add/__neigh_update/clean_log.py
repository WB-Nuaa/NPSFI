import os
import re
from glob import glob

def is_text_char(byte):
    """检查字节是否为可打印ASCII字符或常见控制字符"""
    return (
        32 <= byte <= 126 or  # 可打印ASCII
        byte in {9, 10, 13}   # 制表符(\t)、换行(\n)、回车(\r)
    )

def decode_special_chars(filename):
    """将文件名中的^%XX编码转换为实际字符（如^%40→@）"""
    decoded = []
    i = 0
    while i < len(filename):
        if filename[i] == '^' and i + 3 <= len(filename) and filename[i+1] == '%':
            hex_code = filename[i+2:i+4]
            if re.match(r'[0-9A-Fa-f]{2}', hex_code):
                decoded.append(chr(int(hex_code, 16)))
                i += 4
                continue
        decoded.append(filename[i])
        i += 1
    return ''.join(decoded)

def clean_filename(original_name):
    """
    将原始日志文件名转换为规范格式
    示例输入: "2025-07-21 21^%38^%16.log"
    示例输出: "2025-07-21_21-38-16.log"
    """
    # 使用正则表达式提取日期和时间组件
    match = re.match(
        r'^(\d{4}-\d{2}-\d{2})[ _]?(\d{2})\^%(\d{2})\^%(\d{2})\.log$',
        original_name,
        re.IGNORECASE
    )
    
    if not match:
        raise ValueError(f"文件名格式不匹配: {original_name}")
    
    date, hour, minute, second = match.groups()
    # print(f"{date}_{hour}-{minute}-{second}.log")
    # exit()
    return f"{date}_{hour}-{minute}-{second}.log"

def clean_log_content(input_path, output_path):
    """清理.log文件内容中的二进制字符"""
    try:
        with open(input_path, 'rb') as f_in:
            raw_data = f_in.read()
        
        # 过滤二进制字符
        cleaned_data = bytes(b for b in raw_data if is_text_char(b))
        
        # 写入新文件
        with open(output_path, 'wb') as f_out:
            f_out.write(cleaned_data)
        return True
    except Exception as e:
        print(f"处理文件 {input_path} 时出错: {e}")
        return False

def process_all_logs(input_dir="neigh_resolve_output/error_result"):
    """处理input_dir下所有.log文件"""
    if not os.path.exists(input_dir):
        print(f"目录不存在: {input_dir}")
        return
    
    # 创建输出目录（可选）
    output_dir = "./neigh_resolve_output/results/"
    os.makedirs(output_dir, exist_ok=True)
    
    # 遍历.log文件
    for input_path in glob(os.path.join(input_dir, "*.log")):
        filename = os.path.basename(input_path)
        cleaned_name = clean_filename(filename)
        output_path = os.path.join(output_dir, cleaned_name)
        
        print(f"处理: {filename} → {cleaned_name}")
        clean_log_content(input_path, output_path)
    
    print(f"处理完成！结果保存在: {output_dir}")

if __name__ == "__main__":
    process_all_logs()