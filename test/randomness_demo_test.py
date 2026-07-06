import os, json, urllib.request, time

def find_passing_sample(max_attempts=50):
    for attempt in range(1, max_attempts + 1):
        data = os.urandom(12500)
        hex_data = data.hex()

        payload = json.dumps({
            'input': hex_data,
            'format': 'hex',
            'bitLength': 100000,
            'selectedMethods': list(range(1, 29))
        }).encode('utf-8')
        req = urllib.request.Request(
            'http://localhost:8080/api/randomness/test',
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())['data']

        if result['overallPass']:
            return hex_data, result, attempt
    return None, None, max_attempts

# 获取检测方法列表
with urllib.request.urlopen('http://localhost:8080/api/randomness/methods') as resp:
    methods = json.loads(resp.read())['data']
print(f"后端共支持 {len(methods)} 种检测方法")

# 寻找一个全部通过的演示样本
start = time.time()
hex_data, result, attempts = find_passing_sample()
elapsed = time.time() - start

if result is None:
    print(f"尝试 {attempts} 次后仍未找到全部通过的样本，这是正常的随机波动现象。")
    exit(1)

# 保存演示数据
with open('randomness_demo_100000bits.hex', 'w', encoding='utf-8') as f:
    f.write(hex_data)

print(f"\n已生成并通过全部 28 项检测的演示数据")
print(f"尝试次数: {attempts}")
print(f"数据大小: 12500 字节 / 100000 比特")
print(f"文件保存至: randomness_demo_100000bits.hex")
print(f"Hex 前 64 字符: {hex_data[:64]}")
print(f"检测耗时: {elapsed:.2f} 秒")
print(f"比特长度: {result['bitLength']}")
print(f"总体结论: 通过")
print(f"\n{'编号':<4} {'检测项':<40} {'P-value':<14} {'结论':<6}")
print("-" * 70)
for t in result['tests']:
    p = t['pValue']
    p_str = f"{p:.6f}" if p >= 0.000001 else "<0.000001"
    status = "PASS" if t['pass'] else "FAIL"
    print(f"{t['id']:<4} {t['name']:<40} {p_str:<14} {status:<6}")
