import os, collections

# 读取刚才生成的演示数据
with open('randomness_demo_100000bits.hex', 'r') as f:
    hex_data = f.read()

# Java toBits: 每字节按 MSB->LSB 展开为 8 比特
bits = []
for i in range(0, len(hex_data), 2):
    b = int(hex_data[i:i+2], 16)
    for j in range(8):
        bits.append((b >> (7 - j)) & 1)

n = len(bits)
print(f'n={n}, 前20比特={bits[:20]}')

def psi2(bits, n, m):
    if m <= 0:
        return 0.0
    freq = collections.Counter()
    for i in range(n):
        pattern = ''.join(str(bits[(i + j) % n]) for j in range(m))
        freq[pattern] += 1
    s = sum(c * c for c in freq.values())
    return (s * (2 ** m) / n) - n

for m in [1, 2, 3]:
    val = psi2(bits, n, m)
    freq = collections.Counter(''.join(str(bits[(i + j) % n]) for j in range(m)) for i in range(n))
    print(f'psi2_{m} = {val:.6f}, 模式数={len(freq)}, 频率={dict(freq)}')

# m=1 的具体频率
freq1 = collections.Counter(str(bits[i]) for i in range(n))
print('m=1 freq:', dict(freq1))
print('sum squares m=1:', sum(c*c for c in freq1.values()))
print('expected psi2_1:', (2/n) * sum(c*c for c in freq1.values()) - n)
