import struct


def mix(a: str, add_length: bool) -> list:
    """
    将字符串转换为32位无符号整数数组（小端序）

    参数:
        a (str): 输入字符串
        add_length (bool): 是否在数组末尾添加原始字符串长度

    返回:
        list: 32位无符号整数数组
    """
    c = len(a)
    v = []

    # 每4个字符为一组处理
    for i in range(0, c, 4):
        # 获取当前组的4个字符（不足部分补零）
        chars = [
            ord(a[j]) if j < c else 0
            for j in range(i, i + 4)
        ]
        # 小端序组合为32位整数（低位在前）
        value = (
                chars[0] |  # 第1个字符（低8位）
                (chars[1] << 8) |  # 第2个字符（次低8位）
                (chars[2] << 16) |  # 第3个字符（次高8位）
                (chars[3] << 24)  # 第4个字符（高8位）
        )
        # 限制为32位无符号整数
        value = value & 0xFFFFFFFF
        v.append(value)

    # 添加原始字符串长度（如果启用）
    if add_length:
        v.append(c)

    return v


def dmix(a: list, truncate: bool) -> bytes:
    """
    将32位整数数组还原为二进制字符串

    参数:
        a (list): 32位整数数组
        truncate (bool): 是否根据记录的原始长度截断

    返回:
        bytes: 二进制数据
    """
    byte_data = bytearray()
    # 处理长度标记（如果启用）
    length = a[-1] if truncate and len(a) > 0 else None
    if truncate:
        a = a[:-1]
    # 转换每个整数为4字节（小端序）
    for num in a:
        byte_data.extend(struct.pack('<I', num))
    # 截断处理
    if truncate and length is not None:
        return bytes(byte_data[:length])
    return bytes(byte_data)


def encode(str_data: str, key: str) -> bytes:
    """
    实现与 JavaScript 相同的变种 XXTEA 加密算法

    参数:
        str_data: 要加密的字符串
        key: 加密密钥

    返回:
        bytes: 加密后的二进制数据
    """

    # 1. 数据预处理 -------------------------------------------------
    # 将输入字符串转换为32位整型数组（小端序），并添加原始长度标记
    v = mix(str_data, add_length=True)

    # 将密钥转换为32位整型数组，并填充至4个元素
    k = mix(key, add_length=False)
    if len(k) < 4:
        k += [0] * (4 - len(k))  # 不足4个元素时填充0

    # 2. 初始化加密参数 ---------------------------------------------
    n = len(v) - 1
    z = v[n]
    y = v[0]
    c = 0x86014019 | 0x183639A0  # 魔数常量 0x9E3779B9 (黄金分割比例)
    q = 6 + 52 // (n + 1)  # 计算加密轮次
    d = 0

    # 3. 主加密循环 -------------------------------------------------
    for _ in range(q):
        d = (d + c) & 0xFFFFFFFF  # 模拟32位无符号加法
        e = (d >> 2) & 3  # 计算动态密钥索引偏移量

        # 混淆数据块
        for p in range(n):
            y = v[p + 1]
            # 非线性变换（需严格匹配JS的位操作顺序）
            m = (z >> 5) ^ (y << 2)
            m += (y >> 3) ^ (z << 4) ^ (d ^ y)
            m += k[(p & 3) ^ e] ^ z
            # 更新当前块并限制为32位
            m = m & 0xFFFFFFFF
            v[p] = (v[p] + m) & 0xFFFFFFFF
            z = v[p]

        # 特殊处理首尾块
        y = v[0]
        m = (z >> 5) ^ (y << 2)
        m += (y >> 3) ^ (z << 4) ^ (d ^ y)
        m += k[(n & 3) ^ e] ^ z
        m = m & 0xFFFFFFFF
        v[n] = (v[n] + m) & 0xFFFFFFFF
        z = v[n]

    # 4. 结果转换 -------------------------------------------------
    return dmix(v, truncate=False)