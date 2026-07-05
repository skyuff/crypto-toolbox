/**
 * 依据「商用密码检测工具箱功能清单.md」整理的完整菜单结构。
 * 每一项对应一个路由；核心页面已实现，其余先用占位页 Placeholder。
 */
export const menus = [
  {
    title: '对称密码校验',
    children: [
      { title: '分组密码', path: '/group', view: 'symmetric/GroupView' },
      { title: '序列密码', path: '/seq', view: 'symmetric/SequenceView' },
      { title: 'GCM', path: '/gcm', view: 'symmetric/GcmView' }
    ]
  },
  {
    title: '哈希算法校验',
    children: [
      { title: '哈希与HMAC', path: '/hash', view: 'hash/HashView' },
      { title: 'MAC算法', path: '/mac', view: 'hash/MacView' },
      { title: '哈希算法猜测', path: '/hash/all', view: 'hash/HashAllView' }
    ]
  },
  {
    title: '非对称算法校验',
    children: [
      { title: 'SM2算法', path: '/sm2', view: 'asymmetric/SM2View' },
      { title: 'SM9算法', path: '/sm9', view: 'asymmetric/SM9View' },
      { title: 'RSA算法', path: '/rsa', view: 'asymmetric/RSAView' },
      { title: 'ECDSA算法', path: '/ecdsa', view: 'asymmetric/ECDSAView' },
      { title: 'Attach&Detach', path: '/attach', view: 'asymmetric/AttachView' },
      { title: '点压缩和解压缩', path: '/compress', view: 'asymmetric/CompressView' }
    ]
  },
  {
    title: '数字证书校验',
    children: [
      { title: '证书格式检查', path: '/cert/format/check', view: 'cert/CertFormatCheck' },
      { title: '证书撤销检查', path: '/cert/status/check', view: 'cert/CertStatusCheck' },
      { title: 'CRL有效性校验', path: '/crl/status/check', view: 'cert/CrlFormatCheck' },
      { title: '证书在线签发', path: '/cert/sign/issue', view: 'cert/CertSignAndIssue' },
      { title: 'ASN.1解析', path: '/cert/parse/asn1', view: 'cert/CertFormatASN1' }
    ]
  },
  {
    title: '协议分析工具',
    children: [
      { title: 'SSH包解析', path: '/ssh', view: 'parse/SshView' },
      { title: 'TLS包解析', path: '/tls', view: 'parse/TlsView' },
      { title: 'IPSEC包解析', path: '/ipsec', view: 'parse/IpsecView' }
    ]
  },
  {
    title: '能力验证必备',
    children: [
      { title: 'PRF运算', path: '/prf', view: 'operation/PrfView' },
      { title: 'KDF运算', path: '/kdf', view: 'operation/KdfView' },
      { title: 'TLS密钥生成', path: '/tlcp', view: 'operation/TlcpView' },
      { title: 'SM2加密-K', path: '/sm2k', view: 'operation/Sm2kView' },
      { title: '签名攻击', path: '/unravelSm2', view: 'operation/UnravelSm2View' },
      { title: '点运算', path: '/multiply', view: 'operation/MultiplyView' },
      { title: '口令密钥派生', path: '/pbkdf2', view: 'operation/Pbkdf2View' },
      { title: '工作模式检测', path: '/cipher/mode/detector', view: 'other/CipherModeDetectorView' }
    ]
  },
  {
    title: '其他常用工具',
    children: [
      { title: '密文长度分析', path: '/length', view: 'other/CipherLengthView' },
      { title: '大数运算', path: '/big/number', view: 'other/BigNumberView' },
      { title: '取模运算', path: '/mod/number', view: 'other/ModView' },
      { title: '逻辑运算', path: '/xor', view: 'other/XORView' },
      { title: '字节逆序', path: '/byte/reverse', view: 'other/ByteReverseView' }
    ]
  },
  {
    title: '独立工具',
    children: [
      { title: '编码转换', path: '/encode', view: 'encod/EncodingView' },
      { title: 'UKey包解析', path: '/ukey', view: 'parse/UkeyView' },
      { title: '随机数检测', path: '/randomness', view: 'random/RandomnessView' },
      { title: '时间戳解析', path: '/timestamp', view: 'timestamp/TimestampView' },
      { title: '电子签章校验', path: '/signatrue', view: 'signature/SignatureView' }
    ]
  }
]
