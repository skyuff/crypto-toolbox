# 商用密码检测工具箱

一个功能完整的商用密码算法检测与分析工具集，涵盖对称密码、非对称密码、哈希算法、数字证书、协议分析等多个领域。

## 技术栈

### 后端
- **框架**: Spring Boot 3.3.4
- **Java 版本**: 17
- **核心依赖**:
  - BouncyCastle 1.78.1 (国密算法 SM2/SM3/SM4、证书、ASN.1)
  - Apache PDFBox 3.0.2 (PDF 电子签章解析)
  - Lombok (简化代码)

### 前端
- **框架**: Vue 3.5.10
- **构建工具**: Vite 5.4.8
- **UI 组件库**: Element Plus 2.8.4
- **状态管理**: Pinia 2.2.2
- **HTTP 客户端**: Axios 1.7.7

---

## 功能清单

### 1. 对称密码校验

#### 1.1 分组密码
- **功能**: SM4、AES 等分组密码的加密/解密
- **实现方式**: 基于 BouncyCastle 的 BlockCipherService
- **后端路径**: `backend/src/main/java/com/smtool/module/symmetric/BlockCipherService.java`
- **前端路径**: `frontend/src/views/symmetric/GroupView.vue`
- **API 端点**: `/api/symmetric/encrypt`, `/api/symmetric/decrypt`
- **支持算法**: SM4、AES (ECB/CBC/CFB/OFB/CTR 模式)

#### 1.2 序列密码
- **功能**: ZUC、RC4 等序列密码的加密/解密
- **实现方式**: 基于 BouncyCastle 的 StreamCipherService
- **后端路径**: `backend/src/main/java/com/smtool/module/symmetric/StreamCipherService.java`
- **前端路径**: `frontend/src/views/symmetric/SequenceView.vue`
- **API 端点**: `/api/symmetric/stream-encrypt`, `/api/symmetric/stream-decrypt`
- **支持算法**: ZUC、RC4

#### 1.3 GCM 模式
- **功能**: AES-GCM、SM4-GCM 认证加密
- **实现方式**: 基于 BouncyCastle 的 GcmCipherService
- **后端路径**: `backend/src/main/java/com/smtool/module/symmetric/GcmCipherService.java`
- **前端路径**: `frontend/src/views/symmetric/GcmView.vue`
- **API 端点**: `/api/symmetric/gcm-encrypt`, `/api/symmetric/gcm-decrypt`
- **支持算法**: AES-GCM、SM4-GCM

---

### 2. 哈希算法校验

#### 2.1 哈希与 HMAC
- **功能**: 计算消息的哈希值和 HMAC
- **实现方式**: 基于 BouncyCastle 和 JDK 的 HashService、MacService
- **后端路径**: 
  - `backend/src/main/java/com/smtool/module/hash/HashService.java`
  - `backend/src/main/java/com/smtool/module/hash/MacService.java`
- **前端路径**: `frontend/src/views/hash/HashView.vue`
- **API 端点**: `/api/hash/compute`, `/api/hash/hmac`
- **支持算法**: 
  - 哈希: SM3、SHA-1/224/256/384/512、SHA3-224/256/384/512、MD5
  - HMAC: 同上所有哈希算法

#### 2.2 MAC 算法
- **功能**: CMAC、GMAC 等消息认证码计算
- **实现方式**: 基于 BouncyCastle 的 MacService
- **后端路径**: `backend/src/main/java/com/smtool/module/hash/MacService.java`
- **前端路径**: `frontend/src/views/hash/MacView.vue`
- **API 端点**: `/api/hash/mac`
- **支持算法**: AES-CMAC、SM4-CMAC、GMAC

#### 2.3 哈希算法猜测
- **功能**: 根据输入自动猜测可能的哈希算法
- **实现方式**: 基于 HashService 的多算法并行计算
- **后端路径**: `backend/src/main/java/com/smtool/module/hash/HashService.java`
- **前端路径**: `frontend/src/views/hash/HashAllView.vue`
- **API 端点**: `/api/hash/guess`

---

### 3. 非对称算法校验

#### 3.1 SM2 算法
- **功能**: SM2 密钥生成、签名验签、加密解密
- **实现方式**: 基于 BouncyCastle 的 SM2Service
- **后端路径**: `backend/src/main/java/com/smtool/module/sm2/SM2Service.java`
- **前端路径**: `frontend/src/views/asymmetric/SM2View.vue`
- **API 端点**: 
  - `/api/sm2/keygen` (密钥生成)
  - `/api/sm2/sign`, `/api/sm2/verify` (签名验签)
  - `/api/sm2/encrypt`, `/api/sm2/decrypt` (加密解密)

#### 3.2 SM9 算法
- **功能**: SM9 标识密码算法（纯 Java BigInteger 实现）
- **实现方式**: 基于双线性对运算的 SM9Service 和核心数学库
- **后端路径**: 
  - `backend/src/main/java/com/smtool/module/sm9/SM9Service.java`
  - `backend/src/main/java/com/smtool/module/sm9/core/` (Fp2, Fp4, Fp12, PointG1, PointG2, SM9Pairing)
- **前端路径**: `frontend/src/views/asymmetric/SM9View.vue`
- **API 端点**: 
  - `/api/sm9/keygen` (密钥生成)
  - `/api/sm9/sign`, `/api/sm9/verify` (签名验签)
  - `/api/sm9/encrypt`, `/api/sm9/decrypt` (加密解密)

#### 3.3 RSA 算法
- **功能**: RSA 密钥生成、签名验签、加密解密
- **实现方式**: 基于 JDK 和 BouncyCastle 的 RSAService
- **后端路径**: `backend/src/main/java/com/smtool/module/asymmetric/RSAService.java`
- **前端路径**: `frontend/src/views/asymmetric/RSAView.vue`
- **API 端点**: 
  - `/api/rsa/keygen` (密钥生成)
  - `/api/rsa/sign`, `/api/rsa/verify` (签名验签)
  - `/api/rsa/encrypt`, `/api/rsa/decrypt` (加密解密)
- **支持密钥长度**: 1024、2048、3072、4096 位

#### 3.4 ECDSA 算法
- **功能**: ECDSA 密钥生成、签名验签
- **实现方式**: 基于 BouncyCastle 的 ECDSAService
- **后端路径**: `backend/src/main/java/com/smtool/module/asymmetric/ECDSAService.java`
- **前端路径**: `frontend/src/views/asymmetric/ECDSAView.vue`
- **API 端点**: 
  - `/api/ecdsa/keygen` (密钥生成)
  - `/api/ecdsa/sign`, `/api/ecdsa/verify` (签名验签)
- **支持曲线**: sm2p256v1、secp256k1、prime256v1 (P-256)、secp384r1 (P-384)、secp521r1 (P-521)

#### 3.5 Attach & Detach
- **功能**: 附加数据签名（Attach）和分离验证（Detach）
- **实现方式**: 基于 SM2/RSA 的签名服务
- **后端路径**: `backend/src/main/java/com/smtool/module/asymmetric/` (复用 SM2Service/RSAService)
- **前端路径**: `frontend/src/views/asymmetric/AttachView.vue`

#### 3.6 点压缩和解压缩
- **功能**: 椭圆曲线点的压缩与解压缩
- **实现方式**: 基于 BouncyCastle 的 PointService
- **后端路径**: `backend/src/main/java/com/smtool/module/asymmetric/PointService.java`
- **前端路径**: `frontend/src/views/asymmetric/CompressView.vue`
- **API 端点**: `/api/point/compress`, `/api/point/decompress`

---

### 4. 数字证书校验

#### 4.1 证书格式检查
- **功能**: 验证证书格式、解析证书内容、检查证书链
- **实现方式**: 基于 BouncyCastle 的 CertCheckService
- **后端路径**: `backend/src/main/java/com/smtool/module/cert/CertCheckService.java`
- **前端路径**: `frontend/src/views/cert/CertFormatCheck.vue`
- **API 端点**: `/api/cert/check`
- **布局**: 左右布局（左侧证书链结构，右侧验证结果）

#### 4.2 证书撤销检查
- **功能**: 检查证书是否被撤销（CRL/OCSP）
- **实现方式**: 基于 CertStatusService
- **后端路径**: `backend/src/main/java/com/smtool/module/cert/CertStatusService.java`
- **前端路径**: `frontend/src/views/cert/CertStatusCheck.vue`
- **API 端点**: `/api/cert/status`
- **布局**: 左右布局（左侧证书输入，右侧 CRL 输入）

#### 4.3 CRL 有效性校验
- **功能**: 验证 CRL 格式和签名有效性
- **实现方式**: 基于 CrlCheckService
- **后端路径**: `backend/src/main/java/com/smtool/module/cert/CrlCheckService.java`
- **前端路径**: `frontend/src/views/cert/CrlFormatCheck.vue`
- **API 端点**: `/api/crl/check`
- **布局**: 左右布局（左侧 CRL 输入，右侧签发者证书输入）

#### 4.4 证书在线签发
- **功能**: CSR 生成和证书签发
- **实现方式**: 基于 CertIssueService
- **后端路径**: `backend/src/main/java/com/smtool/module/cert/CertIssueService.java`
- **前端路径**: `frontend/src/views/cert/CertSignAndIssue.vue`
- **API 端点**: 
  - `/api/cert/csr` (生成 CSR)
  - `/api/cert/issue` (签发证书)
- **功能模块**:
  - CSR 生成 tab
  - 证书签发 tab（包含两个子功能：直接生成 PFX 证书、提交证书请求 P10）
  - 证书类型：用户证书、CA 中间证书、SSL 证书
  - PFX 密码输入

#### 4.5 ASN.1 解析
- **功能**: 解析 ASN.1 编码的证书内容
- **实现方式**: 基于 Asn1ParseService
- **后端路径**: `backend/src/main/java/com/smtool/module/cert/Asn1ParseService.java`
- **前端路径**: `frontend/src/views/cert/CertFormatASN1.vue`
- **API 端点**: `/api/cert/asn1/parse`
- **支持格式**: Hex、Base64、PEM、自动识别
- **特性**: 支持证书文件上传，树形结构展示

---

### 5. 协议分析工具

#### 5.1 SSH 包解析
- **功能**: 解析 SSH 协议流量包
- **实现方式**: 基于 SshParseService 的字节流解析
- **后端路径**: `backend/src/main/java/com/smtool/module/parse/SshParseService.java`
- **前端路径**: `frontend/src/views/parse/SshView.vue`
- **API 端点**: `/api/ssh/parse`
- **输入**: 流量包文件、源 IP、目标 IP、目标端口（默认 22）
- **输出**: APDU 包列表、协议信息

#### 5.2 TLS 包解析
- **功能**: 解析 TLS/SSL 协议流量包
- **实现方式**: 基于 TlsParseService 的字节流解析
- **后端路径**: `backend/src/main/java/com/smtool/module/parse/TlsParseService.java`
- **前端路径**: `frontend/src/views/parse/TlsView.vue`
- **API 端点**: `/api/tls/parse`
- **输入**: 流量包文件、源 IP、目标 IP
- **输出**: TLS 报文解析结果

#### 5.3 IPSec 包解析
- **功能**: 解析 IPSec/IKE 协议流量包
- **实现方式**: 基于 IpsecParseService 的字节流解析
- **后端路径**: `backend/src/main/java/com/smtool/module/parse/IpsecParseService.java`
- **前端路径**: `frontend/src/views/parse/IpsecView.vue`
- **API 端点**: `/api/ipsec/parse`
- **输入**: 流量包文件、源 IP、目标 IP
- **输出**: IPSec/IKE 报文解析结果

---

### 6. 能力验证必备

#### 6.1 PRF 运算
- **功能**: TLS 1.2 PRF 伪随机函数计算
- **实现方式**: 基于 PrfService 的哈希迭代
- **后端路径**: `backend/src/main/java/com/smtool/module/operation/PrfService.java`
- **前端路径**: `frontend/src/views/operation/PrfView.vue`
- **API 端点**: `/api/prf/compute`
- **公式**: PRF(secret, label, seed) = P_hash(secret, label || seed)
- **支持算法**: SM3、SHA-224/256/384/512、SHA3 系列、SHA-1、MD5

#### 6.2 KDF 运算
- **功能**: GM/T KDF 密钥派生函数
- **实现方式**: 基于 KdfService 的计数器模式派生
- **后端路径**: `backend/src/main/java/com/smtool/module/operation/KdfService.java`
- **前端路径**: `frontend/src/views/operation/KdfView.vue`
- **API 端点**: `/api/kdf/derive`
- **公式**: Hai = Hash(Z || counter)
- **支持算法**: SM3、SHA 系列

#### 6.3 TLS 密钥生成
- **功能**: 模拟 TLS/TLCP 密钥派生全过程
- **实现方式**: 基于 TlsKeyService
- **后端路径**: `backend/src/main/java/com/smtool/module/operation/TlsKeyService.java`
- **前端路径**: `frontend/src/views/operation/TlcpView.vue`
- **API 端点**: `/api/tlskey/generate`
- **流程**: PreMasterSecret → MasterSecret(48B) → KeyBlock
- **密码套件类型**:
  - 分组算法（默认 KeyBlock 104 字节）
  - GCM (AEAD)（默认 KeyBlock 40 字节）

#### 6.4 SM2 加密-K 碰撞分析
- **功能**: SM2 加密随机数 k 碰撞分析与明文恢复
- **实现方式**: 基于 Sm2kService 的暴力搜索（1-1,000,000 范围）
- **后端路径**: `backend/src/main/java/com/smtool/module/operation/Sm2kService.java`
- **前端路径**: `frontend/src/views/operation/Sm2kView.vue`
- **API 端点**: 
  - `/api/sm2k/collide` (碰撞随机数 k)
  - `/api/sm2k/recover` (恢复明文)
- **支持格式**: C1C3C2、C1C2C3

#### 6.5 签名攻击（SM2 随机数重用攻击）
- **功能**: 利用随机数重用恢复私钥
- **实现方式**: 基于 SigAttackService 的数学攻击
- **后端路径**: `backend/src/main/java/com/smtool/module/operation/SigAttackService.java`
- **前端路径**: `frontend/src/views/operation/UnravelSm2View.vue`
- **API 端点**: `/api/sig-attack/recover`
- **攻击原理**: 两组签名使用相同随机数 k 时，可恢复私钥 d
- **输出**: 恢复的私钥 d、随机数 k、推导公钥 P = d·G
- **验证**: 使用推导公钥验证两组签名

#### 6.6 点运算
- **功能**: 椭圆曲线点乘、点加、点减运算
- **实现方式**: 基于 PointOpService
- **后端路径**: `backend/src/main/java/com/smtool/module/operation/PointOpService.java`
- **前端路径**: `frontend/src/views/operation/MultiplyView.vue`
- **API 端点**: `/api/point/op`
- **支持运算**: 点乘 [k]P、点加 P+Q、点减 P-Q
- **支持曲线**: sm2p256v1、secp256k1、prime256v1、secp384r1、secp521r1

#### 6.7 口令密钥派生 (PBKDF2)
- **功能**: 基于口令的密钥派生
- **实现方式**: 基于 Pbkdf2Service 的 PBKDF2 算法
- **后端路径**: `backend/src/main/java/com/smtool/module/operation/Pbkdf2Service.java`
- **前端路径**: `frontend/src/views/operation/Pbkdf2View.vue`
- **API 端点**: `/api/pbkdf2/derive`
- **支持算法**: SM3、SHA-224/256/384/512、SHA3 系列、SHA-1、MD5
- **参数**: 迭代次数（默认 1024）、密钥长度

#### 6.8 工作模式检测
- **功能**: 检测密文使用的加密工作模式
- **实现方式**: 基于 CipherModeService 的模式识别
- **后端路径**: `backend/src/main/java/com/smtool/module/other/CipherModeService.java`
- **前端路径**: `frontend/src/views/other/CipherModeDetectorView.vue`
- **API 端点**: `/api/cipher/mode/detect`

---

### 7. 其他常用工具

#### 7.1 密文长度分析
- **功能**: 分析密文长度与算法、安全强度的关系
- **实现方式**: 基于 CipherLengthService 的预定义规则
- **后端路径**: `backend/src/main/java/com/smtool/module/other/CipherLengthService.java`
- **前端路径**: `frontend/src/views/other/CipherLengthView.vue`
- **API 端点**: `/api/cipher/length/analyze`
- **特性**: 页面加载时自动显示「各算法分组与安全强度」表格

#### 7.2 大数运算
- **功能**: 大整数加减乘除、模运算
- **实现方式**: 基于 BigInteger 的 BigNumberService
- **后端路径**: `backend/src/main/java/com/smtool/module/tool/BigNumberService.java`
- **前端路径**: `frontend/src/views/other/BigNumberView.vue`
- **API 端点**: `/api/bignumber/calculate`
- **支持运算**: 加、减、乘、除、模幂、模逆

#### 7.3 取模运算
- **功能**: 模运算专用工具
- **实现方式**: 基于 ModMathService
- **后端路径**: `backend/src/main/java/com/smtool/module/tool/ModMathService.java`
- **前端路径**: `frontend/src/views/other/ModView.vue`
- **API 端点**: `/api/modmath/calculate`

#### 7.4 逻辑运算
- **功能**: 位逻辑运算和移位操作
- **实现方式**: 基于 LogicService 的字节级运算
- **后端路径**: `backend/src/main/java/com/smtool/module/tool/LogicService.java`
- **前端路径**: `frontend/src/views/other/XORView.vue`
- **API 端点**: `/api/logic/operate`
- **支持运算**: 
  - 逻辑与 (AND)
  - 逻辑或 (OR)
  - 逻辑异或 (XOR)
  - 逻辑非 (NOT)
  - 循环左移
  - 循环右移
- **特性**: 数据 A 和 B 并排输入，支持十六进制/Base64 切换

#### 7.5 字节逆序
- **功能**: 字节序列逆序转换
- **实现方式**: 基于 ByteOrderService
- **后端路径**: `backend/src/main/java/com/smtool/module/tool/ByteOrderService.java`
- **前端路径**: `frontend/src/views/other/ByteReverseView.vue`
- **API 端点**: `/api/byteorder/reverse`
- **分组字节数**: 1（整体逆序）、2、4、8（用于大端/小端转换）

---

### 8. 独立工具

#### 8.1 编码转换
- **功能**: 多种编码格式互转
- **实现方式**: 基于 EncodeService
- **后端路径**: `backend/src/main/java/com/smtool/module/tool/EncodeService.java`
- **前端路径**: `frontend/src/views/encod/EncodingView.vue`
- **API 端点**: 
  - `/api/encode/convert` (编码转换)
  - `/api/encode/url` (URL 编解码)
  - `/api/encode/charset` (字符集转换)
  - `/api/encode/asn1` (ASN.1 解析)
- **支持编码**:
  - UTF-8、Hex、Base64、Base64URL、URL、Base58、Binary、Decimal、Bytes
  - 字符集：Big5、GBK、GB2312、GB18030、EUC-JP、EUC-KR、Shift_JIS、ISO 系列、UTF-16/32 等（约 170 种）

#### 8.2 UKey 包解析
- **功能**: 解析 UKey 通信数据包
- **实现方式**: 基于 UkeyParseService 的 APDU 解析
- **后端路径**: `backend/src/main/java/com/smtool/module/parse/UkeyParseService.java`
- **前端路径**: `frontend/src/views/parse/UkeyView.vue`
- **API 端点**: `/api/ukey/traffic/parse`
- **支持厂商**: 符合 0017 标准规范、山东渔翁、海泰方圆、上海华申、三未信安、飞天诚信、北京 CA、中金国信 (CFCA)

#### 8.3 随机数检测
- **功能**: 28 种随机性检测方法
- **实现方式**: 基于 RandomnessService 的统计检测
- **后端路径**: `backend/src/main/java/com/smtool/module/random/RandomnessService.java`
- **前端路径**: `frontend/src/views/random/RandomnessView.vue`
- **API 端点**: `/api/randomness/test`
- **输入格式**: 十六进制、Base64、字符串、文件上传
- **演示数据**: `frontend/public/randomness_demo_100000bits.hex` (100000 位)

#### 8.4 时间戳解析
- **功能**: 解析时间戳令牌（TST）
- **实现方式**: 基于 TimestampService
- **后端路径**: `backend/src/main/java/com/smtool/module/timestamp/TimestampService.java`
- **前端路径**: `frontend/src/views/timestamp/TimestampView.vue`
- **API 端点**: `/api/timestamp/parse`

#### 8.5 电子签章校验
- **功能**: 验证 PDF/OFD 文件中的电子签章
- **实现方式**: 
  - PDF: 基于 PDFBox 和 BouncyCastle 的 CMS 验证
  - OFD: 基于 OfdSealVerifier
- **后端路径**: 
  - `backend/src/main/java/com/smtool/module/signature/PdfSealVerifier.java`
  - `backend/src/main/java/com/smtool/module/signature/OfdSealVerifier.java`
- **前端路径**: `frontend/src/views/signature/SignatureView.vue`
- **API 端点**: `/api/seal/verify-file`
- **输出**: 签章人姓名、位置、原因、时间、验证状态、证书详情
- **限制**: 支持 ORD/PDF 文件，大小 ≤ 10MB

---

## 环境要求

### 必需环境
- **JDK**: 17 或更高版本
- **Maven**: 3.6 或更高版本
- **Node.js**: 16 或更高版本（推荐 18+）
- **npm**: 8 或更高版本（或使用 pnpm/yarn）

### 可选环境
- **IDE**: IntelliJ IDEA、VS Code、Eclipse
- **浏览器**: Chrome、Firefox、Edge（推荐最新版）

---

## 编译与运行

### Windows 环境

#### 1. 后端编译与运行

```bash
# 进入后端目录
cd backend

# 编译打包（跳过测试）
mvn clean package -DskipTests

# 或直接运行
mvn spring-boot:run

# 运行打包后的 jar
java -jar target/crypto-toolbox-backend-1.0.0.jar
```

后端启动后访问：http://localhost:8080

#### 2. 前端编译与运行

```bash
# 进入前端目录
cd frontend

# 安装依赖
npm install

# 开发模式运行（热更新）
npm run dev

# 生产环境构建
npm run build

# 预览构建结果
npm run preview
```

前端开发服务器：http://localhost:5173

#### 3. 完整启动流程

```bash
# 终端 1：启动后端
cd backend
mvn spring-boot:run

# 终端 2：启动前端
cd frontend
npm run dev
```

访问 http://localhost:5173 即可使用（前端会自动代理 API 请求到后端 8080 端口）

---

### Linux 环境

#### 1. 安装依赖

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-17-jdk maven nodejs npm

# CentOS/RHEL
sudo yum install java-17-openjdk-devel maven nodejs npm

# 或使用 SDKMAN 安装 JDK
curl -s "https://get.sdkman.io" | bash
sdk install java 17.0.9-tem
sdk install maven
```

#### 2. 后端编译与运行

```bash
cd backend

# 编译
mvn clean package -DskipTests

# 运行（前台）
java -jar target/crypto-toolbox-backend-1.0.0.jar

# 运行（后台）
nohup java -jar target/crypto-toolbox-backend-1.0.0.jar > backend.log 2>&1 &

# 停止后台进程
pkill -f crypto-toolbox-backend
```

#### 3. 前端编译与运行

```bash
cd frontend

# 安装依赖
npm install

# 开发模式
npm run dev

# 生产构建
npm run build

# 使用 nginx 部署生产环境
sudo cp -r dist/* /var/www/html/
```

#### 4. 使用 systemd 管理服务（可选）

创建 `/etc/systemd/system/crypto-backend.service`:

```ini
[Unit]
Description=Crypto Toolbox Backend
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/backend
ExecStart=/usr/bin/java -jar /path/to/backend/target/crypto-toolbox-backend-1.0.0.jar
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable crypto-backend
sudo systemctl start crypto-backend
sudo systemctl status crypto-backend
```

---

### 国产服务器环境（麒麟 V10、统信 UOS 等）

#### 1. 环境准备

**麒麟 V10 / 统信 UOS (ARM64 架构)**:

```bash
# 安装毕昇 JDK（华为开源，支持 ARM64）
# 下载地址：https://www.hikunpeng.com/developer/devkit/compiler/jdk

# 或使用毕昇 JDK 安装包
sudo rpm -ivh biSheng-jdk-17_linux-aarch64.rpm

# 配置环境变量
export JAVA_HOME=/usr/local/bisheng-jdk-17
export PATH=$JAVA_HOME/bin:$PATH

# 安装 Maven
sudo yum install maven

# 安装 Node.js（使用 NVM）
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 18
nvm use 18
```

**统信 UOS (x86_64 架构)**:

```bash
# 使用系统自带包管理器
sudo apt update
sudo apt install openjdk-17-jdk maven nodejs npm

# 或使用毕昇 JDK
sudo dpkg -i biSheng-jdk-17_linux-amd64.deb
```

#### 2. 编译与运行

编译和运行步骤与标准 Linux 环境完全一致，参考上文「Linux 环境」部分。

#### 3. 国产数据库适配（如需）

如使用达梦、人大金仓等国产数据库，需：

1. 在 `pom.xml` 中添加对应 JDBC 驱动依赖
2. 修改 `application.yml` 中的数据源配置
3. 调整 SQL 方言（如使用 MyBatis）

当前版本未使用数据库，如后续扩展可直接对接。

#### 4. 国产中间件适配（如需）

如使用东方通 TongWeb、金蝶 AAS 等中间件，需：

1. 将应用打包为 WAR 包（修改 `pom.xml` 的 `<packaging>war</packaging>`）
2. 按照中间件文档部署 WAR 包
3. 调整上下文路径和端口配置

---

## 常见问题与解决方案

### 1. JDK 版本问题

**问题**: `Unsupported class file major version 61`

**原因**: 使用了 JDK 11 或更低版本编译/运行

**解决**: 
```bash
# 检查 Java 版本
java -version

# 确保使用 JDK 17+
export JAVA_HOME=/path/to/jdk-17
export PATH=$JAVA_HOME/bin:$PATH
```

---

### 2. Maven 依赖下载慢

**问题**: Maven 下载依赖非常慢或超时

**解决**: 配置阿里云镜像

编辑 `~/.m2/settings.xml`:

```xml
<settings>
  <mirrors>
    <mirror>
      <id>aliyun</id>
      <name>Aliyun Maven</name>
      <url>https://maven.aliyun.com/repository/public</url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

---

### 3. 前端端口被占用

**问题**: `Port 5173 is already in use`

**解决**:

```bash
# 方法 1：修改 vite.config.js
server: {
  port: 5174  # 改为其他端口
}

# 方法 2：命令行指定端口
npm run dev -- --port 5174
```

---

### 4. 后端端口被占用

**问题**: `Port 8080 is already in use`

**解决**:

```bash
# 方法 1：修改 application.yml
server:
  port: 8081

# 方法 2：命令行指定端口
java -jar target/crypto-toolbox-backend-1.0.0.jar --server.port=8081

# 方法 3：查找并杀死占用进程
# Windows
netstat -ano | findstr :8080
taskkill /PID <进程ID> /F

# Linux
lsof -i :8080
kill -9 <进程ID>
```

---

### 5. 跨域问题

**问题**: 前端访问后端 API 报 CORS 错误

**解决**: 

已配置跨域支持，无需额外操作。如仍有问题：

1. 检查前端 `vite.config.js` 的代理配置
2. 检查后端 `WebConfig.java` 的 CORS 配置
3. 确保前端通过 `/api` 前缀访问（会自动代理到后端）

---

### 6. BouncyCastle 版本冲突

**问题**: `java.lang.NoSuchMethodError` 或 `ClassNotFoundException`

**原因**: 项目中多个依赖引入了不同版本的 BouncyCastle

**解决**:

```bash
# 查看依赖树
mvn dependency:tree | grep bouncycastle

# 在 pom.xml 中强制指定版本
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78.1</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

---

### 7. 前端构建失败

**问题**: `npm install` 或 `npm run build` 失败

**解决**:

```bash
# 清除缓存
npm cache clean --force

# 删除 node_modules 和 lock 文件
rm -rf node_modules package-lock.json

# 重新安装
npm install

# 使用淘宝镜像
npm config set registry https://registry.npmmirror.com
npm install
```

---

### 8. SM9 算法性能问题

**问题**: SM9 运算非常慢

**原因**: SM9 核心使用纯 Java BigInteger 实现（无双线性对库）

**解决**:
- 这是设计决策，确保无外部依赖
- 生产环境建议开启 JIT 编译优化
- 如需高性能，可考虑替换为 C/C++ JNI 实现

---

### 9. 证书解析失败

**问题**: 证书格式检查或 ASN.1 解析报错

**可能原因**:
1. 证书格式不正确（非 PEM/DER）
2. 证书已损坏
3. 不支持的证书类型

**解决**:
```bash
# 使用 OpenSSL 验证证书
openssl x509 -in cert.pem -text -noout

# 转换为标准格式
openssl x509 -in cert.cer -out cert.pem
```

---

### 10. 内存不足

**问题**: `java.lang.OutOfMemoryError`

**解决**:

```bash
# 增加 JVM 堆内存
java -Xmx2g -Xms512m -jar target/crypto-toolbox-backend-1.0.0.jar
```

---

### 11. 国产操作系统特有问题

**问题**: 麒麟 V10 / 统信 UOS 上运行异常

**排查**:

```bash
# 检查系统架构
uname -m

# 检查 JDK 架构
java -version

# 确保 JDK 和系统架构一致（x86_64 或 aarch64）

# 检查依赖库
ldd /path/to/jdk/lib/libjava.so
```

**常见问题**:
- ARM64 架构使用了 x86 的 JDK → 安装对应架构的 JDK
- 缺少系统库 → 使用 `yum install` 或 `apt install` 安装
- 权限问题 → 使用 `sudo` 或调整文件权限

---

### 12. 前端页面白屏

**问题**: 访问前端页面显示空白

**排查**:
1. 打开浏览器开发者工具（F12）查看控制台错误
2. 检查后端是否正常启动
3. 检查 API 请求是否成功

**解决**:
```bash
# 重新构建前端
cd frontend
rm -rf dist
npm run build

# 检查路由配置
# 确保所有路由对应的 Vue 文件存在
```

---

## 项目结构

```
商密检测工具箱/
├── backend/                          # 后端项目
│   ├── src/main/java/com/smtool/
│   │   ├── CryptoToolboxApplication.java    # 主启动类
│   │   ├── common/                          # 通用类
│   │   │   ├── ApiResponse.java
│   │   │   └── GlobalExceptionHandler.java
│   │   ├── config/                          # 配置类
│   │   │   ├── BouncyCastleConfig.java
│   │   │   └── WebConfig.java
│   │   ├── module/                          # 业务模块
│   │   │   ├── asymmetric/                  # 非对称算法
│   │   │   ├── cert/                        # 证书相关
│   │   │   ├── hash/                        # 哈希算法
│   │   │   ├── operation/                   # 运算工具
│   │   │   ├── other/                       # 其他工具
│   │   │   ├── parse/                       # 协议解析
│   │   │   ├── random/                      # 随机数
│   │   │   ├── signature/                   # 电子签章
│   │   │   ├── sm2/                         # SM2 算法
│   │   │   ├── sm9/                         # SM9 算法
│   │   │   ├── symmetric/                   # 对称算法
│   │   │   ├── timestamp/                   # 时间戳
│   │   │   └── tool/                        # 通用工具
│   │   └── util/                            # 工具类
│   ├── src/main/resources/
│   │   └── application.yml                  # 配置文件
│   └── pom.xml                              # Maven 配置
│
└── frontend/                         # 前端项目
    ├── src/
    │   ├── main.js                          # 入口文件
    │   ├── router.js                        # 路由配置
    │   ├── menus.js                         # 菜单配置
    │   ├── api.js                           # API 封装
    │   ├── views/                           # 页面组件
    │   │   ├── asymmetric/                  # 非对称算法页面
    │   │   ├── cert/                        # 证书页面
    │   │   ├── encod/                       # 编码转换页面
    │   │   ├── hash/                        # 哈希页面
    │   │   ├── operation/                   # 运算页面
    │   │   ├── other/                       # 其他页面
    │   │   ├── parse/                       # 解析页面
    │   │   ├── random/                      # 随机数页面
    │   │   ├── signature/                   # 签章页面
    │   │   ├── symmetric/                   # 对称页面
    │   │   └── timestamp/                   # 时间戳页面
    │   └── components/                      # 公共组件
    ├── public/                              # 静态资源
    ├── package.json                         # npm 配置
    └── vite.config.js                       # Vite 配置
```

---

## 开发指南

### 添加新功能

1. **后端**:
   - 在 `backend/src/main/java/com/smtool/module/` 下创建新模块
   - 实现 Controller、Service、Request 类
   - 添加 `@RestController` 和 `@RequestMapping` 注解

2. **前端**:
   - 在 `frontend/src/views/` 下创建 Vue 组件
   - 在 `frontend/src/menus.js` 中添加菜单项
   - 路由会自动生成（基于 `router.js` 的自动收集）

### API 规范

- 所有 API 以 `/api` 开头
- 使用 RESTful 风格
- 统一返回格式：`ApiResponse<T>`
- 错误统一由 `GlobalExceptionHandler` 处理

---

## 许可证

本项目仅供学习和研究使用。

---

## 联系方式

如有问题或建议，欢迎反馈。

---

## 更新日志

### v1.0.0 (2026-07-05)
- 完成所有核心功能开发
- 支持 8 大类 38 个功能点
- 完整的文档和使用说明
