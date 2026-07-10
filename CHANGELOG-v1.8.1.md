# v1.8.1 变更日志

**发布日期**：2026-07-10  
**标签**：`v1.8.1`  
**上一个版本**：`v1.5.2`

本版本主要围绕 **IPsec / TLS / 国密证书解析** 的能力补齐、**国密算法（SM2/SM9/TLCP）** 的合规性修复，以及 **前端交互细节** 的持续打磨。所有后端核心模块均补充了对应的单元测试。

---

## 一、新增功能

### 1. IPsec 流量包解析能力大幅增强

- **多链路层类型支持**：扩展 `PacketOffsetUtil`，新增对以下 link type 的解析：
  - `LINKTYPE_LINUX_SLL (113)`
  - `LINKTYPE_NULL (0)`
  - `LINKTYPE_PPP (9)`
  - `LINKTYPE_IEEE802_11 (105)`
- **数据平面协议解析**：新增 ESP / AH 协议（协议号 50 / 51）的数据平面 SA 解析与展示。
- **pcapng 时间戳修正**：EPB 时间戳改为从 `timestampHi / timestampLo` 计算，避免时间偏差。
- **TCP 流重组加固**：重组时过滤 SYN / RST 报文段，防止 payload 被污染。
- **IP 分片重组**：新增 `IpFragmentReassembler`，对跨 IP 分片的 IKE / 证书载荷进行重组后再解析。
- **IKE NAT-T Marker 检测**：按 `>= 4 字节` 规则识别 Marker-only 报文。

### 2. IKE 证书链提取与导出

- 新增 `IsakmpCertificateExtractor`，按 RFC 2408 解析 ISAKMP Certificate Payload：
  - 支持 `next_payload = 6` 的证书载荷链表遍历；
  - 支持 Cert Encoding = `4 (X.509 Signature)`、`5 (X.509 KeyExchange)`、`7 (PKCS#7)`；
  - 支持国密私有载荷直接以 `0x30` 开头的 Raw DER 格式。
- 新增国密/SM2 证书解析：
  - 自定义 OID 映射：`1.2.156.10197.1.501 (SM2-with-SM3)`、`1.2.156.10197.1.301 (SM2 curve)`；
  - 使用 `asn1crypto` 处理 UTF8String 中文字段；
  - 解析版本、序列号、颁发者、使用者、有效期、签名算法、密钥用法（KeyUsage 标志位）等标准字段；
  - 解析失败时保留原始 DER Base64，支持前端导出 `.pem` / `.der`。
- IKE 解密密钥日志导入：新增 `IpsecKeyLogParser`，支持格式：
  ```
  IKEv1 <initiator_spi> <responder_spi> <skeyid_e> [<skeyid_a>] [<iv>]
  ```
  用于解密已加密 IKE 消息并提取证书链。
- 证书展示：仅渲染实际解析出的证书，不再显示空占位；支持客户端/服务端证书链分别展示与批量导出。

### 3. TLS 流量包解析加固

- **Handshake 跨记录重组**：对跨越多个 TLS Record 的 Handshake 消息进行正确重组。
- **Handshake body 边界保护**：按 `hsLength` 解析，避免跨记录边界错误。
- **未知密码套件显示**：识别不出的密码套件直接输出十六进制值，不再留空。
- **证书链校验**：新增 BasicConstraints CA 标志与 `pathLenConstraint` 检查。
- **前端 Base64 兼容**：证书导出时清理空白字符，避免 `atob` 报错。

### 4. 国密算法与证书模块增强

- **SM2**：
  - 输入校验：SM2 密钥操作增加 null / empty 校验，防止 NPE；
  - 用户 ID 使用 GM/T 0003 固定字节序列，不再使用平台默认字符集。
- **SM9**：签名/验签流程遵循 GM/T 0044 标准，保证互操作性。
- **TLCP**：KeyBlock 长度按 SM3/SM4 参数动态计算，去除硬编码。
- **X.509 / CRL**：
  - CRL 吊销条目不再截断，全部处理并展示；
  - 证书有效期精确到日期时间，不再使用 30 天/月近似；
  - ASN.1 解析支持 BIT STRING 内嵌证书等所有 DER 类型；
  - 国密 X.509 兼容 SM2 特定 OID 映射与 UTF8String 中文。

### 5. 辅助脚本

- 新增 `scripts/extract_ipsec_certs.py`：基于 tshark + asn1crypto 批量从 pcap / ISAKMP 报文中提取并解析证书。

---

## 二、问题修复

| 问题 | 修复方式 |
|------|----------|
| IPsec 无法解析 Linux cooked-capture 抓包 | 新增 `LINKTYPE_LINUX_SLL` 等链路层偏移计算 |
| IPsec 只解析控制面、缺少 ESP/SA | 新增 ESP/AH 数据平面解析与 SA 统计 |
| pcapng 时间戳不准 | EPB 时间戳改用 `timestampHi/timestampLo` 组合计算 |
| TCP 重组 payload 被 SYN/RST 污染 | 重组前过滤 SYN/RST 报文段 |
| 证书链数量统计缺失 | `IpsecSessionMapper` 修正证书计数逻辑 |
| 加密 IKE 会话被空返回给前端 | `IpsecTrafficParseService` 过滤全加密会话 |
| IKEv1 版本显示为 `IKEv1` | 统一显示为 `ISAKMP 1.1` |
| ISAKMP 证书载荷长度解析错误 | 严格按 Payload Length 计算 DER 数据长度 |
| 国密证书 SM2 曲线 OID 报错 | 自定义 OID 映射 + asn1crypto 兼容处理 |
| 证书中文乱码 | 使用支持 UTF8String 的 ASN.1/X.509 库 |
| TLS 多记录 Handshake 解析错误 | 增加 Handshake 消息重组与长度边界检查 |
| 未知 TLS 密码套件显示为空 | 回退显示十六进制值 |
| 前端证书导出 Base64 含空格失败 | 导出前清理空白字符 |
| SM2 密钥空值导致 NPE | 增加 null/empty 输入校验 |
| SM9 签名不兼容外部工具 | 遵循 GM/T 0044 |
| TLCP KeyBlock 硬编码 | 按 SM3/SM4 参数动态计算 |
| CRL 条目被截断 | 全部遍历处理 |
| 证书有效期近似 | 精确解析 NotBefore / NotAfter |

---

## 三、前端交互优化

- **IPsec 解析结果展示重构**（`IpsecView.vue`）：
  - 展开行精简为 10 项核心信息；
  - SPI、Nonce、SK、 identities、签名等详情移入“查看完整详情”弹窗；
  - 证书链支持导出。
- **HMAC / MAC 密钥长度显示**：
  - `HashView.vue`、`MacView.vue` 中密钥输入框右侧数字由“字节数”改为“字符数”，与十六进制字符串长度一致。
- **盐值位置按钮布局**：
  - `HashView.vue` 中“前置 / 后置”按钮由垂直堆叠改为水平并列。
- **证书动态渲染**：所有证书展示页仅显示实际解析出的证书，不再预留空占位。

---

## 四、测试覆盖

新增/更新大量单元测试，覆盖以下场景：

- `PacketOffsetUtilTest`：多种 link type 偏移计算；
- `PacketParserTest` / `TlsParseServiceTest` / `TlsSessionAnalyzerTest`：TLS Handshake 重组、未知套件、证书提取；
- `IsakmpCertificateExtractorTest`：Raw DER、国密私有载荷、链表遍历；
- `IpsecTrafficParseServiceTest` / `IpsecKeyLogParserTest`：IPsec 会话解析、密钥日志导入、加密会话过滤；
- `IpsecTrafficParseDebug` 及多个调试 Dump 类：用于现场抓包验证与问题定位。

---

## 五、主要变更文件

### 修改文件

```
backend/src/main/java/com/smtool/module/cert/Asn1ParseService.java
backend/src/main/java/com/smtool/module/cert/CertCheckService.java
backend/src/main/java/com/smtool/module/cert/CertIssueRequest.java
backend/src/main/java/com/smtool/module/cert/CertIssueService.java
backend/src/main/java/com/smtool/module/cert/CrlCheckService.java
backend/src/main/java/com/smtool/module/cert/CsrRequest.java
backend/src/main/java/com/smtool/module/cert/OidNames.java
backend/src/main/java/com/smtool/module/operation/Pbkdf2Service.java
backend/src/main/java/com/smtool/module/operation/PrfService.java
backend/src/main/java/com/smtool/module/operation/SigAttackService.java
backend/src/main/java/com/smtool/module/operation/Sm2kService.java
backend/src/main/java/com/smtool/module/operation/TlsKeyService.java
backend/src/main/java/com/smtool/module/parse/IpsecParseController.java
backend/src/main/java/com/smtool/module/parse/IpsecParseService.java
backend/src/main/java/com/smtool/module/parse/IpsecSession.java
backend/src/main/java/com/smtool/module/parse/IpsecSessionAnalyzer.java
backend/src/main/java/com/smtool/module/parse/IpsecSessionDto.java
backend/src/main/java/com/smtool/module/parse/IpsecSessionMapper.java
backend/src/main/java/com/smtool/module/parse/IpsecTrafficParseService.java
backend/src/main/java/com/smtool/module/parse/PacketParser.java
backend/src/main/java/com/smtool/module/parse/PcapPacket.java
backend/src/main/java/com/smtool/module/parse/PcapngReader.java
backend/src/main/java/com/smtool/module/parse/SshParseService.java
backend/src/main/java/com/smtool/module/parse/SshStreamParser.java
backend/src/main/java/com/smtool/module/parse/TcpReassemblyService.java
backend/src/main/java/com/smtool/module/parse/TcpStream.java
backend/src/main/java/com/smtool/module/parse/TlsCertificateExtractor.java
backend/src/main/java/com/smtool/module/parse/TlsParseService.java
backend/src/main/java/com/smtool/module/parse/TlsSession.java
backend/src/main/java/com/smtool/module/parse/TlsSessionAnalyzer.java
backend/src/main/java/com/smtool/module/parse/TlsSessionMapper.java
backend/src/main/java/com/smtool/module/parse/TlsStreamParser.java
backend/src/main/java/com/smtool/module/parse/UkeyParseService.java
backend/src/main/java/com/smtool/module/parse/UkeyTrafficParseService.java
backend/src/main/java/com/smtool/module/sm2/SM2Service.java
backend/src/main/java/com/smtool/module/sm9/SM9Controller.java
backend/src/main/java/com/smtool/module/sm9/SM9Service.java
backend/src/main/java/com/smtool/util/CodecUtil.java
backend/src/main/resources/application.yml
backend/src/test/java/com/smtool/module/parse/IpsecTrafficParseDebug.java
frontend/src/views/asymmetric/SM2View.vue
frontend/src/views/asymmetric/SM9View.vue
frontend/src/views/hash/HashView.vue
frontend/src/views/hash/MacView.vue
frontend/src/views/parse/IpsecView.vue
frontend/src/views/parse/TlsView.vue
frontend/src/views/parse/UkeyView.vue
```

### 新增文件

```
backend/src/main/java/com/smtool/module/parse/IpFragmentReassembler.java
backend/src/main/java/com/smtool/module/parse/IpsecCertificateInfo.java
backend/src/main/java/com/smtool/module/parse/IpsecCertificateInfoDto.java
backend/src/main/java/com/smtool/module/parse/IpsecDataPlaneSa.java
backend/src/main/java/com/smtool/module/parse/IpsecDataPlaneSaDto.java
backend/src/main/java/com/smtool/module/parse/IpsecIkeDecryptor.java
backend/src/main/java/com/smtool/module/parse/IpsecKeyLogEntry.java
backend/src/main/java/com/smtool/module/parse/IpsecKeyLogParser.java
backend/src/main/java/com/smtool/module/parse/IsakmpCertificateExtractor.java
backend/src/main/java/com/smtool/module/parse/PacketOffsetUtil.java
backend/src/main/java/com/smtool/module/parse/TlsCipherSuites.java
backend/src/test/java/com/smtool/module/parse/IpsecAllSessionsDump.java
backend/src/test/java/com/smtool/module/parse/IpsecCertInspect.java
backend/src/test/java/com/smtool/module/parse/IpsecCertPayloadsDump.java
backend/src/test/java/com/smtool/module/parse/IpsecDeepCertScan.java
backend/src/test/java/com/smtool/module/parse/IpsecExchangeSummaryDump.java
backend/src/test/java/com/smtool/module/parse/IpsecFirstPacketsDump.java
backend/src/test/java/com/smtool/module/parse/IpsecFragmentScan.java
backend/src/test/java/com/smtool/module/parse/IpsecKeyLogParserTest.java
backend/src/test/java/com/smtool/module/parse/IpsecMainModeDump.java
backend/src/test/java/com/smtool/module/parse/IpsecPcapProbe.java
backend/src/test/java/com/smtool/module/parse/IpsecReassembleCertDump.java
backend/src/test/java/com/smtool/module/parse/IpsecTargetCheck.java
backend/src/test/java/com/smtool/module/parse/IpsecTrafficParseServiceTest.java
backend/src/test/java/com/smtool/module/parse/IpsecUnencryptedDump.java
backend/src/test/java/com/smtool/module/parse/IsakmpCertificateExtractorTest.java
backend/src/test/java/com/smtool/module/parse/PacketOffsetUtilTest.java
backend/src/test/java/com/smtool/module/parse/PacketParserTest.java
backend/src/test/java/com/smtool/module/parse/TlsCertificateExtractorTest.java
backend/src/test/java/com/smtool/module/parse/TlsParseServiceTest.java
backend/src/test/java/com/smtool/module/parse/TlsSessionAnalyzerTest.java
frontend/public/inject_pcap.js
scripts/extract_ipsec_certs.py
CHANGELOG-v1.8.1.md
```

---

## 六、未纳入版本控制的辅助/调试文件

以下文件仅用于本地调试、抓包验证或旧版本归档，**不会**随 v1.8.1 发布提交：

```
backend/debug-out.txt
backend/ipsec-debug-output.txt
bastion_parse_result.json
bastion_parse_result_with_notes.json
fetch_ipsec_response.py
inspect_response.py
ipsec_parse_response.json
ipsec_response.json
login_parse_result.json
login_parse_result_final.json
parse_cert_tmp.py
releasev1.6/
releasev1.6.1/
releasev1.6.2/
releasev1.6.3/
test/SM2-test.zip
test/SM2-test/
test/sm2_cert.pem
test/sm2_crl.pem
test/sm2_private.pem
test/商用密码检测工具箱功能清单.md
test/时间戳.txt
test/随机数.txt
商用密码检测工具箱_用户手册.docx
商用密码检测工具箱_用户手册_含使用指南.docx
```

---

## 七、验证情况

- 后端 `mvn compile` 通过；
- 前端 `npm run build` 通过；
- IPsec / TLS / 分组解析相关单元测试全部通过；
- 使用用户提供的 `ipsec.pcap` 验证：成功解析 IKEv1 Main Mode 证书链、ESP SA 数据平面，证书字段与导出功能正常。
