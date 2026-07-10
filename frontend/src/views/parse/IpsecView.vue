<template>
  <el-card>
    <div class="page-title">IPSec 流量包解析工作区</div>
    <el-form label-position="top">
      <el-row :gutter="20">
        <el-col :span="12">
          <el-form-item label="流量包文件">
            <el-upload
              drag
              action="#"
              :auto-upload="false"
              :on-change="handleFileChange"
              :show-file-list="false"
              style="width: 100%"
            >
              <el-icon class="el-icon--upload"><Upload /></el-icon>
              <div class="el-upload__text">点击或拖拽文件到此区域上传</div>
            </el-upload>
            <div v-if="form.fileName" class="file-name">{{ form.fileName }}</div>
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="IPSec / IKE 报文">
            <el-input
              v-model="form.input"
              type="textarea"
              :rows="4"
              placeholder="IKE / ISAKMP 十六进制报文（hex）"
            />
          </el-form-item>
        </el-col>
      </el-row>

      <el-row :gutter="20">
        <el-col :span="12">
          <el-form-item label="源 IP">
            <el-input v-model="form.srcIp" placeholder="0.0.0.0" />
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="目标 IP">
            <el-input v-model="form.dstIp" placeholder="0.0.0.0" />
          </el-form-item>
        </el-col>
      </el-row>

      <el-form-item>
        <div class="btn-row">
          <el-button type="primary" :loading="loadingTraffic" @click="runTraffic">解析流量包</el-button>
          <el-button type="primary" :loading="loadingMessage" @click="runMessage">解析 IPSec 报文</el-button>
          <el-button @click="clear">清空</el-button>
        </div>
      </el-form-item>
    </el-form>

    <div v-if="messageResult" class="result-section">
      <div class="section-title">IPSec 报文解析结果</div>
      <JsonView :data="cnMessageResult" />
    </div>

    <div v-if="trafficResult" class="result-section">
      <div class="section-title">流量包解析结果</div>
      <div class="summary">
        共解析出 {{ trafficResult.sessionCount }} 组会话数据，解析时间：{{ formatTime(parseTimeDate) }}
      </div>

      <el-table
        :data="trafficResult.sessions"
        border
        style="width: 100%"
        row-key="id"
      >
        <el-table-column type="expand" width="40">
          <template #default="{ row }">
            <div class="detail-panel">
              <el-descriptions :column="2" border>
                <el-descriptions-item label="协议版本" :span="2">
                  <div class="version-line">
                    <span>{{ row.protocolVersion || '-' }}</span>
                    <el-tag v-if="row.label" size="small" type="info">{{ row.label }}</el-tag>
                    <el-tag v-if="row.gm" size="small" type="danger">国密</el-tag>
                  </div>
                </el-descriptions-item>
                <el-descriptions-item label="加密算法">
                  {{ formatEncryption(row) }}
                </el-descriptions-item>
                <el-descriptions-item label="MAC算法">
                  {{ row.selectedIntegrity || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="认证算法">
                  {{ row.selectedAuthMethod || row.authMethod || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="非对称算法">
                  {{ row.selectedDhGroup || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="密钥更新周期" :span="2">
                  {{ formatLifetime(row.keyLifetimeSeconds) }}
                </el-descriptions-item>
              </el-descriptions>

              <div v-if="parsedCertSlots(row).length" class="cert-grid-section">
                <div class="cert-grid-title">证书链</div>
                <el-row :gutter="16">
                  <el-col
                    v-for="slot in parsedCertSlots(row)"
                    :key="slot.label"
                    :xs="24"
                    :sm="12"
                  >
                    <div class="cert-card">
                      <div class="cert-card-header">
                        <span class="cert-card-label">{{ slot.label }}</span>
                        <el-button type="primary" link size="small" @click="exportCertificate(slot.cert, slot.label)">导出证书</el-button>
                      </div>
                      <div class="cert-card-body">
                        <div class="cert-field">
                          <span class="cert-field-label">证书版本</span>
                          <span class="cert-field-value">{{ slot.cert.version || '-' }}</span>
                        </div>
                        <div class="cert-field">
                          <span class="cert-field-label">序列号</span>
                          <span class="cert-field-value">{{ slot.cert.serialNumber || '-' }}</span>
                        </div>
                        <div class="cert-field">
                          <span class="cert-field-label">使用者</span>
                          <span class="cert-field-value">{{ slot.cert.subject || '-' }}</span>
                        </div>
                        <div class="cert-field">
                          <span class="cert-field-label">颁发者</span>
                          <span class="cert-field-value">{{ slot.cert.issuer || '-' }}</span>
                        </div>
                        <div class="cert-field">
                          <span class="cert-field-label">有效期</span>
                          <span class="cert-field-value">{{ certLifetime(slot.cert) }}</span>
                        </div>
                        <div class="cert-field">
                          <span class="cert-field-label">签名算法</span>
                          <span class="cert-field-value">{{ slot.cert.signatureAlgorithm || '-' }}</span>
                        </div>
                        <div class="cert-field">
                          <span class="cert-field-label">密钥用法</span>
                          <span class="cert-field-value">{{ slot.cert.keyUsage || '-' }}</span>
                        </div>
                      </div>
                    </div>
                  </el-col>
                </el-row>
              </div>

              <div class="detail-actions">
                <el-button type="primary" size="small" @click="openFullDetail(row)">查看完整详情</el-button>
              </div>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="协议版本" prop="protocolVersion" min-width="260" show-overflow-tooltip>
          <template #default="{ row }">
            {{ row.protocolVersion || '-' }}
          </template>
        </el-table-column>
        <el-table-column label="发起方 IP" prop="srcIp" min-width="140" />
        <el-table-column label="发起方端口" prop="srcPort" width="110" />
        <el-table-column label="接收端 IP" prop="dstIp" min-width="140" />
        <el-table-column label="接收端端口" prop="dstPort" width="110" />
      </el-table>
    </div>

    <el-dialog
      v-model="detailVisible"
      title="完整详情"
      width="80%"
      top="5vh"
      :close-on-click-modal="false"
    >
      <div v-if="currentDetail" class="full-detail-dialog">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="协议版本" :span="2">
            <div class="version-line">
              <span>{{ currentDetail.protocolVersion || '-' }}</span>
              <el-tag v-if="currentDetail.label" size="small" type="info">{{ currentDetail.label }}</el-tag>
              <el-tag v-if="currentDetail.gm" size="small" type="danger">国密</el-tag>
            </div>
          </el-descriptions-item>
          <el-descriptions-item label="加密算法">
            {{ formatEncryption(currentDetail) }}
          </el-descriptions-item>
          <el-descriptions-item label="MAC 算法">
            {{ currentDetail.selectedIntegrity || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="认证算法">
            {{ currentDetail.selectedAuthMethod || currentDetail.authMethod || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="非对称算法">
            {{ currentDetail.selectedDhGroup || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="密钥更新周期" :span="2">
            {{ formatLifetime(currentDetail.keyLifetimeSeconds) }}
          </el-descriptions-item>
          <el-descriptions-item label="发起方 SPI">
            {{ currentDetail.initiatorSpi || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="响应方 SPI">
            {{ currentDetail.responderSpi || '-' }}
          </el-descriptions-item>
        </el-descriptions>

        <div v-if="parsedCertSlots(currentDetail).length" class="cert-grid-section">
          <div class="cert-grid-title">证书链</div>
          <el-row :gutter="16">
            <el-col
              v-for="slot in parsedCertSlots(currentDetail)"
              :key="slot.label"
              :xs="24"
              :sm="12"
            >
              <div class="cert-card">
                <div class="cert-card-header">
                  <span class="cert-card-label">{{ slot.label }}</span>
                  <el-button type="primary" link size="small" @click="exportCertificate(slot.cert, slot.label)">导出证书</el-button>
                </div>
                <div class="cert-card-body">
                  <div class="cert-field">
                    <span class="cert-field-label">证书版本</span>
                    <span class="cert-field-value">{{ slot.cert.version || '-' }}</span>
                  </div>
                  <div class="cert-field">
                    <span class="cert-field-label">序列号</span>
                    <span class="cert-field-value">{{ slot.cert.serialNumber || '-' }}</span>
                  </div>
                  <div class="cert-field">
                    <span class="cert-field-label">使用者</span>
                    <span class="cert-field-value">{{ slot.cert.subject || '-' }}</span>
                  </div>
                  <div class="cert-field">
                    <span class="cert-field-label">颁发者</span>
                    <span class="cert-field-value">{{ slot.cert.issuer || '-' }}</span>
                  </div>
                  <div class="cert-field">
                    <span class="cert-field-label">有效期</span>
                    <span class="cert-field-value">{{ certLifetime(slot.cert) }}</span>
                  </div>
                  <div class="cert-field">
                    <span class="cert-field-label">签名算法</span>
                    <span class="cert-field-value">{{ slot.cert.signatureAlgorithm || '-' }}</span>
                  </div>
                  <div class="cert-field">
                    <span class="cert-field-label">密钥用法</span>
                    <span class="cert-field-value">{{ slot.cert.keyUsage || '-' }}</span>
                  </div>
                </div>
              </div>
            </el-col>
          </el-row>
        </div>

        <el-descriptions :column="2" border>
          <el-descriptions-item label="客户端 Nonce" :span="2">
            <div v-if="currentDetail.initiatorNonce" class="hex-preview">{{ formatHexPreview(currentDetail.initiatorNonce) }}</div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item label="服务端 Nonce" :span="2">
            <div v-if="currentDetail.responderNonce" class="hex-preview">{{ formatHexPreview(currentDetail.responderNonce) }}</div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item label="客户端 SK" :span="2">
            <div v-if="currentDetail.initiatorKeData" class="hex-preview">{{ formatHexPreview(currentDetail.initiatorKeData) }}</div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item label="服务端 SK" :span="2">
            <div v-if="currentDetail.responderKeData" class="hex-preview">{{ formatHexPreview(currentDetail.responderKeData) }}</div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item label="客户端身份" :span="2">
            {{ currentDetail.initiatorIdentity || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="服务端身份" :span="2">
            {{ currentDetail.responderIdentity || '-' }}
          </el-descriptions-item>
          <el-descriptions-item label="客户端签名" :span="2">
            <div v-if="currentDetail.initiatorSignature" class="hex-preview">{{ formatHexPreview(currentDetail.initiatorSignature) }}</div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item label="服务端签名" :span="2">
            <div v-if="currentDetail.responderSignature" class="hex-preview">{{ formatHexPreview(currentDetail.responderSignature) }}</div>
            <span v-else>-</span>
          </el-descriptions-item>
        </el-descriptions>

        <div v-if="currentDetail.hasDataPlane && currentDetail.dataPlaneSas && currentDetail.dataPlaneSas.length" class="detail-block">
          <div class="block-title">ESP/AH 数据面 SA</div>
          <el-table :data="currentDetail.dataPlaneSas" border size="small">
            <el-table-column label="协议" prop="protocol" width="80" />
            <el-table-column label="SPI" prop="spiHex" min-width="120" />
            <el-table-column label="源 IP" prop="srcIp" min-width="140" />
            <el-table-column label="目标 IP" prop="dstIp" min-width="140" />
            <el-table-column label="包数" prop="packetCount" width="100" />
            <el-table-column label="字节数" prop="byteCount" width="120" />
            <el-table-column label="序列号范围" min-width="160">
              <template #default="{ row: sa }">{{ sa.firstSeq }} - {{ sa.lastSeq }}</template>
            </el-table-column>
          </el-table>
        </div>

        <div class="detail-block">
          <div class="block-title">完整原始数据</div>
          <JsonView :data="toChinese(currentDetail)" />
        </div>
      </div>
      <template #footer>
        <el-button @click="detailVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { Upload } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'
import JsonView from '../../components/JsonView.vue'

const CN_MAP = {
  srcIp: '源 IP',
  dstIp: '目标 IP',
  totalBytes: '总字节数',
  truncated: '数据截断',
  header: 'ISAKMP 头部',
  payloads: 'Payload 链',
  initiatorSpi: '发起方 SPI',
  responderSpi: '响应方 SPI',
  version: '版本',
  exchangeType: '交换类型',
  flags: '标志',
  messageId: '消息 ID',
  length: '长度',
  nextPayload: '下一个 Payload',
  payloadType: 'Payload 类型',
  payloadTypeCode: 'Payload 类型码',
  critical: '关键位',
  payloadLength: 'Payload 长度',
  data: '数据',
  direction: '方向',
  sessionCount: '会话数',
  parseTimeMs: '解析耗时(ms)',
  sessions: '会话列表',
  protocolVersion: '协议版本',
  label: '标签',
  gm: '国密',
  selectedEncryption: '协商加密算法',
  selectedEncryptionKeyLength: '协商加密密钥长度',
  selectedIntegrity: '协商完整性算法',
  selectedPrf: '协商 PRF',
  selectedDhGroup: '协商 DH 组',
  selectedAuthMethod: '协商认证方式',
  keyLifetimeSeconds: '密钥更新周期（秒）',
  initiatorIdentity: '发起方身份',
  responderIdentity: '响应方身份',
  authMethod: '认证方式',
  certificateCount: '证书数量',
  vendorIds: 'Vendor ID',
  notifyTypes: 'Notify 类型',
  deleteTypes: 'Delete 类型',
  initiatorAlgorithms: '发起方算法提案',
  responderAlgorithms: '响应方算法提案',
  encryption: '加密',
  integrity: '完整性',
  prf: 'PRF',
  dhGroup: 'DH 组',
  notes: '备注',
  messages: '消息列表',
  hasDataPlane: '数据面流量',
  dataPlaneSas: 'ESP/AH 数据面 SA',
  protocol: '协议',
  spi: 'SPI',
  spiHex: 'SPI',
  packetCount: '包数',
  byteCount: '字节数',
  firstSeq: '首个序列号',
  lastSeq: '最后序列号',
  sampleSequenceNumbers: '序列号样例',
  initiatorCertificates: '发起方证书链',
  responderCertificates: '响应方证书链',
  initiatorNonce: '发起方 Nonce',
  responderNonce: '响应方 Nonce',
  initiatorKeData: '发起方 KE 数据',
  responderKeData: '响应方 KE 数据',
  initiatorSignature: '发起方签名',
  responderSignature: '响应方签名',
  index: '序号',
  version: '版本',
  serialNumber: '序列号',
  subject: '使用者',
  issuer: '颁发者',
  notBefore: '生效时间',
  notAfter: '过期时间',
  signatureAlgorithm: '签名算法',
  publicKeyAlgorithm: '公钥算法',
  keyUsage: '密钥用法',
  derBase64: 'DER Base64'
}

const form = reactive({
  file: null,
  fileName: '',
  input: '',
  format: 'hex',
  srcIp: '',
  dstIp: ''
})
const trafficResult = ref(null)
const messageResult = ref(null)
const loadingTraffic = ref(false)
const loadingMessage = ref(false)
const parseTimeDate = ref(null)
const detailVisible = ref(false)
const currentDetail = ref(null)

const cnMessageResult = computed(() => messageResult.value ? toChinese(messageResult.value) : null)

function toChinese(data) {
  if (Array.isArray(data)) return data.map(toChinese)
  if (data && typeof data === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(data)) {
      out[CN_MAP[k] || k] = toChinese(v)
    }
    return out
  }
  return data
}

function handleFileChange(file) {
  form.file = file.raw
  form.fileName = file.name
}

async function runTraffic() {
  if (!form.file) {
    ElMessage.warning('请先上传流量包文件')
    return
  }
  loadingTraffic.value = true
  try {
    const fd = new FormData()
    fd.append('file', form.file)
    const res = await api.post('/ipsec/traffic/parse', fd)
    trafficResult.value = res
    parseTimeDate.value = new Date()
    messageResult.value = null
  } catch (e) {
    ElMessage.error('解析失败：' + (e.response?.data?.message || e.message))
  } finally {
    loadingTraffic.value = false
  }
}

async function runMessage() {
  if (!form.input.trim()) {
    ElMessage.warning('请先输入 IPSec / IKE 报文')
    return
  }
  loadingMessage.value = true
  try {
    const res = await api.post('/ipsec/parse', { ...form })
    messageResult.value = res
  } catch (e) {
    ElMessage.error('解析失败：' + (e.response?.data?.message || e.message))
  } finally {
    loadingMessage.value = false
  }
}

function clear() {
  form.file = null
  form.fileName = ''
  form.input = ''
  form.format = 'hex'
  form.srcIp = ''
  form.dstIp = ''
  trafficResult.value = null
  messageResult.value = null
  parseTimeDate.value = null
  detailVisible.value = false
  currentDetail.value = null
}

function formatTime(date) {
  if (!date) return '-'
  const pad = n => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

function formatEncryption(row) {
  if (!row) return '-'
  const alg = row.selectedEncryption
  const len = row.selectedEncryptionKeyLength
  if (!alg) return '-'
  if (len != null) return `${alg} (${len} bit)`
  return alg
}

function formatLifetime(seconds) {
  if (seconds == null) return '-'
  const s = Number(seconds)
  if (isNaN(s)) return '-'
  if (s < 60) return `${s} 秒`
  if (s < 3600) return `${Math.floor(s / 60)} 分 ${s % 60} 秒`
  if (s < 86400) return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`
  return `${Math.floor(s / 86400)} 天 ${Math.floor((s % 86400) / 3600)} 小时`
}

function isParsedCert(cert) {
  if (!cert) return false
  // 标准 X.509 证书必有 version；issuer / notBefore / notAfter 也必须有值
  if (cert.version) return true
  if (cert.issuer && cert.notBefore && cert.notAfter) return true
  return false
}

function certLifetime(cert) {
  if (!cert) return '-'
  if (cert.notBefore && cert.notAfter) {
    return `${cert.notBefore} ~ ${cert.notAfter}`
  }
  return cert.notBefore || cert.notAfter || '-'
}

function certSlots(row) {
  if (!row) return []
  const slots = []
  const initiatorCerts = row.initiatorCertificates || []
  const responderCerts = row.responderCertificates || []
  initiatorCerts.forEach((cert, index) => {
    slots.push({ label: `客户端证书链-${index + 1}`, cert })
  })
  responderCerts.forEach((cert, index) => {
    slots.push({ label: `服务端证书链-${index + 1}`, cert })
  })
  return slots
}

function parsedCertSlots(row) {
  return certSlots(row).filter(slot => isParsedCert(slot.cert))
}

function formatHexPreview(value) {
  if (!value) return '-'
  const text = String(value)
  return text.length > 128 ? text.slice(0, 128) + '...' : text
}

function openFullDetail(row) {
  currentDetail.value = row
  detailVisible.value = true
}

function exportCertificate(cert, label) {
  if (!cert || !cert.derBase64) {
    ElMessage.warning('证书数据为空，无法导出')
    return
  }
  try {
    const cleaned = cert.derBase64.replace(/\s/g, '')
    const binary = atob(cleaned)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    const blob = new Blob([bytes], { type: 'application/x-x509-ca-cert' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const serial = cert.serialNumber || cert.subject || 'cert'
    a.download = `${label || 'certificate'}-${serial}.cer`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    ElMessage.success('证书导出成功')
  } catch (e) {
    ElMessage.error('证书导出失败：' + e.message)
  }
}
</script>

<style scoped>
.page-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 20px;
}
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
}
.result-section {
  margin-top: 20px;
}
.section-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 12px;
}
.summary {
  margin-bottom: 16px;
  font-size: 15px;
  font-weight: 500;
  color: #303133;
}
.file-name {
  margin-top: 8px;
  font-size: 13px;
  color: #606266;
  word-break: break-all;
}
.detail-panel {
  padding: 16px;
  background: #fafafa;
  border-radius: 4px;
}
.detail-actions {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
.cert-grid-section {
  margin-top: 16px;
}
.cert-grid-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 12px;
}
.cert-card {
  background: #fff;
  border: 1px solid #e4e7ed;
  border-radius: 8px;
  padding: 14px;
  margin-bottom: 16px;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.04);
}
.cert-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
  padding-bottom: 10px;
  border-bottom: 1px solid #ebeef5;
}
.cert-card-label {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
}
.cert-card-body {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.cert-field {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 13px;
  line-height: 1.5;
}
.cert-field-label {
  color: #606266;
  min-width: 64px;
  flex-shrink: 0;
}
.cert-field-value {
  color: #303133;
  word-break: break-all;
  flex: 1;
}
.hex-preview {
  font-family: monospace;
  font-size: 13px;
  word-break: break-all;
  color: #606266;
  line-height: 1.6;
}
.full-detail-dialog {
  max-height: 70vh;
  overflow-y: auto;
  padding-right: 8px;
}
.detail-block {
  margin-top: 16px;
}
.block-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 8px;
}
.version-line {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
</style>
