<template>
  <el-card>
    <div class="page-title">TLS 流量包解析工作区</div>
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
          <el-form-item label="TLS 报文">
            <el-input
              v-model="form.input"
              type="textarea"
              :rows="6"
              placeholder="TLS record 十六进制报文（hex）"
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
          <el-button type="primary" :loading="loadingMessage" @click="runMessage">解析 TLS 报文</el-button>
          <el-button @click="clear">清空</el-button>
        </div>
      </el-form-item>
    </el-form>

    <div v-if="messageResult" class="result-section">
      <div class="section-title">TLS 报文解析结果</div>
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
                <el-descriptions-item label="握手完成">
                  {{ row.handshakeCompleted ? '是' : '否' }}
                </el-descriptions-item>
                <el-descriptions-item label="认证模式">
                  {{ row.authMode || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="服务端选中密码套件" :span="2">
                  {{ cipherSuiteText(row.serverSelectedCipherSuite) }}
                </el-descriptions-item>
                <el-descriptions-item label="Client Random" :span="2">
                  {{ row.clientRandom || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="Server Random" :span="2">
                  {{ row.serverRandom || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="Server Name" :span="2">
                  {{ row.serverName || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="客户端会话 ID" :span="2">
                  {{ row.clientSessionId || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="服务端会话 ID" :span="2">
                  {{ row.serverSessionId || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="客户端压缩方法" :span="1">
                  {{ row.clientCompressionMethods || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="服务端压缩方法" :span="1">
                  {{ row.serverCompressionMethod || '-' }}
                </el-descriptions-item>
                <el-descriptions-item v-if="row.notes && row.notes.length" label="解析备注" :span="2">
                  <div v-for="(note, idx) in row.notes" :key="'note-' + idx" class="note-item">{{ note }}</div>
                </el-descriptions-item>
              </el-descriptions>

              <div class="detail-block">
                <div class="block-title">客户端密码套件</div>
                <div class="algo-list">
                  <el-tag
                    v-for="(cs, idx) in row.clientCipherSuites"
                    :key="'cs-' + idx"
                    size="small"
                    class="algo-tag"
                    :type="isSelectedCipherSuite(row, cs) ? 'success' : ''"
                  >
                    {{ cs.name || cs.value || cs }}
                  </el-tag>
                  <span v-if="!row.clientCipherSuites || row.clientCipherSuites.length === 0">-</span>
                </div>
              </div>

              <el-collapse class="param-collapse">
                <el-collapse-item v-if="row.clientExtensions && row.clientExtensions.length" title="客户端扩展列表">
                  <div v-for="(ext, idx) in row.clientExtensions" :key="'ce-' + idx" class="ext-block">
                    <div class="ext-title">{{ ext.type || ext['类型'] || '扩展 ' + idx }}</div>
                    <JsonView :data="toChinese(ext)" />
                  </div>
                </el-collapse-item>
                <el-collapse-item v-if="row.serverExtensions && row.serverExtensions.length" title="服务端扩展列表">
                  <div v-for="(ext, idx) in row.serverExtensions" :key="'se-' + idx" class="ext-block">
                    <div class="ext-title">{{ ext.type || ext['类型'] || '扩展 ' + idx }}</div>
                    <JsonView :data="toChinese(ext)" />
                  </div>
                </el-collapse-item>
                <el-collapse-item v-if="row.serverCertificateChain && row.serverCertificateChain.length" title="服务端证书链">
                  <div v-for="(cert, idx) in row.serverCertificateChain" :key="'scert-' + idx" class="cert-block">
                    <div class="cert-title">证书 {{ idx + 1 }}</div>
                    <JsonView :data="toChinese(cert)" />
                  </div>
                </el-collapse-item>
                <el-collapse-item v-if="row.clientCertificateChain && row.clientCertificateChain.length" title="客户端证书链">
                  <div v-for="(cert, idx) in row.clientCertificateChain" :key="'ccert-' + idx" class="cert-block">
                    <div class="cert-title">证书 {{ idx + 1 }}</div>
                    <JsonView :data="toChinese(cert)" />
                  </div>
                </el-collapse-item>
              </el-collapse>
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
  isGmSuite: '是否国密套件',
  truncated: '数据截断',
  note: '备注',
  record: 'Record 层',
  handshake: 'Handshake 层',
  contentType: '内容类型',
  version: '版本',
  length: '长度',
  handshakeType: '握手类型',
  client_version: '客户端版本',
  server_version: '服务端版本',
  random: '随机数',
  sessionIdLength: '会话 ID 长度',
  sessionId: '会话 ID',
  cipherSuitesLength: '密码套件列表长度',
  cipherSuites: '密码套件列表',
  cipherSuite: '密码套件',
  compressionMethodsLength: '压缩方法长度',
  compressionMethods: '压缩方法',
  compressionMethod: '压缩方法',
  extensionsLength: '扩展总长度',
  extensions: '扩展列表',
  value: '值',
  name: '名称',
  gm: '国密',
  type: '类型',
  data: '数据',
  sessionCount: '会话数',
  parseTimeMs: '解析耗时(ms)',
  sessions: '会话列表',
  protocolVersion: '协议版本',
  label: '标签',
  handshakeCompleted: '握手完成',
  authMode: '认证模式',
  serverSelectedCipherSuite: '服务端选中密码套件',
  clientRandom: '客户端随机数',
  serverRandom: '服务端随机数',
  serverName: '服务端名称',
  clientCipherSuites: '客户端密码套件',
  clientCompressionMethods: '客户端压缩方法',
  serverCompressionMethod: '服务端压缩方法',
  clientSessionId: '客户端会话 ID',
  serverSessionId: '服务端会话 ID',
  clientExtensions: '客户端扩展',
  serverExtensions: '服务端扩展',
  serverCertificateChain: '服务端证书链',
  clientCertificateChain: '客户端证书链',
  notes: '解析备注',
  version: '版本',
  serialNumber: '序列号',
  subject: '主题',
  issuer: '签发者',
  notBefore: '生效时间',
  notAfter: '失效时间',
  expired: '已过期',
  signatureAlgorithm: '签名算法',
  publicKeyAlgorithm: '公钥算法',
  publicKeyHex: '公钥(hex)',
  keyUsage: '密钥用途',
  isSm2: 'SM2',
  sm2: 'SM2',
  derBase64: 'DER(Base64)',
  extensions: '扩展',
  checks: '校验结果',
  description: '描述',
  oid: 'OID',
  critical: '关键',
  value: '值'
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
    const res = await api.post('/tls/traffic/parse', fd)
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
    ElMessage.warning('请先输入 TLS 报文')
    return
  }
  loadingMessage.value = true
  try {
    const res = await api.post('/tls/parse', { ...form })
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
}

function formatTime(date) {
  if (!date) return '-'
  const pad = n => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

function cipherSuiteText(cs) {
  if (!cs) return '-'
  if (typeof cs === 'string') return cs
  return cs.name || cs.value || JSON.stringify(cs)
}

function isSelectedCipherSuite(row, cs) {
  if (!cs || !row || !row.serverSelectedCipherSuite) return false
  const selected = row.serverSelectedCipherSuite
  if (typeof cs === 'object' && typeof selected === 'object') {
    return cs.value === selected.value
  }
  return cs === selected
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
.detail-block {
  margin-top: 16px;
}
.block-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 8px;
}
.algo-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.algo-tag {
  margin: 0;
}
.param-collapse {
  margin-top: 16px;
}
.ext-block,
.cert-block {
  margin-bottom: 12px;
}
.ext-block:last-child,
.cert-block:last-child {
  margin-bottom: 0;
}
.ext-title,
.cert-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 6px;
}
.note-item {
  font-size: 13px;
  color: #f56c6c;
  margin-bottom: 4px;
}
.version-line {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
</style>
