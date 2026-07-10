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
              <div class="el-upload__text">点击或将文件拖拽到此处上传</div>
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
              placeholder="TLS record 十六进制报文 (hex)"
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
        流量解析后 {{ trafficResult.sessionCount }} 组会话数据，解析时间：{{ formatTime(parseTimeDate) }}
      </div>

      <el-table
        :data="pagedSessions"
        border
        style="width: 100%"
        row-key="id"
        :expand-row-keys="expandRowKeys"
      >
        <el-table-column type="expand" width="40">
          <template #default="{ row }">
            <div class="detail-panel">
              <el-descriptions :column="2" border>
                <el-descriptions-item label="协议版本">
                  <div class="version-line">
                    <span>{{ fallbackText(row.protocolVersion) }}</span>
                    <el-tag v-if="row.gm" size="small" type="danger">国密</el-tag>
                  </div>
                </el-descriptions-item>
                <el-descriptions-item label="是否完成握手">
                  {{ row.handshakeCompleted ? '是' : '否' }}
                </el-descriptions-item>
                <el-descriptions-item label="认证方式">
                  {{ row.authMode || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="服务端选择的密码套件">
                  {{ cipherSuiteText(row.serverSelectedCipherSuite) }}
                </el-descriptions-item>
                <el-descriptions-item label="客户端 Session ID">
                  {{ row.clientSessionId || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="服务端 Session ID">
                  {{ row.serverSessionId || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="客户端压缩方法">
                  {{ row.clientCompressionMethods || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="服务端压缩方法">
                  {{ row.serverCompressionMethod || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="客户端随机数" :span="2">
                  <div class="mono-wrap">{{ row.clientRandom || '-' }}</div>
                </el-descriptions-item>
                <el-descriptions-item label="服务端随机数" :span="2">
                  <div class="mono-wrap">{{ row.serverRandom || '-' }}</div>
                </el-descriptions-item>
                <el-descriptions-item v-if="row.notes && row.notes.length" label="解析备注" :span="2">
                  <div v-for="(note, idx) in row.notes" :key="'note-' + idx" class="note-item">{{ note }}</div>
                </el-descriptions-item>
              </el-descriptions>

              <el-collapse v-model="collapseActiveNames" class="param-collapse">
                <el-collapse-item v-if="row.clientExtensions && row.clientExtensions.length" name="client-extensions" title="客户端扩展列表">
                  <div class="ext-list">
                    <div v-for="(ext, idx) in row.clientExtensions" :key="'ce-' + idx" class="ext-row">
                      <span class="ext-type">{{ ext.type || ext['类型'] || '扩展 ' + idx }}</span>
                      <span class="ext-data">{{ ext.data || ext['数据'] || '-' }}</span>
                    </div>
                  </div>
                </el-collapse-item>
                <el-collapse-item v-if="row.serverExtensions && row.serverExtensions.length" name="server-extensions" title="服务端扩展列表">
                  <div class="ext-list">
                    <div v-for="(ext, idx) in row.serverExtensions" :key="'se-' + idx" class="ext-row">
                      <span class="ext-type">{{ ext.type || ext['类型'] || '扩展 ' + idx }}</span>
                      <span class="ext-data">{{ ext.data || ext['数据'] || '-' }}</span>
                    </div>
                  </div>
                </el-collapse-item>
                <el-collapse-item v-if="row.serverCertificateChain && row.serverCertificateChain.length" name="server-cert-chain" title="服务端证书链">
                  <div class="cert-chain-grid two-column">
                    <div v-for="(cert, idx) in row.serverCertificateChain" :key="'scert-' + idx" class="cert-card">
                      <div class="cert-title">
                        <span>服务端证书链-{{ idx + 1 }}</span>
                        <el-button type="primary" size="small" @click="exportCert(cert, idx)">导出证书</el-button>
                      </div>
                      <div class="cert-header">
                        <el-tag size="small">{{ certVersionText(cert) }}</el-tag>
                        <el-tag v-if="cert.expired || cert['已过期']" size="small" type="danger">证书不在有效期内</el-tag>
                        <el-tag v-else size="small" type="success">证书在有效期内</el-tag>
                      </div>
                      <div class="cert-body">
                        <div class="cert-row">
                          <span class="cert-label">序列号</span>
                          <span class="cert-val">{{ certSerialText(cert) }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">使用者</span>
                          <span class="cert-val">{{ cert.subject || cert['使用者'] || cert['主体'] || cert['主题'] || '-' }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">颁发者</span>
                          <span class="cert-val">{{ cert.issuer || cert['颁发者'] || cert['签发者'] || '-' }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">有效期</span>
                          <span class="cert-val">{{ cert.validityPeriod || cert['有效期'] || (cert.notBefore && cert.notAfter ? cert.notBefore + ' ~ ' + cert.notAfter : '-') }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">签名算法</span>
                          <span class="cert-val">{{ certSignatureText(cert) }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">公钥算法</span>
                          <span class="cert-val">{{ cert.publicKeyAlgorithm || cert['公钥算法'] || '-' }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">密钥用法</span>
                          <span class="cert-val">{{ cert.keyUsage || cert['密钥用法'] || cert['公钥用途'] || '-' }}</span>
                        </div>
                        <el-collapse class="cert-sub-collapse">
                          <el-collapse-item :name="'spub-' + idx" title="公钥 Hex">
                            <pre class="hex-pre">{{ cert.publicKeyHex || cert['公钥 hex'] || cert['公钥(hex)'] || '-' }}</pre>
                          </el-collapse-item>
                          <el-collapse-item :name="'sext-' + idx" title="证书扩展项">
                            <div v-if="cert.extensions && cert.extensions.length" class="ext-list">
                              <div v-for="(ext, eidx) in cert.extensions" :key="'sext-' + idx + '-' + eidx" class="ext-row">
                                <span class="ext-type">{{ ext.name || ext.oid || '扩展 ' + eidx }}</span>
                                <span class="ext-data">{{ ext.description || ext.value || '-' }}</span>
                              </div>
                            </div>
                            <div v-else class="empty-text">无扩展项</div>
                          </el-collapse-item>
                          <el-collapse-item :name="'schk-' + idx" title="证书格式检查">
                            <div v-if="cert.checks && cert.checks.length" class="check-list">
                              <div v-for="(chk, cidx) in cert.checks" :key="'schk-' + idx + '-' + cidx" class="check-row">
                                <el-tag :type="(chk.pass || chk['通过']) ? 'success' : 'danger'" size="small">
                                  {{ (chk.pass || chk['通过']) ? '通过' : '未通过' }}
                                </el-tag>
                                <span class="check-text">{{ (chk.item || chk['检查项']) + '：' + (chk.message || chk['说明'] || chk['信息'] || '') }}</span>
                              </div>
                            </div>
                            <div v-else class="empty-text">无检查项</div>
                          </el-collapse-item>
                        </el-collapse>
                      </div>
                    </div>
                  </div>
                </el-collapse-item>
                <el-collapse-item v-if="row.clientCertificateChain && row.clientCertificateChain.length" name="client-cert-chain" title="客户端证书链">
                  <div class="cert-chain-grid two-column">
                    <div v-for="(cert, idx) in row.clientCertificateChain" :key="'ccert-' + idx" class="cert-card">
                      <div class="cert-title">
                        <span>客户端证书链-{{ idx + 1 }}</span>
                        <el-button type="primary" size="small" @click="exportCert(cert, idx)">导出证书</el-button>
                      </div>
                      <div class="cert-header">
                        <el-tag size="small">{{ certVersionText(cert) }}</el-tag>
                        <el-tag v-if="cert.expired || cert['已过期']" size="small" type="danger">证书不在有效期内</el-tag>
                        <el-tag v-else size="small" type="success">证书在有效期内</el-tag>
                      </div>
                      <div class="cert-body">
                        <div class="cert-row">
                          <span class="cert-label">序列号</span>
                          <span class="cert-val">{{ certSerialText(cert) }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">使用者</span>
                          <span class="cert-val">{{ cert.subject || cert['使用者'] || cert['主体'] || cert['主题'] || '-' }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">颁发者</span>
                          <span class="cert-val">{{ cert.issuer || cert['颁发者'] || cert['签发者'] || '-' }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">有效期</span>
                          <span class="cert-val">{{ cert.validityPeriod || cert['有效期'] || (cert.notBefore && cert.notAfter ? cert.notBefore + ' ~ ' + cert.notAfter : '-') }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">签名算法</span>
                          <span class="cert-val">{{ certSignatureText(cert) }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">公钥算法</span>
                          <span class="cert-val">{{ cert.publicKeyAlgorithm || cert['公钥算法'] || '-' }}</span>
                        </div>
                        <div class="cert-row">
                          <span class="cert-label">密钥用法</span>
                          <span class="cert-val">{{ cert.keyUsage || cert['密钥用法'] || cert['公钥用途'] || '-' }}</span>
                        </div>
                        <el-collapse class="cert-sub-collapse">
                          <el-collapse-item :name="'cpub-' + idx" title="公钥 Hex">
                            <pre class="hex-pre">{{ cert.publicKeyHex || cert['公钥 hex'] || cert['公钥(hex)'] || '-' }}</pre>
                          </el-collapse-item>
                          <el-collapse-item :name="'cext-' + idx" title="证书扩展项">
                            <div v-if="cert.extensions && cert.extensions.length" class="ext-list">
                              <div v-for="(ext, eidx) in cert.extensions" :key="'cext-' + idx + '-' + eidx" class="ext-row">
                                <span class="ext-type">{{ ext.name || ext.oid || '扩展 ' + eidx }}</span>
                                <span class="ext-data">{{ ext.description || ext.value || '-' }}</span>
                              </div>
                            </div>
                            <div v-else class="empty-text">无扩展项</div>
                          </el-collapse-item>
                          <el-collapse-item :name="'cchk-' + idx" title="证书格式检查">
                            <div v-if="cert.checks && cert.checks.length" class="check-list">
                              <div v-for="(chk, cidx) in cert.checks" :key="'cchk-' + idx + '-' + cidx" class="check-row">
                                <el-tag :type="(chk.pass || chk['通过']) ? 'success' : 'danger'" size="small">
                                  {{ (chk.pass || chk['通过']) ? '通过' : '未通过' }}
                                </el-tag>
                                <span class="check-text">{{ (chk.item || chk['检查项']) + '：' + (chk.message || chk['说明'] || chk['信息'] || '') }}</span>
                              </div>
                            </div>
                            <div v-else class="empty-text">无检查项</div>
                          </el-collapse-item>
                        </el-collapse>
                      </div>
                    </div>
                  </div>
                </el-collapse-item>
                <el-collapse-item v-if="row.serverKeyExchange" name="server-key-exchange" title="服务端密钥交换">
                  <JsonView :data="toChinese(row.serverKeyExchange)" />
                </el-collapse-item>
              </el-collapse>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="协议版本" prop="protocolVersion" min-width="260" show-overflow-tooltip>
          <template #default="{ row }">
            {{ fallbackText(row.protocolVersion) }}
          </template>
        </el-table-column>
        <el-table-column label="发起方 IP" prop="srcIp" min-width="140" />
        <el-table-column label="发起方端口" prop="srcPort" width="110" />
        <el-table-column label="目标IP" prop="dstIp" min-width="140" />
        <el-table-column label="接收端端口" prop="dstPort" width="110" />
        <el-table-column label="结果" prop="result" width="90">
          <template #default="{ row }">
            <el-tag v-if="row.result" size="small" :type="row.result === 'TLCP' ? 'danger' : 'success'">{{ row.result }}</el-tag>
            <span v-else>-</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" size="small" @click="toggleExpand(row)">查看详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-row">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="trafficResult.sessionCount"
          layout="prev, pager, next, total"
          background
        />
      </div>
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
  version: '版本号',
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
  extensions: '证书扩展项',
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
  serverKeyExchange: '服务端密钥交换',
  serverCertificateChain: '服务端证书链',
  clientCertificateChain: '客户端证书链',
  notes: '解析备注',
  serialNumber: '序列号',
  subject: '主体',
  issuer: '颁发者',
  notBefore: '生效时间',
  notAfter: '失效时间',
  validityPeriod: '有效期',
  expired: '已过期',
  signatureAlgorithm: '签名算法',
  publicKeyAlgorithm: '公钥算法',
  publicKeyHex: '公钥 hex',
  keyUsage: '密钥用途',
  isSm2: 'SM2',
  sm2: 'SM2',
  derBase64: 'DER(Base64)',
  checks: '证书链校验信息',
  description: '描述',
  oid: 'OID',
  critical: '关键',
  algorithm: '密钥交换算法',
  curveType: '曲线类型',
  namedCurve: '命名曲线',
  publicKeyHex: '公钥 hex',
  rawHex: '原始数据(hex)',
  parseNote: '解析备注'
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
const expandedRows = ref(new Set())
const expandRowKeys = computed(() => Array.from(expandedRows.value))
const collapseActiveNames = ref(['server-cert-chain'])
const currentPage = ref(1)
const pageSize = ref(10)

const cnMessageResult = computed(() => messageResult.value ? toChinese(messageResult.value) : null)
const pagedSessions = computed(() => {
  if (!trafficResult.value || !trafficResult.value.sessions) return []
  const start = (currentPage.value - 1) * pageSize.value
  return trafficResult.value.sessions.slice(start, start + pageSize.value)
})

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
    currentPage.value = 1
    expandedRows.value.clear()
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
  currentPage.value = 1
  expandedRows.value.clear()
}

function formatTime(date) {
  if (!date) return '-'
  const pad = n => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

/** 空值回退：仅对 null/undefined/空字符串显示 '-'，保留 0/false 等合法值 */
function fallbackText(v) {
  return v === undefined || v === null || v === '' ? '-' : String(v)
}

/** 证书版本显示：将数值 0/1/2 正确映射为 v1/v2/v3，避免 0 被误判为空 */
function certVersionText(cert) {
  const v = cert.version ?? cert['版本号'] ?? cert['版本']
  if (v === undefined || v === null || v === '') return '-'
  if (typeof v === 'number') return 'v' + (v + 1)
  return String(v)
}

/** 证书序列号显示：保留 '0' 等合法值 */
function certSerialText(cert) {
  const s = cert.serialNumber ?? cert['序列号']
  return s === undefined || s === null || s === '' ? '-' : String(s)
}

function cipherSuiteText(cs) {
  if (!cs) return '-'
  if (typeof cs === 'string') return cs
  if (cs.value && cs.name) return cs.value + ' ' + cs.name
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

function toggleExpand(row) {
  if (expandedRows.value.has(row.id)) {
    expandedRows.value.delete(row.id)
  } else {
    expandedRows.value.add(row.id)
  }
}

function certSignatureText(cert) {
  const sa = cert.signatureAlgorithm || cert['签名算法']
  if (!sa) return '-'
  if (typeof sa === 'string') return sa
  return sa.name || sa.value || sa.oid || JSON.stringify(sa)
}

function exportCert(cert, idx) {
  const base64 = cert.derBase64 || cert['DER(Base64)']
  if (!base64) {
    ElMessage.warning('证书没有 DER 数据')
    return
  }
  try {
    const bytes = Uint8Array.from(atob(base64.replace(/\s/g, '')), c => c.charCodeAt(0))
    const blob = new Blob([bytes], { type: 'application/x-x509-ca-cert' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = certFileName(cert, idx)
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    ElMessage.success('证书导出成功')
  } catch (e) {
    ElMessage.error('证书导出失败：' + e.message)
  }
}

function certFileName(cert, idx) {
  const subject = cert.subject || cert['主题'] || ''
  const cnMatch = subject.match(/CN=([^,;/]+)/i)
  const cn = cnMatch ? cnMatch[1].trim() : (cert.serialNumber || cert['序列号'] || 'cert')
  const safe = cn.replace(/[\\/:*?"<>|]/g, '_')
  return `cert_${idx + 1}_${safe}.cer`
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
.cert-chain-section {
  margin-top: 16px;
}
.cert-chain-grid.two-column {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.cert-chain-grid.two-column .cert-block {
  margin-bottom: 0;
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
  display: flex;
  align-items: center;
  justify-content: space-between;
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
.cert-card {
  background: #fff;
  border: 1px solid #ebeef5;
  border-radius: 4px;
  padding: 12px;
}
.cert-card .cert-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.cert-body {
  font-size: 13px;
}
.cert-row {
  display: flex;
  padding: 6px 0;
  border-bottom: 1px dashed #ebeef5;
}
.cert-row:last-child {
  border-bottom: none;
}
.cert-label {
  color: #409eff;
  font-weight: 600;
  min-width: 100px;
  flex-shrink: 0;
}
.cert-val {
  color: #303133;
  word-break: break-all;
  flex: 1;
  font-family: monospace;
}
.pagination-row {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
.mono-wrap {
  font-family: monospace;
  word-break: break-all;
}
.ext-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.ext-row {
  display: flex;
  gap: 12px;
  font-size: 13px;
}
.ext-type {
  color: #409eff;
  font-weight: 600;
  min-width: 220px;
  flex-shrink: 0;
}
.ext-data {
  color: #303133;
  font-family: monospace;
  word-break: break-all;
  flex: 1;
}
.cert-header {
  display: flex;
  gap: 8px;
  margin-bottom: 10px;
}
.cert-sub-collapse {
  margin-top: 8px;
}
.hex-pre {
  margin: 0;
  padding: 8px;
  background: #f5f7fa;
  border-radius: 4px;
  font-size: 12px;
  word-break: break-all;
  white-space: pre-wrap;
}
.check-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.check-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
}
.check-text {
  color: #303133;
}
.empty-text {
  font-size: 13px;
  color: #909399;
}
</style>
