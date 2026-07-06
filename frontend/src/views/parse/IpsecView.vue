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
              :rows="6"
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
                <el-descriptions-item label="发起方 SPI" :span="1">
                  {{ row.initiatorSpi || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="响应方 SPI" :span="1">
                  {{ row.responderSpi || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="协商加密算法">
                  {{ row.selectedEncryption || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="协商完整性算法">
                  {{ row.selectedIntegrity || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="协商 PRF">
                  {{ row.selectedPrf || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="协商 DH 组">
                  {{ row.selectedDhGroup || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="发起方身份" :span="2">
                  {{ row.initiatorIdentity || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="响应方身份" :span="2">
                  {{ row.responderIdentity || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="认证方式">
                  {{ row.authMethod || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="证书数量">
                  {{ row.certificateCount }}
                </el-descriptions-item>
                <el-descriptions-item label="Vendor ID" :span="2">
                  <div v-if="row.vendorIds && row.vendorIds.length" class="tag-list">
                    <el-tag v-for="(v, idx) in row.vendorIds" :key="'vid-' + idx" size="small" class="algo-tag">{{ v }}</el-tag>
                  </div>
                  <span v-else>-</span>
                </el-descriptions-item>
                <el-descriptions-item label="Notify 类型" :span="2">
                  <div v-if="row.notifyTypes && row.notifyTypes.length" class="tag-list">
                    <el-tag v-for="(v, idx) in row.notifyTypes" :key="'nt-' + idx" size="small" class="algo-tag">{{ v }}</el-tag>
                  </div>
                  <span v-else>-</span>
                </el-descriptions-item>
                <el-descriptions-item label="Delete 类型" :span="2">
                  <div v-if="row.deleteTypes && row.deleteTypes.length" class="tag-list">
                    <el-tag v-for="(v, idx) in row.deleteTypes" :key="'dt-' + idx" size="small" class="algo-tag">{{ v }}</el-tag>
                  </div>
                  <span v-else>-</span>
                </el-descriptions-item>
                <el-descriptions-item v-if="row.notes && row.notes.length" label="解析备注" :span="2">
                  <div v-for="(note, idx) in row.notes" :key="'note-' + idx" class="note-item">{{ note }}</div>
                </el-descriptions-item>
              </el-descriptions>

              <div class="detail-block">
                <div class="block-title">发起方算法提案</div>
                <div v-for="(list, key) in row.initiatorAlgorithms" :key="'init-algo-' + key" class="algo-sub-block">
                  <div class="algo-sub-title">{{ algoTitle(key) }}</div>
                  <div class="algo-list">
                    <el-tag v-for="(alg, idx) in list" :key="'init-' + key + '-' + idx" size="small" class="algo-tag" :type="isSelected(row, key, alg, 'initiator') ? 'success' : ''">
                      {{ alg }}
                    </el-tag>
                    <span v-if="!list || list.length === 0">-</span>
                  </div>
                </div>
              </div>

              <div class="detail-block">
                <div class="block-title">响应方算法提案</div>
                <div v-for="(list, key) in row.responderAlgorithms" :key="'resp-algo-' + key" class="algo-sub-block">
                  <div class="algo-sub-title">{{ algoTitle(key) }}</div>
                  <div class="algo-list">
                    <el-tag v-for="(alg, idx) in list" :key="'resp-' + key + '-' + idx" size="small" class="algo-tag" :type="isSelected(row, key, alg, 'responder') ? 'success' : ''">
                      {{ alg }}
                    </el-tag>
                    <span v-if="!list || list.length === 0">-</span>
                  </div>
                </div>
              </div>

              <el-collapse v-if="row.messages && row.messages.length" class="param-collapse">
                <el-collapse-item v-for="(msg, idx) in row.messages" :key="'msg-' + idx" :title="msgTitle(msg)">
                  <JsonView :data="toChinese(msg)" />
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
  selectedIntegrity: '协商完整性算法',
  selectedPrf: '协商 PRF',
  selectedDhGroup: '协商 DH 组',
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
  messages: '消息列表'
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
}

function formatTime(date) {
  if (!date) return '-'
  const pad = n => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

function algoTitle(key) {
  const titles = {
    encryption: '加密',
    integrity: '完整性',
    prf: 'PRF',
    dhGroup: 'DH 组'
  }
  return titles[key] || key
}

function isSelected(row, key, alg, side) {
  if (!alg || !row) return false
  const selectedMap = {
    encryption: 'selectedEncryption',
    integrity: 'selectedIntegrity',
    prf: 'selectedPrf',
    dhGroup: 'selectedDhGroup'
  }
  const field = selectedMap[key]
  return field && alg === row[field]
}

function msgTitle(msg) {
  const direction = msg?.direction || '-'
  const exchangeType = msg?.header?.exchangeType || '-'
  return `${direction} - ${exchangeType}`
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
.tag-list {
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
.hex-block {
  font-family: monospace;
  font-size: 13px;
  word-break: break-all;
  background: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  color: #303133;
  line-height: 1.6;
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
.algo-sub-block {
  margin-bottom: 12px;
}
.algo-sub-block:last-child {
  margin-bottom: 0;
}
.algo-sub-title {
  font-size: 13px;
  color: #606266;
  margin-bottom: 6px;
}
</style>
