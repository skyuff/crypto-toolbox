<template>
  <el-card>
    <div class="page-title">SSH 流量包解析工作区</div>
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
          <el-row :gutter="20">
            <el-col :span="12">
              <el-form-item label="目标端口">
                <el-input v-model.number="form.dstPort" placeholder="22" />
              </el-form-item>
            </el-col>
            <el-col :span="12">
              <el-form-item label="源 IP">
                <el-input v-model="form.srcIp" placeholder="0.0.0.0" />
              </el-form-item>
            </el-col>
          </el-row>
          <el-form-item label="目标 IP">
            <el-input v-model="form.dstIp" placeholder="0.0.0.0" />
          </el-form-item>
        </el-col>
      </el-row>

      <el-form-item>
        <div class="btn-row">
          <el-button type="primary" :loading="loading" @click="run">解析</el-button>
          <el-button @click="clear">清空</el-button>
        </div>
      </el-form-item>
    </el-form>

    <div v-if="result" class="result-section">
      <div class="summary">
        共解析出 {{ result.sessionCount }} 组会话数据，解析时间：{{ formatTime(parseTimeDate) }}
      </div>

      <el-table
        :data="result.sessions"
        border
        style="width: 100%"
        row-key="id"
        @expand-change="handleExpand"
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
                <el-descriptions-item label="软件版本" :span="2">
                  {{ row.softwareVersion || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="密钥交换算法">
                  {{ row.selectedKexAlgorithm || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="主机密钥算法">
                  {{ row.selectedHostKeyAlgorithm || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="加密算法（C→S）">
                  {{ row.selectedEncryptionAlgorithmClientToServer || row.selectedEncryptionAlgorithm || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="加密算法（S→C）">
                  {{ row.selectedEncryptionAlgorithmServerToClient || row.selectedEncryptionAlgorithm || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="MAC 算法（C→S）">
                  {{ row.selectedMacAlgorithmClientToServer || row.selectedMacAlgorithm || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="MAC 算法（S→C）">
                  {{ row.selectedMacAlgorithmServerToClient || row.selectedMacAlgorithm || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="压缩算法（C→S）">
                  {{ row.selectedCompressionAlgorithmClientToServer || row.selectedCompressionAlgorithm || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="压缩算法（S→C）">
                  {{ row.selectedCompressionAlgorithmServerToClient || row.selectedCompressionAlgorithm || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="服务端签名类型">
                  {{ row.serverSignatureType || '-' }}
                </el-descriptions-item>
                <el-descriptions-item label="服务端公钥类型">
                  {{ row.serverPublicKeyType || '-' }}
                </el-descriptions-item>
              </el-descriptions>

              <div class="detail-block">
                <div class="block-title">客户端支持的算法</div>
                <div v-for="(list, key) in row.clientAlgorithms" :key="'client-algo-' + key" class="algo-sub-block">
                  <div class="algo-sub-title">{{ algoTitle(key) }}</div>
                  <div class="algo-list">
                    <el-tag v-for="(alg, idx) in list" :key="'client-' + key + '-' + idx" size="small" class="algo-tag" :type="isSelected(row, key, alg, 'client') ? 'success' : ''">
                      {{ alg }}
                    </el-tag>
                    <span v-if="!list || list.length === 0">-</span>
                  </div>
                </div>
              </div>

              <div class="detail-block">
                <div class="block-title">服务端支持的算法</div>
                <div v-for="(list, key) in row.serverAlgorithms" :key="'server-algo-' + key" class="algo-sub-block">
                  <div class="algo-sub-title">{{ algoTitle(key) }}</div>
                  <div class="algo-list">
                    <el-tag v-for="(alg, idx) in list" :key="'server-' + key + '-' + idx" size="small" class="algo-tag" :type="isSelected(row, key, alg, 'server') ? 'success' : ''">
                      {{ alg }}
                    </el-tag>
                    <span v-if="!list || list.length === 0">-</span>
                  </div>
                </div>
              </div>

              <el-collapse class="param-collapse">
                <el-collapse-item v-if="row.clientDhInitParamHex" title="客户端协商 DH 参数">
                  <div class="hex-block">{{ row.clientDhInitParamHex }}</div>
                </el-collapse-item>
                <el-collapse-item v-if="row.serverDhReplyParamHex" title="服务端响应 DH 参数">
                  <div class="hex-block">{{ row.serverDhReplyParamHex }}</div>
                </el-collapse-item>
                <el-collapse-item v-if="row.serverPublicKeyHex" title="服务端公钥（hex）">
                  <div class="hex-block">{{ row.serverPublicKeyHex }}</div>
                </el-collapse-item>
                <el-collapse-item v-if="row.serverSignatureValueHex" title="服务端签名值">
                  <div class="hex-block">{{ row.serverSignatureValueHex }}</div>
                </el-collapse-item>
              </el-collapse>

              <div v-if="row.notes && row.notes.length" class="detail-block">
                <div class="block-title">解析备注</div>
                <div v-for="(note, idx) in row.notes" :key="'note-' + idx" class="note-item">{{ note }}</div>
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
  </el-card>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { Upload } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const form = reactive({
  file: null,
  fileName: '',
  srcIp: '',
  dstIp: '',
  dstPort: 22
})

const result = ref(null)
const loading = ref(false)
const parseTimeDate = ref(null)

function handleFileChange(file) {
  form.file = file.raw
  form.fileName = file.name
}

async function run() {
  if (!form.file) {
    ElMessage.warning('请先上传流量包文件')
    return
  }
  loading.value = true
  try {
    const fd = new FormData()
    fd.append('file', form.file)
    const res = await api.post('/ssh/traffic/parse', fd)
    result.value = res
    parseTimeDate.value = new Date()
  } catch (e) {
    ElMessage.error('解析失败：' + (e.response?.data?.message || e.message))
  } finally {
    loading.value = false
  }
}

function clear() {
  form.file = null
  form.fileName = ''
  form.srcIp = ''
  form.dstIp = ''
  form.dstPort = 22
  result.value = null
  parseTimeDate.value = null
}

function formatTime(date) {
  if (!date) return '-'
  const pad = n => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

function handleExpand(row, expandedRows) {
  // 可在此处理展开/收起事件
}

function algoTitle(key) {
  const titles = {
    kex: '密钥交换',
    hostKey: '主机密钥',
    encryption: '对称加密',
    mac: '完整性校验（MAC）',
    compression: '压缩'
  }
  return titles[key] || key
}

function isSelected(row, key, alg, side) {
  if (!alg || !row) return false
  if (key === 'kex') return alg === row.selectedKexAlgorithm
  if (key === 'hostKey') return alg === row.selectedHostKeyAlgorithm
  if (key === 'encryption') {
    return alg === row.selectedEncryptionAlgorithmClientToServer || alg === row.selectedEncryptionAlgorithmServerToClient
  }
  if (key === 'mac') {
    return alg === row.selectedMacAlgorithmClientToServer || alg === row.selectedMacAlgorithmServerToClient
  }
  if (key === 'compression') {
    return alg === row.selectedCompressionAlgorithmClientToServer || alg === row.selectedCompressionAlgorithmServerToClient
  }
  return false
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
