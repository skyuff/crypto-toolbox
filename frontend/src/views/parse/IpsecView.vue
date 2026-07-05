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
          <el-button type="primary" :loading="loading" @click="run">解析</el-button>
          <el-button @click="clear">清空</el-button>
        </div>
      </el-form-item>
    </el-form>

    <div v-if="cnResult" class="result-section">
      <div class="section-title">解析结果</div>
      <JsonView :data="cnResult" />
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
  critical: '关键位',
  payloadLength: 'Payload 长度',
  data: '数据'
}

const form = reactive({
  input: '',
  format: 'hex',
  srcIp: '',
  dstIp: ''
})
const rawResult = ref(null)
const loading = ref(false)

const cnResult = computed(() => rawResult.value ? toChinese(rawResult.value) : null)

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

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function handleFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    form.input = arrayBufferToHex(e.target.result)
    form.format = 'hex'
    ElMessage.success('流量包文件上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

async function run() {
  if (!form.input.trim()) {
    ElMessage.warning('请先上传文件或输入 IPSec / IKE 报文')
    return
  }
  loading.value = true
  try {
    rawResult.value = await api.post('/ipsec/parse', { ...form })
  } finally {
    loading.value = false
  }
}

function clear() {
  form.input = ''
  form.format = 'hex'
  form.srcIp = ''
  form.dstIp = ''
  rawResult.value = null
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
</style>
