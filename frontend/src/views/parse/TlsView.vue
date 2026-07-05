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
    ElMessage.warning('请先上传文件或输入 TLS 报文')
    return
  }
  loading.value = true
  try {
    rawResult.value = await api.post('/tls/parse', { ...form })
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
