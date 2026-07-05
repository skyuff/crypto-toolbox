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
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="SSH 报文">
            <el-input
              v-model="form.input"
              type="textarea"
              :rows="6"
              placeholder="可输入 SSH banner 文本（如 SSH-2.0-OpenSSH_8.9p1）或十六进制/UTF8 报文"
            />
          </el-form-item>
        </el-col>
      </el-row>

      <el-row :gutter="20">
        <el-col :span="8">
          <el-form-item label="源 IP">
            <el-input v-model="form.srcIp" placeholder="0.0.0.0" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item label="目标 IP">
            <el-input v-model="form.dstIp" placeholder="0.0.0.0" />
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item label="目标端口">
            <el-input v-model.number="form.dstPort" placeholder="22" />
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
  dstPort: '目标端口',
  totalBytes: '总字节数',
  kind: '报文类型',
  identificationString: '标识串',
  protoVersion: '协议版本',
  softwareVersion: '软件版本',
  comments: '注释',
  note: '备注',
  packetLength: '包长度',
  paddingLength: '填充长度',
  payloadLength: '载荷长度',
  messageCode: '消息码',
  kexInit: '密钥交换初始化',
  cookie: '随机 Cookie',
  kex_algorithms: '密钥交换算法',
  server_host_key_algorithms: '服务器主机密钥算法',
  encryption_algorithms_client_to_server: '客户端到服务端加密算法',
  encryption_algorithms_server_to_client: '服务端到客户端加密算法',
  mac_algorithms_client_to_server: '客户端到服务端 MAC 算法',
  mac_algorithms_server_to_client: '服务端到客户端 MAC 算法',
  compression_algorithms_client_to_server: '客户端到服务端压缩算法',
  compression_algorithms_server_to_client: '服务端到客户端压缩算法',
  languages_client_to_server: '客户端到服务端语言',
  languages_server_to_client: '服务端到客户端语言',
  firstKexPacketFollows: '首个 KEX 包紧随其后',
  reserved: '保留字段',
  truncated: '数据截断'
}

const form = reactive({
  input: '',
  format: 'hex',
  srcIp: '',
  dstIp: '',
  dstPort: 22
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
    ElMessage.warning('请先上传文件或输入 SSH 报文')
    return
  }
  loading.value = true
  try {
    const payload = { ...form }
    if (typeof payload.input === 'string' && payload.input.trim().startsWith('SSH-')) {
      payload.format = 'utf8'
    }
    rawResult.value = await api.post('/ssh/parse', payload)
  } finally {
    loading.value = false
  }
}

function clear() {
  form.input = ''
  form.format = 'hex'
  form.srcIp = ''
  form.dstIp = ''
  form.dstPort = 22
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
