<template>
  <el-card>
    <div class="page-title">UKey 流量包解析工作区</div>
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
              <div class="el-upload__text">点击或拖拽文件到区域上传</div>
            </el-upload>
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="UKey 报文">
            <el-input
              v-model="form.input"
              type="textarea"
              :rows="6"
              placeholder="UKey 通信报文十六进制（hex），为空时可上传流量包文件"
            />
          </el-form-item>
        </el-col>
      </el-row>

      <el-row :gutter="20">
        <el-col :span="12">
          <el-form-item label="UKey 厂商">
            <el-select v-model="form.vendor" placeholder="请选择 UKey 厂商" style="width: 100%" filterable>
              <el-option
                v-for="item in vendorOptions"
                :key="item.value"
                :label="item.label"
                :value="item.value"
              />
            </el-select>
          </el-form-item>
        </el-col>
        <el-col :span="12">
          <el-form-item label="公钥/证书格式">
            <el-radio-group v-model="form.keyCertMode">
              <el-radio-button value="hex">HEX</el-radio-button>
              <el-radio-button value="base64">Base64</el-radio-button>
            </el-radio-group>
          </el-form-item>
        </el-col>
      </el-row>

      <el-form-item label="公钥/证书内容">
        <el-input
          v-model="form.keyCertInput"
          type="textarea"
          :rows="4"
          placeholder="可选：输入随流量包使用的公钥或 X.509 证书，用于辅助解析"
        />
      </el-form-item>

      <el-form-item>
        <div class="btn-row">
          <el-button native-type="button" type="primary" :loading="loading" @click="run">解析</el-button>
          <el-button native-type="button" @click="clear">清空</el-button>
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

const vendorOptions = [
  { label: '符合 GM/T 0017 标准规范', value: 'GM/T 0017' },
  { label: '飞天诚信 ePass', value: '飞天诚信' },
  { label: '天地融 WatchData', value: '天地融' },
  { label: '握奇 WatchKEY', value: '握奇' },
  { label: '华大电子', value: '华大电子' },
  { label: '国民技术', value: '国民技术' },
  { label: '东软', value: '东软' },
  { label: '同方微电子', value: '同方微电子' },
  { label: '中电华大', value: '中电华大' },
  { label: '上海复旦', value: '上海复旦' },
  { label: '芯邦', value: '芯邦' },
  { label: '其他厂商', value: '其他' }
]

const CN_MAP = {
  vendor: 'UKey 厂商',
  fileName: '文件名',
  fileSize: '文件大小（字节）',
  fileHexPreview: '文件 Hex 预览',
  keyCertInfo: '公钥/证书信息',
  apduPackets: 'APDU 包列表',
  note: '备注',
  index: '序号',
  offset: '偏移量',
  length: '长度',
  raw: '原始数据',
  totalBytes: '总字节数',
  apduType: 'APDU 类型',
  CLA: 'CLA',
  INS: 'INS',
  P1: 'P1',
  P2: 'P2',
  Lc: 'Lc',
  Data: 'Data',
  Le: 'Le',
  case: 'APDU 情形',
  SW1: 'SW1',
  SW2: 'SW2',
  statusWord: '状态字',
  success: '是否成功',
  consumedBytes: '消费字节数',
  truncated: '是否截断',
  type: '类型',
  subject: '主题',
  issuer: '颁发者',
  serialNumber: '序列号',
  notBefore: '生效时间',
  notAfter: '过期时间',
  sigAlgName: '签名算法',
  publicKeyAlgorithm: '公钥算法',
  derLength: 'DER 长度',
  algorithm: '算法',
  format: '格式',
  encodedLength: '编码长度',
  error: '错误信息'
}

const form = reactive({
  input: '',
  vendor: 'GM/T 0017',
  keyCertInput: '',
  keyCertMode: 'hex'
})
const currentFile = ref(null)
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

function hexToArrayBuffer(hex) {
  const s = hex.replace(/\s+/g, '')
  if (!s || s.length % 2 !== 0) return null
  const bytes = new Uint8Array(s.length / 2)
  for (let i = 0; i < s.length; i += 2) {
    bytes[i / 2] = parseInt(s.substring(i, i + 2), 16)
  }
  return bytes.buffer
}

function handleFileChange(file) {
  currentFile.value = file.raw
  const reader = new FileReader()
  reader.onload = (e) => {
    form.input = arrayBufferToHex(e.target.result)
    ElMessage.success('流量包文件上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

async function run() {
  let uploadFile = currentFile.value
  if (!uploadFile && form.input.trim()) {
    const buf = hexToArrayBuffer(form.input)
    if (!buf) {
      ElMessage.warning('UKey 报文不是有效十六进制')
      return
    }
    uploadFile = new File([buf], 'ukey-traffic.bin', { type: 'application/octet-stream' })
  }
  if (!uploadFile) {
    ElMessage.warning('请先上传流量包文件或输入 UKey 报文')
    return
  }

  const data = new FormData()
  data.append('vendor', form.vendor)
  data.append('file', uploadFile)
  if (form.keyCertInput.trim()) {
    data.append('keyCertInput', form.keyCertInput.trim())
    data.append('keyCertMode', form.keyCertMode)
  }

  loading.value = true
  try {
    rawResult.value = await api.post('/ukey/traffic/parse', data, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
  } finally {
    loading.value = false
  }
}

function clear() {
  form.input = ''
  form.vendor = 'GM/T 0017'
  form.keyCertInput = ''
  form.keyCertMode = 'hex'
  currentFile.value = null
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
