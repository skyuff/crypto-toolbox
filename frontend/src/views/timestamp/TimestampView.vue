<template>
  <el-card>
    <div class="page-title">时间戳解析与验证</div>

    <el-tabs v-model="activeTab" type="card">
      <el-tab-pane label="时间戳解析" name="parse">
        <el-form label-position="top">
          <el-form-item label="时间戳令牌数据">
            <div class="format-row">
              <el-radio-group v-model="parseForm.format" size="small">
                <el-radio-button value="hex">Hex</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ parseByteCount }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(parseForm.input)">复制</el-button>
                <el-upload action="#" :auto-upload="false" :on-change="handleParseFile" :show-file-list="false" style="display: inline-block">
                  <el-button size="small" :icon="Upload">上传令牌文件</el-button>
                </el-upload>
              </div>
            </div>
            <el-input
              v-model="parseForm.input"
              type="textarea"
              :rows="6"
              placeholder="请输入时间戳令牌数据，或上传令牌文件"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              支持 RFC 3161 与 GB/T 33000-2014 时间戳令牌格式。
            </div>
          </el-form-item>

          <el-form-item>
            <div class="btn-row">
              <el-button native-type="button" type="primary" :loading="parseLoading" @click="runParse">解析时间戳</el-button>
              <el-button native-type="button" @click="cleanWhitespace(parseForm)">清理空格和换行</el-button>
              <el-button native-type="button" @click="clearParse">清空</el-button>
            </div>
          </el-form-item>
        </el-form>

        <div v-if="parseResult" class="result-section">
          <div class="section-title">解析结果</div>
          <JsonView :data="toChinese(parseResult)" />
        </div>
      </el-tab-pane>

      <el-tab-pane label="时间戳验证" name="verify">
        <el-form label-position="top">
          <el-form-item label="时间戳令牌数据">
            <div class="format-row">
              <el-radio-group v-model="verifyForm.format" size="small">
                <el-radio-button value="hex">Hex</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ verifyTokenByteCount }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(verifyForm.input)">复制</el-button>
                <el-upload action="#" :auto-upload="false" :on-change="handleVerifyTokenFile" :show-file-list="false" style="display: inline-block">
                  <el-button size="small" :icon="Upload">上传令牌文件</el-button>
                </el-upload>
              </div>
            </div>
            <el-input
              v-model="verifyForm.input"
              type="textarea"
              :rows="5"
              placeholder="请输入时间戳令牌数据"
            />
            <div class="hint warn">
              <el-icon><InfoFilled /></el-icon>
              用于验证消息摘要是否与原始数据一致。
            </div>
          </el-form-item>

          <el-form-item label="原始数据">
            <div class="format-row">
              <el-radio-group v-model="verifyForm.originalFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
                <el-radio-button value="utf8">字符串</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ verifyOriginalByteCount }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(verifyForm.originalInput)">复制</el-button>
                <el-upload action="#" :auto-upload="false" :on-change="handleVerifyOriginalFile" :show-file-list="false" style="display: inline-block">
                  <el-button size="small" :icon="Upload">上传原始文件</el-button>
                </el-upload>
              </div>
            </div>
            <el-input
              v-model="verifyForm.originalInput"
              type="textarea"
              :rows="5"
              placeholder="请输入原始数据，或上传原始文件"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              请填写生成时间戳时使用的原始数据。
            </div>
          </el-form-item>

          <el-form-item>
            <div class="btn-row">
              <el-button native-type="button" type="primary" :loading="verifyLoading" @click="runVerify">验证时间戳</el-button>
              <el-button native-type="button" @click="cleanWhitespace(verifyForm)">清理空格和换行</el-button>
              <el-button native-type="button" @click="clearVerify">清空</el-button>
            </div>
          </el-form-item>
        </el-form>

        <div v-if="verifyResult" class="result-section">
          <div class="section-title">验证结果</div>
          <JsonView :data="toChinese(verifyResult)" />
        </div>
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { Upload, DocumentCopy, InfoFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'
import JsonView from '../../components/JsonView.vue'

const activeTab = ref('parse')

const CN_MAP = {
  status: '状态码',
  statusString: '状态字符串',
  statusText: '状态说明',
  message: '提示信息',
  genTime: '生成时间',
  serialNumber: '序列号',
  tsaPolicyId: 'TSA 策略 OID',
  hashAlgorithm: '摘要算法 OID',
  digestAlgorithm: '摘要算法 OID',
  messageImprint: '消息摘要',
  tsaName: 'TSA 名称',
  accuracy: '精度',
  nonce: '随机数',
  ordering: '是否要求顺序',
  signerCertCount: '签名证书数量',
  certificates: '签名证书列表',
  subject: '主题',
  issuer: '颁发者',
  verified: '验证结果',
  verifyMessage: '验证说明',
  expectedMessageImprint: '时间戳中的摘要',
  actualMessageImprint: '原始数据计算摘要',
  originalBytes: '原始数据字节数'
}

const parseForm = reactive({
  input: '',
  format: 'hex'
})
const verifyForm = reactive({
  input: '',
  format: 'hex',
  originalInput: '',
  originalFormat: 'utf8'
})

const parseResult = ref(null)
const verifyResult = ref(null)
const parseLoading = ref(false)
const verifyLoading = ref(false)

function byteCountOf(value, format) {
  if (!value) return 0
  if (format === 'hex') {
    const s = value.replace(/\s+/g, '')
    return Math.floor(s.length / 2)
  }
  if (format === 'base64') {
    try {
      const s = value.replace(/\s+/g, '')
      return Math.floor(atob(s).length)
    } catch (e) {
      return 0
    }
  }
  return new Blob([value]).size
}

const parseByteCount = computed(() => byteCountOf(parseForm.input, parseForm.format))
const verifyTokenByteCount = computed(() => byteCountOf(verifyForm.input, verifyForm.format))
const verifyOriginalByteCount = computed(() => byteCountOf(verifyForm.originalInput, verifyForm.originalFormat))

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function handleParseFile(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    parseForm.format = 'hex'
    parseForm.input = arrayBufferToHex(e.target.result)
    ElMessage.success('令牌文件上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

function handleVerifyTokenFile(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    verifyForm.format = 'hex'
    verifyForm.input = arrayBufferToHex(e.target.result)
    ElMessage.success('令牌文件上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

function handleVerifyOriginalFile(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    verifyForm.originalFormat = 'hex'
    verifyForm.originalInput = arrayBufferToHex(e.target.result)
    ElMessage.success('原始文件上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace(form) {
  form.input = form.input.replace(/\s+/g, '')
  if (form.originalInput !== undefined) {
    form.originalInput = form.originalInput.replace(/\s+/g, '')
  }
}

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

async function runParse() {
  if (!parseForm.input.trim()) {
    ElMessage.warning('请输入时间戳令牌数据')
    return
  }
  parseLoading.value = true
  try {
    parseResult.value = await api.post('/timestamp/parse', { ...parseForm })
  } finally {
    parseLoading.value = false
  }
}

async function runVerify() {
  if (!verifyForm.input.trim()) {
    ElMessage.warning('请输入时间戳令牌数据')
    return
  }
  if (!verifyForm.originalInput.trim()) {
    ElMessage.warning('请输入原始数据')
    return
  }
  verifyLoading.value = true
  try {
    verifyResult.value = await api.post('/timestamp/verify', { ...verifyForm })
  } finally {
    verifyLoading.value = false
  }
}

function clearParse() {
  parseForm.input = ''
  parseForm.format = 'hex'
  parseResult.value = null
}

function clearVerify() {
  verifyForm.input = ''
  verifyForm.format = 'hex'
  verifyForm.originalInput = ''
  verifyForm.originalFormat = 'utf8'
  verifyResult.value = null
}
</script>

<style scoped>
.page-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 20px;
}
.format-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}
.data-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.hint {
  margin-top: 8px;
  color: #909399;
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 4px;
}
.hint.warn {
  color: #f56c6c;
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
