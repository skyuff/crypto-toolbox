<template>
  <el-card>
    <el-form label-width="96px" class="crypto-form">
      <!-- 算法选择 -->
      <el-form-item label="算法选择">
        <el-radio-group v-model="form.algorithm">
          <el-radio-button v-for="a in algorithms" :key="a" :value="a">{{ a }}</el-radio-button>
        </el-radio-group>
      </el-form-item>

      <!-- 加密模式 -->
      <el-form-item label="加密模式">
        <el-radio-group v-model="form.mode">
          <el-radio-button v-for="m in modes" :key="m" :value="m">{{ m }}</el-radio-button>
        </el-radio-group>
      </el-form-item>

      <!-- 填充方式 -->
      <el-form-item label="填充方式">
        <el-radio-group v-model="form.padding" :disabled="isStreamLike">
          <el-radio-button v-for="p in paddings" :key="p.value" :value="p.value">{{ p.label }}</el-radio-button>
        </el-radio-group>
      </el-form-item>

      <el-row :gutter="20">
        <!-- 输入文本 -->
        <el-col :span="12">
          <el-form-item label="输入文本">
            <div class="field-head">
              <el-radio-group v-model="form.inputFormat" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <span class="count">{{ byteLen(form.input, form.inputFormat) }} 字节</span>
            </div>
            <el-input v-model="form.input" type="textarea" :rows="5" placeholder="请输入待处理的数据" />
          </el-form-item>
        </el-col>

        <!-- 密文文本 -->
        <el-col :span="12">
          <el-form-item label="密文文本">
            <div class="field-head">
              <el-radio-group v-model="form.outputFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <span class="count">
                {{ byteLen(form.cipher, form.outputFormat) }} 字节
                <el-button link type="primary" size="small" @click="copy(form.cipher)">复制</el-button>
              </span>
            </div>
            <el-input v-model="form.cipher" type="textarea" :rows="5" placeholder="请输入密文数据" />
          </el-form-item>
        </el-col>
      </el-row>

      <el-row :gutter="20">
        <!-- 密钥 -->
        <el-col :span="12">
          <el-form-item label="密钥">
            <div class="field-head">
              <el-radio-group v-model="form.keyFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <span class="count">{{ byteLen(form.key, form.keyFormat) }} 字节</span>
            </div>
            <div class="with-btn">
              <el-input v-model="form.key" :placeholder="`请输入 ${expectedKeyLen} 字节的密钥`" />
              <el-button @click="genKey">生成密钥</el-button>
            </div>
          </el-form-item>
        </el-col>

        <!-- IV -->
        <el-col :span="12">
          <el-form-item label="IV">
            <div class="field-head">
              <el-radio-group v-model="form.ivFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <span class="count">{{ byteLen(form.iv, form.ivFormat) }} 字节</span>
            </div>
            <div class="with-btn">
              <el-input v-model="form.iv" :disabled="form.mode === 'ECB'" placeholder="请输入 16 字节的 IV" />
              <el-button :disabled="form.mode === 'ECB'" @click="genIv">生成 IV</el-button>
            </div>
          </el-form-item>
        </el-col>
      </el-row>

      <el-form-item>
        <el-button type="primary" :loading="loading" @click="encrypt">加 密</el-button>
        <el-button type="success" :loading="loading" @click="decrypt">解 密</el-button>
        <el-button @click="trimSpace">清理空格和换行</el-button>
        <el-button type="danger" plain @click="clearAll">清 空</el-button>
      </el-form-item>

      <el-form-item label="详情" v-if="detail">
        <el-text type="info">{{ detail }}</el-text>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const algorithms = ['SM4', 'AES-128', 'AES-192', 'AES-256', 'DES', '3DES-2KEY', '3DES-3KEY']
const modes = ['ECB', 'CBC', 'CTR', 'OFB', 'CFB', 'XTS']
const paddings = [
  { label: 'PKCS7', value: 'PKCS7' },
  { label: 'ISO10126', value: 'ISO10126' },
  { label: 'ISO7816-4', value: 'ISO7816-4' },
  { label: 'ANSI X9.23', value: 'ANSI X9.23' },
  { label: 'ZERO', value: 'ZERO' },
  { label: 'NO PADDING', value: 'NO PADDING' }
]

const form = reactive({
  algorithm: 'SM4',
  mode: 'CBC',
  padding: 'PKCS7',
  key: '0123456789abcdeffedcba9876543210',
  keyFormat: 'hex',
  iv: '000102030405060708090a0b0c0d0e0f',
  ivFormat: 'hex',
  input: 'hello world',
  inputFormat: 'utf8',
  cipher: '',
  outputFormat: 'hex'
})

const detail = ref('')
const loading = ref(false)

// 流式模式（CTR/OFB/CFB）无需填充
const isStreamLike = computed(() => ['CTR', 'OFB', 'CFB'].includes(form.mode))

// 各算法期望的密钥字节数（XTS 为双倍）
const expectedKeyLen = computed(() => {
  const base = {
    'SM4': 16, 'AES-128': 16, 'AES-192': 24, 'AES-256': 32,
    'DES': 8, '3DES-2KEY': 16, '3DES-3KEY': 24
  }[form.algorithm] || 16
  return form.mode === 'XTS' ? base * 2 : base
})

watch(() => form.mode, (m) => {
  if (m === 'ECB') form.iv = ''
  if (m === 'XTS') form.padding = 'NO PADDING'
})

// 计算不同编码下的字节数
function byteLen(str, fmt) {
  if (!str) return 0
  try {
    if (fmt === 'hex') return Math.floor(str.replace(/[\s:]/g, '').length / 2)
    if (fmt === 'base64') return atob(str.trim()).length
    return new TextEncoder().encode(str).length
  } catch {
    return 0
  }
}

function randHex(bytes) {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  return Array.from(arr).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function genKey() {
  form.keyFormat = 'hex'
  form.key = randHex(expectedKeyLen.value)
  ElMessage.success(`已生成 ${expectedKeyLen.value} 字节密钥`)
}

function genIv() {
  form.ivFormat = 'hex'
  form.iv = randHex(16)
  ElMessage.success('已生成 16 字节 IV')
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}

function trimSpace() {
  form.input = form.input.replace(/\s/g, '')
  form.cipher = form.cipher.replace(/\s/g, '')
  form.key = form.key.replace(/\s/g, '')
  form.iv = form.iv.replace(/\s/g, '')
}

function clearAll() {
  form.input = ''
  form.cipher = ''
  detail.value = ''
}

async function encrypt() {
  loading.value = true
  try {
    const r = await api.post('/symmetric/block', {
      operation: 'encrypt',
      algorithm: form.algorithm,
      mode: form.mode,
      padding: form.padding,
      key: form.key,
      keyFormat: form.keyFormat,
      iv: form.iv,
      ivFormat: form.ivFormat,
      input: form.input,
      inputFormat: form.inputFormat,
      outputFormat: form.outputFormat
    })
    form.cipher = r.output
    detail.value = `transformation = ${r.transformation}，输出 ${r.outputLength} 字节`
    ElMessage.success('加密成功')
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || '加密失败')
  } finally {
    loading.value = false
  }
}

async function decrypt() {
  loading.value = true
  try {
    const r = await api.post('/symmetric/block', {
      operation: 'decrypt',
      algorithm: form.algorithm,
      mode: form.mode,
      padding: form.padding,
      key: form.key,
      keyFormat: form.keyFormat,
      iv: form.iv,
      ivFormat: form.ivFormat,
      input: form.cipher,
      inputFormat: form.outputFormat,
      outputFormat: form.inputFormat
    })
    form.input = r.output
    detail.value = `transformation = ${r.transformation}，输出 ${r.outputLength} 字节`
    ElMessage.success('解密成功')
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || '解密失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.crypto-form { max-width: 1100px; }
.field-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  margin-bottom: 6px;
}
.field-head .count { color: #909399; font-size: 12px; }
.with-btn { display: flex; gap: 8px; width: 100%; }
.with-btn .el-input { flex: 1; }
</style>
