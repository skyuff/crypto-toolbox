<template>
  <el-card>
    <div class="title">哈希与 HMAC</div>

    <!-- 算法选择 -->
    <div class="label">算法选择</div>
    <el-radio-group v-model="algorithm" size="default" class="algs">
      <el-radio-button v-for="a in algorithms" :key="a" :value="a">{{ a }}</el-radio-button>
    </el-radio-group>

    <el-row :gutter="24" style="margin-top: 16px">
      <!-- 左：输入消息 -->
      <el-col :span="12">
        <div class="label"><span class="req">*</span> 输入消息</div>
        <div class="row">
          <el-radio-group v-model="inputFormat" size="small">
            <el-radio-button value="utf8">字符串</el-radio-button>
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <span class="bytes">{{ byteLen(input, inputFormat) }} 字节</span>
          <el-button size="small" @click="copy(input)">复制</el-button>
        </div>
        <el-input v-model="input" type="textarea" :rows="5" />
      </el-col>

      <!-- 右：结果 -->
      <el-col :span="12">
        <div class="label">哈希 / MAC 结果</div>
        <div class="row">
          <el-radio-group v-model="resultFormat" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <span class="bytes">{{ resultBytes }} 字节</span>
          <el-button size="small" @click="copy(resultText)">复制</el-button>
        </div>
        <el-input v-model="resultText" type="textarea" :rows="5" readonly />
      </el-col>
    </el-row>

    <el-row :gutter="24" style="margin-top: 16px">
      <!-- 左：盐值 -->
      <el-col :span="12">
        <div class="label">盐值</div>
        <div class="row">
          <el-radio-group v-model="saltFormat" size="small">
            <el-radio-button value="utf8">字符串</el-radio-button>
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
        </div>
        <div class="row">
          <el-input v-model="salt" placeholder="可选">
            <template #suffix>{{ byteLen(salt, saltFormat) }}</template>
          </el-input>
          <el-radio-group v-model="saltPosition" size="default" style="margin-left: 8px">
            <el-radio-button value="pre">前置</el-radio-button>
            <el-radio-button value="post">后置</el-radio-button>
          </el-radio-group>
        </div>
      </el-col>

      <!-- 右：HMAC 密钥 -->
      <el-col :span="12">
        <div class="label"><span class="req">*</span> HMAC 密钥</div>
        <div class="row">
          <el-radio-group v-model="keyFormat" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
        </div>
        <div class="row">
          <el-input v-model="key" placeholder="HMAC 密钥">
            <template #suffix>{{ byteLen(key, keyFormat) }}</template>
          </el-input>
          <el-button size="default" style="margin-left: 8px" @click="genKey(16)">128 位密钥</el-button>
          <el-button size="default" @click="genKey(32)">256 位密钥</el-button>
          <el-button size="default" @click="genKey(64)">512 位密钥</el-button>
        </div>
      </el-col>
    </el-row>

    <!-- 迭代次数 -->
    <div class="label" style="margin-top: 16px"><span class="req">*</span> 迭代次数</div>
    <el-input-number v-model="iterations" :min="1" :max="1000000" controls-position="right" style="width: 100%" />

    <!-- 按钮 -->
    <div class="actions">
      <el-button :loading="loading" @click="doHash">计算哈希</el-button>
      <el-button :loading="loading" @click="doHmac">计算 HMAC</el-button>
      <el-button type="primary" @click="clean">清理空格和换行</el-button>
      <el-button type="danger" plain @click="clear">清空</el-button>
    </div>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const algorithms = [
  'SM3', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512',
  'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHA-1', 'MD5'
]

const algorithm = ref('SM3')
const input = ref('')
const inputFormat = ref('utf8')
const salt = ref('')
const saltFormat = ref('utf8')
const saltPosition = ref('pre')
const key = ref('')
const keyFormat = ref('hex')
const iterations = ref(1)
const resultFormat = ref('hex')
const loading = ref(false)

const result = reactive({ hex: '', base64: '' })
const resultText = computed(() => resultFormat.value === 'base64' ? result.base64 : result.hex)
const resultBytes = computed(() => {
  const h = result.hex || ''
  return Math.floor(h.length / 2)
})

function byteLen(str, fmt) {
  if (!str) return 0
  try {
    if (fmt === 'hex') return Math.floor(str.replace(/\s/g, '').length / 2)
    if (fmt === 'base64') {
      const s = str.replace(/\s/g, '')
      return Math.floor(s.replace(/=+$/, '').length * 3 / 4)
    }
    return new TextEncoder().encode(str).length
  } catch { return 0 }
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function genKey(len) {
  const bytes = new Uint8Array(len)
  crypto.getRandomValues(bytes)
  if (keyFormat.value === 'base64') {
    key.value = btoa(String.fromCharCode(...bytes))
  } else {
    key.value = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  }
}

async function doHash() {
  loading.value = true
  try {
    const r = await api.post('/hash/digest', {
      algorithm: algorithm.value,
      input: input.value,
      inputFormat: inputFormat.value,
      salt: salt.value,
      saltFormat: saltFormat.value,
      saltPosition: saltPosition.value,
      iterations: iterations.value
    })
    result.hex = r.hex
    result.base64 = r.base64
  } catch (e) {
    ElMessage.error(e?.message || '计算失败')
  } finally { loading.value = false }
}

async function doHmac() {
  if (!key.value) { ElMessage.warning('请填写 HMAC 密钥'); return }
  loading.value = true
  try {
    const r = await api.post('/hash/mac', {
      type: 'HMAC-' + algorithm.value,
      key: key.value,
      keyFormat: keyFormat.value,
      input: input.value,
      inputFormat: inputFormat.value
    })
    result.hex = r.hex
    result.base64 = r.base64
  } catch (e) {
    ElMessage.error(e?.message || '计算失败')
  } finally { loading.value = false }
}

function clean() {
  input.value = input.value.replace(/[\s\r\n]/g, '')
  salt.value = salt.value.replace(/[\s\r\n]/g, '')
  key.value = key.value.replace(/[\s\r\n]/g, '')
}

function clear() {
  input.value = ''
  salt.value = ''
  key.value = ''
  result.hex = ''
  result.base64 = ''
  iterations.value = 1
}
</script>

<style scoped>
.title { font-size: 16px; font-weight: 600; margin-bottom: 16px; }
.label { font-size: 13px; color: #333; margin-bottom: 8px; }
.req { color: #f56c6c; margin-right: 2px; }
.algs { flex-wrap: wrap; }
.row { display: flex; align-items: center; margin-bottom: 8px; }
.spacer { flex: 1; }
.bytes { color: #409eff; font-size: 12px; margin-right: 8px; }
.actions { margin-top: 20px; text-align: center; }
.actions .el-button { margin: 0 6px; }
</style>
