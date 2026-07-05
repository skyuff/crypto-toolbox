<template>
  <el-card>
    <div class="title">MAC 算法</div>

    <!-- 算法选择 -->
    <div class="label">算法选择</div>
    <el-radio-group v-model="algorithm">
      <el-radio-button v-for="a in algorithms" :key="a" :value="a">{{ a }}</el-radio-button>
    </el-radio-group>

    <!-- MAC 模式 -->
    <div class="label" style="margin-top: 16px">MAC 模式</div>
    <el-radio-group v-model="type" class="wrap">
      <el-radio-button v-for="m in modes" :key="m" :value="m">{{ m }}</el-radio-button>
    </el-radio-group>

    <el-row :gutter="24" style="margin-top: 16px">
      <!-- 消息 -->
      <el-col :span="12">
        <div class="label"><span class="req">*</span> 消息</div>
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

      <!-- MAC 结果 -->
      <el-col :span="12">
        <div class="label">MAC 结果</div>
        <div class="row">
          <el-radio-group v-model="resultFormat" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <el-radio-group v-model="macSize" size="small" style="margin-left: 8px">
            <el-radio-button :value="8">8字节</el-radio-button>
            <el-radio-button :value="12">12字节</el-radio-button>
            <el-radio-button :value="16">16字节</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <span class="bytes">{{ resultBytes }} 字节</span>
          <el-button size="small" @click="copy(resultText)">复制</el-button>
        </div>
        <el-input v-model="resultText" type="textarea" :rows="5" readonly />
      </el-col>
    </el-row>

    <!-- 填充模式 -->
    <div class="label" style="margin-top: 16px"><span class="req">*</span> 填充模式</div>
    <el-radio-group v-model="padding" class="wrap">
      <el-radio-button value="method1">GB/T17964-2021 附录C.2 填充方式一</el-radio-button>
      <el-radio-button value="method2">GB/T17964-2021 附录C.3 填充方式二</el-radio-button>
      <el-radio-button value="method3">GB/T17964-2021 附录C.4 填充方式三</el-radio-button>
    </el-radio-group>

    <!-- 密钥一 -->
    <div class="label" style="margin-top: 16px"><span class="req">*</span> 密钥一</div>
    <div class="row">
      <el-radio-group v-model="keyFormat" size="small">
        <el-radio-button value="hex">十六进制</el-radio-button>
        <el-radio-button value="base64">Base64</el-radio-button>
      </el-radio-group>
    </div>
    <div class="row">
      <el-input v-model="key" placeholder="密钥">
        <template #suffix>{{ byteLen(key, keyFormat) }}</template>
      </el-input>
      <el-button style="margin-left: 8px" @click="genKey">生成密钥</el-button>
    </div>

    <!-- 按钮 -->
    <div class="actions">
      <el-button :loading="loading" @click="compute">计算 MAC</el-button>
      <el-button type="primary" @click="clean">清理空格和换行</el-button>
      <el-button type="danger" plain @click="clear">清空</el-button>
    </div>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const algorithms = ['SM4', 'AES-128', 'AES-192', 'AES-256']
const modes = ['CBC-MAC', 'CMAC', 'EMAC', 'ANSI-retail-MAC', 'MacDES', 'LMAC', 'CBCR', 'TrCBC']

const algorithm = ref('SM4')
const type = ref('CBC-MAC')
const padding = ref('method1')
const macSize = ref(16)
const input = ref('')
const inputFormat = ref('utf8')
const key = ref('')
const keyFormat = ref('hex')
const resultFormat = ref('hex')
const loading = ref(false)

const result = reactive({ hex: '', base64: '' })
const resultText = computed(() => resultFormat.value === 'base64' ? result.base64 : result.hex)
const resultBytes = computed(() => Math.floor((result.hex || '').length / 2))

const keyBytes = computed(() => {
  if (algorithm.value.includes('192')) return 24
  if (algorithm.value.includes('256')) return 32
  return 16
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

function genKey() {
  const bytes = new Uint8Array(keyBytes.value)
  crypto.getRandomValues(bytes)
  if (keyFormat.value === 'base64') {
    key.value = btoa(String.fromCharCode(...bytes))
  } else {
    key.value = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
  }
}

async function compute() {
  if (!key.value) { ElMessage.warning('请填写密钥'); return }
  loading.value = true
  try {
    const r = await api.post('/hash/mac', {
      type: type.value,
      algorithm: algorithm.value,
      padding: padding.value,
      macSize: macSize.value,
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
  key.value = key.value.replace(/[\s\r\n]/g, '')
}

function clear() {
  input.value = ''
  key.value = ''
  result.hex = ''
  result.base64 = ''
}
</script>

<style scoped>
.title { font-size: 16px; font-weight: 600; margin-bottom: 16px; }
.label { font-size: 13px; color: #333; margin-bottom: 8px; }
.req { color: #f56c6c; margin-right: 2px; }
.wrap { flex-wrap: wrap; }
.row { display: flex; align-items: center; margin-bottom: 8px; }
.spacer { flex: 1; }
.bytes { color: #409eff; font-size: 12px; margin-right: 8px; }
.actions { margin-top: 20px; text-align: center; }
.actions .el-button { margin: 0 6px; }
</style>
