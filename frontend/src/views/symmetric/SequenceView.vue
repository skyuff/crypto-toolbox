<template>
  <el-card>
    <el-form label-width="96px" class="crypto-form">
      <!-- 算法选择 -->
      <el-form-item label="算法选择">
        <el-radio-group v-model="form.algorithm">
          <el-radio-button value="ZUC-128">ZUC-128</el-radio-button>
          <el-radio-button value="ZUC-256">ZUC-256</el-radio-button>
        </el-radio-group>
      </el-form-item>

      <el-row :gutter="20">
        <!-- 消息 -->
        <el-col :span="12">
          <el-form-item label="消息">
            <div class="field-head">
              <el-radio-group v-model="form.inputFormat" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <span class="count">
                {{ byteLen(form.input, form.inputFormat) }} 字节
                <el-button link type="primary" size="small" @click="copy(form.input)">复制</el-button>
              </span>
            </div>
            <el-input v-model="form.input" type="textarea" :rows="5" placeholder="请输入待处理的消息" />
          </el-form-item>
        </el-col>

        <!-- 密文 / MAC -->
        <el-col :span="12">
          <el-form-item label="密文 / MAC">
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
            <el-input v-model="form.cipher" type="textarea" :rows="5" placeholder="请输入密文或查看 MAC 结果" />
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
              <el-input v-model="form.key" :placeholder="`请输入 ${keyLen} 字节的密钥`" />
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
              <el-input v-model="form.iv" :placeholder="`请输入 ${ivLen} 字节的 IV`" />
              <el-button @click="genIv">生成 IV</el-button>
            </div>
          </el-form-item>
        </el-col>
      </el-row>

      <!-- ZUC-256 MAC 长度 -->
      <el-form-item label="MAC 长度" v-if="form.algorithm === 'ZUC-256'">
        <el-radio-group v-model="form.tagLength">
          <el-radio-button :value="32">32 bit</el-radio-button>
          <el-radio-button :value="64">64 bit</el-radio-button>
          <el-radio-button :value="128">128 bit</el-radio-button>
        </el-radio-group>
        <el-text type="info" style="margin-left: 8px">仅计算 MAC 时生效</el-text>
      </el-form-item>

      <el-form-item>
        <el-button type="primary" :loading="loading" @click="encrypt">加 密</el-button>
        <el-button type="success" :loading="loading" @click="decrypt">解 密</el-button>
        <el-button type="warning" :loading="loading" @click="computeMac">计算 MAC</el-button>
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

const form = reactive({
  algorithm: 'ZUC-128',
  key: '0123456789abcdeffedcba9876543210',
  keyFormat: 'hex',
  iv: '000102030405060708090a0b0c0d0e0f',
  ivFormat: 'hex',
  input: 'hello zuc',
  inputFormat: 'utf8',
  cipher: '',
  outputFormat: 'hex',
  tagLength: 128
})

const detail = ref('')
const loading = ref(false)

// ZUC-128：16 字节密钥 + 16 字节 IV；ZUC-256：32 字节密钥 + 25 字节 IV
const keyLen = computed(() => (form.algorithm === 'ZUC-256' ? 32 : 16))
const ivLen = computed(() => (form.algorithm === 'ZUC-256' ? 25 : 16))

// 切换算法时自动重置默认密钥/IV 到正确长度
watch(() => form.algorithm, () => {
  form.keyFormat = 'hex'
  form.ivFormat = 'hex'
  form.key = randHex(keyLen.value)
  form.iv = randHex(ivLen.value)
})

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
  form.key = randHex(keyLen.value)
  ElMessage.success(`已生成 ${keyLen.value} 字节密钥`)
}

function genIv() {
  form.ivFormat = 'hex'
  form.iv = randHex(ivLen.value)
  ElMessage.success(`已生成 ${ivLen.value} 字节 IV`)
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

function payload(op, input, inputFormat, outputFormat) {
  return {
    operation: op,
    algorithm: form.algorithm,
    key: form.key,
    keyFormat: form.keyFormat,
    iv: form.iv,
    ivFormat: form.ivFormat,
    input,
    inputFormat,
    outputFormat,
    tagLength: form.tagLength
  }
}

async function encrypt() {
  loading.value = true
  try {
    const r = await api.post('/symmetric/stream', payload('encrypt', form.input, form.inputFormat, form.outputFormat))
    form.cipher = r.output
    detail.value = `${r.algorithm} 加密，输出 ${r.outputLength} 字节`
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
    const r = await api.post('/symmetric/stream', payload('decrypt', form.cipher, form.outputFormat, form.inputFormat))
    form.input = r.output
    detail.value = `${r.algorithm} 解密，输出 ${r.outputLength} 字节`
    ElMessage.success('解密成功')
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || '解密失败')
  } finally {
    loading.value = false
  }
}

async function computeMac() {
  loading.value = true
  try {
    const r = await api.post('/symmetric/stream/mac', payload('mac', form.input, form.inputFormat, form.outputFormat))
    form.cipher = r.mac
    detail.value = `${r.algorithm} MAC（${r.macBits} bit / ${r.macLength} 字节）`
    ElMessage.success('MAC 计算成功')
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || 'MAC 计算失败')
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
