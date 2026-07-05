<template>
  <el-card>
    <el-form label-width="120px" class="crypto-form">
      <!-- 算法选择 -->
      <el-form-item label="算法选择">
        <el-radio-group v-model="form.algorithm">
          <el-radio-button v-for="a in algorithms" :key="a" :value="a">{{ a }}</el-radio-button>
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
            <el-input v-model="form.input" type="textarea" :rows="5" placeholder="请输入待加密或解密后的消息" />
          </el-form-item>
        </el-col>

        <!-- 密文 -->
        <el-col :span="12">
          <el-form-item label="密文">
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
            <el-input v-model="form.cipher" type="textarea" :rows="5" placeholder="请输入待解密或加密后的密文" />
          </el-form-item>
        </el-col>
      </el-row>

      <el-row :gutter="20">
        <!-- AAD -->
        <el-col :span="12">
          <el-form-item label="附加认证数据(AAD)">
            <div class="field-head">
              <el-radio-group v-model="form.aadFormat" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <span class="count">{{ byteLen(form.aad, form.aadFormat) }} 字节</span>
            </div>
            <el-input v-model="form.aad" placeholder="请输入附加认证数据（可空）" />
          </el-form-item>
        </el-col>

        <!-- 认证标签 Tag -->
        <el-col :span="12">
          <el-form-item label="认证标签(Tag)">
            <div class="field-head">
              <div>
                <el-radio-group v-model="form.tagFormat" size="small">
                  <el-radio-button value="hex">十六进制</el-radio-button>
                  <el-radio-button value="base64">Base64</el-radio-button>
                </el-radio-group>
                <el-radio-group v-model="form.tagLength" size="small" style="margin-left: 8px">
                  <el-radio-button :value="128">16 字节</el-radio-button>
                  <el-radio-button :value="64">8 字节</el-radio-button>
                  <el-radio-button :value="32">4 字节</el-radio-button>
                </el-radio-group>
              </div>
            </div>
            <el-input v-model="form.tag" placeholder="请输入认证标签（解密需填，加密自动生成）" />
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
              <el-input v-model="form.iv" placeholder="请输入 12 字节的 IV" />
              <el-button @click="genIv">生成 IV</el-button>
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
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const algorithms = ['SM4', 'AES-128', 'AES-192', 'AES-256']

const form = reactive({
  algorithm: 'SM4',
  key: '0123456789abcdeffedcba9876543210',
  keyFormat: 'hex',
  iv: '000102030405060708090a0b',
  ivFormat: 'hex',
  aad: '',
  aadFormat: 'hex',
  input: 'hello gcm',
  inputFormat: 'utf8',
  cipher: '',
  outputFormat: 'hex',
  tag: '',
  tagFormat: 'hex',
  tagLength: 128
})

const detail = ref('')
const loading = ref(false)

const keyLen = computed(() => ({ 'SM4': 16, 'AES-128': 16, 'AES-192': 24, 'AES-256': 32 }[form.algorithm] || 16))

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
  form.iv = randHex(12)
  ElMessage.success('已生成 12 字节 IV')
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}

function trimSpace() {
  form.input = form.input.replace(/\s/g, '')
  form.cipher = form.cipher.replace(/\s/g, '')
  form.aad = form.aad.replace(/\s/g, '')
  form.tag = form.tag.replace(/\s/g, '')
  form.key = form.key.replace(/\s/g, '')
  form.iv = form.iv.replace(/\s/g, '')
}

function clearAll() {
  form.input = ''
  form.cipher = ''
  form.tag = ''
  detail.value = ''
}

async function encrypt() {
  loading.value = true
  try {
    const r = await api.post('/symmetric/gcm', {
      operation: 'encrypt',
      algorithm: form.algorithm,
      tagLength: form.tagLength,
      key: form.key, keyFormat: form.keyFormat,
      iv: form.iv, ivFormat: form.ivFormat,
      aad: form.aad, aadFormat: form.aadFormat,
      input: form.input, inputFormat: form.inputFormat,
      outputFormat: form.outputFormat,
      tagFormat: form.tagFormat
    })
    form.cipher = r.output
    form.tag = r.tag
    detail.value = `${r.transformation}，Tag ${r.tagLength} 字节`
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
    const r = await api.post('/symmetric/gcm', {
      operation: 'decrypt',
      algorithm: form.algorithm,
      tagLength: form.tagLength,
      key: form.key, keyFormat: form.keyFormat,
      iv: form.iv, ivFormat: form.ivFormat,
      aad: form.aad, aadFormat: form.aadFormat,
      input: form.cipher, inputFormat: form.outputFormat,
      outputFormat: form.inputFormat,
      tag: form.tag, tagFormat: form.tagFormat
    })
    form.input = r.output
    detail.value = `${r.transformation}，认证校验通过 ✓`
    ElMessage.success('解密成功，认证校验通过')
  } catch (e) {
    ElMessage.error(e?.response?.data?.message || '解密失败或认证校验不通过')
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
