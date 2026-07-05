<template>
  <el-card>
    <div class="page-title">PBKDF 密钥派生</div>

    <el-form label-position="top">
      <!-- 摘要算法 -->
      <el-form-item label="摘要算法">
        <el-radio-group v-model="form.prf" size="small">
          <el-radio-button value="SM3">SM3</el-radio-button>
          <el-radio-button value="SHA-224">SHA-224</el-radio-button>
          <el-radio-button value="SHA-256">SHA-256</el-radio-button>
          <el-radio-button value="SHA-384">SHA-384</el-radio-button>
          <el-radio-button value="SHA-512">SHA-512</el-radio-button>
          <el-radio-button value="SHA3-224">SHA3-224</el-radio-button>
          <el-radio-button value="SHA3-256">SHA3-256</el-radio-button>
          <el-radio-button value="SHA3-384">SHA3-384</el-radio-button>
          <el-radio-button value="SHA3-512">SHA3-512</el-radio-button>
          <el-radio-button value="SHA-1">SHA-1</el-radio-button>
          <el-radio-button value="MD5">MD5</el-radio-button>
        </el-radio-group>
      </el-form-item>

      <!-- 口令 / 盐值 并排 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="口令 Password">
            <div class="format-row">
              <el-radio-group v-model="form.passwordFormat" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.password, form.passwordFormat) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.password)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.password" type="textarea" :rows="4" placeholder="请输入 Password" />
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="盐值 Salt">
            <div class="format-row">
              <el-radio-group v-model="form.saltFormat" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.salt, form.saltFormat) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.salt)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.salt" type="textarea" :rows="4" placeholder="请输入 Salt" />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 迭代次数 / 密钥长度 并排 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="迭代次数">
            <el-input-number v-model="form.iterations" :min="1" :max="10000000" style="width: 100%" />
          </el-form-item>
        </el-col>
        <el-col :xs="24" :md="12">
          <el-form-item label="密钥长度（字节）">
            <el-input-number v-model="form.keyLength" :min="1" :max="512" style="width: 100%" />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 派生密钥 -->
      <el-form-item label="派生密钥">
        <div class="format-row">
          <el-radio-group v-model="form.outputFormat" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <div class="data-actions">
            <el-tag size="small" type="info">{{ resultByteCount }} 字节</el-tag>
            <el-button size="small" :icon="DocumentCopy" @click="copy(resultText)">复制</el-button>
          </div>
        </div>
        <el-input v-model="resultText" type="textarea" :rows="4" readonly placeholder="派生密钥将显示在这里" />
      </el-form-item>

      <!-- 操作按钮 -->
      <el-form-item>
        <div class="btn-row">
          <el-button type="primary" :loading="loading" @click="run">派生密钥</el-button>
          <el-button type="primary" @click="cleanWhitespace">清理空格和换行</el-button>
          <el-button type="primary" @click="clearAll">清空</el-button>
        </div>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { DocumentCopy } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const form = reactive({
  password: '',
  passwordFormat: 'utf8',
  salt: '',
  saltFormat: 'hex',
  iterations: 1024,
  keyLength: 32,
  prf: 'SHA-256',
  outputFormat: 'hex'
})

const result = ref(null)
const loading = ref(false)

const resultText = computed(() => {
  if (!result.value) return ''
  return result.value.key || ''
})

const resultByteCount = computed(() => {
  return result.value ? (result.value.keyLength || 0) : 0
})

function byteCount(value, format) {
  if (!value) return 0
  const fmt = (format || 'utf8').toLowerCase()
  if (fmt === 'base64') {
    try {
      const s = value.replace(/\s+/g, '')
      return Math.floor(atob(s).length)
    } catch (e) {
      return 0
    }
  }
  if (fmt === 'hex') {
    const s = value.replace(/\s+/g, '').replace(/^0x/i, '')
    return Math.floor(s.length / 2)
  }
  // utf8 / string
  return new Blob([value]).size
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace() {
  form.password = form.password.replace(/\s+/g, '')
  form.salt = form.salt.replace(/\s+/g, '')
}

function clearAll() {
  form.password = ''
  form.passwordFormat = 'utf8'
  form.salt = ''
  form.saltFormat = 'hex'
  form.iterations = 1024
  form.keyLength = 32
  form.prf = 'SHA-256'
  form.outputFormat = 'hex'
  result.value = null
}

async function run() {
  if (!form.password.trim()) {
    ElMessage.warning('请输入口令 Password')
    return
  }
  if (!form.salt.trim()) {
    ElMessage.warning('请输入盐值 Salt')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/pbkdf2/derive', form)
  } finally {
    loading.value = false
  }
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
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 8px;
}
</style>
