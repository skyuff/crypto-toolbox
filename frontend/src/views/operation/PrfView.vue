<template>
  <el-card>
    <div class="page-title">伪随机函数 PRF</div>

    <el-alert
      type="info"
      :closable="false"
      style="margin-bottom: 20px"
      title="TLS 1.2 PRF：PRF(secret, label, seed) = P_hash(secret, label || seed)，用于握手密钥派生。"
    />

    <el-form label-position="top">
      <!-- 摘要算法 -->
      <el-form-item label="摘要算法">
        <el-radio-group v-model="form.hash" size="small" class="hash-group">
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

      <!-- Key / Seed -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="Key">
            <div class="format-row">
              <el-radio-group v-model="form.secretFormat" size="small">
                <el-radio-button value="string">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.secret, form.secretFormat) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.secret)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.secret"
              type="textarea"
              :rows="5"
              placeholder="请输入 Key"
            />
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="Seed">
            <div class="format-row">
              <el-radio-group v-model="form.seedFormat" size="small">
                <el-radio-button value="string">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.seed, form.seedFormat) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.seed)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.seed"
              type="textarea"
              :rows="5"
              placeholder="请输入 Seed"
            />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- Label / 迭代轮数 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="18">
          <el-form-item label="Label（字符串）">
            <el-input v-model="form.label" placeholder="请输入 Label" />
          </el-form-item>
        </el-col>
        <el-col :xs="24" :md="6">
          <el-form-item label="迭代轮数">
            <el-input-number v-model="form.iterations" :min="1" :max="256" :precision="0" style="width: 100%" />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 输出结果 -->
      <el-form-item label="输出结果">
        <div class="format-row">
          <el-radio-group v-model="form.formatOut" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <div class="data-actions">
            <el-tag size="small" type="info">{{ resultByteCount }} 字节</el-tag>
            <el-button size="small" :icon="DocumentCopy" @click="copy(resultText)">复制</el-button>
          </div>
        </div>
        <el-input
          v-model="resultText"
          type="textarea"
          :rows="5"
          readonly
          placeholder="结果将显示在这里"
        />
      </el-form-item>

      <!-- 操作按钮 -->
      <el-form-item>
        <div class="btn-row">
          <el-button native-type="button" type="primary" :loading="loading" @click="run">执行 PRF</el-button>
          <el-button native-type="button" @click="cleanWhitespace">清理空格和换行</el-button>
          <el-button native-type="button" @click="clearAll">清空</el-button>
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
  secret: '',
  seed: '',
  label: 'master secret',
  iterations: 4,
  hash: 'SHA-256',
  secretFormat: 'hex',
  seedFormat: 'hex',
  formatOut: 'hex'
})

const loading = ref(false)
const result = ref(null)

const resultText = computed(() => {
  if (!result.value) return ''
  return result.value.output
})

const resultByteCount = computed(() => {
  return result.value ? result.value.byteLength : 0
})

function byteCount(value, format) {
  if (!value) return 0
  if (format === 'hex') {
    const s = value.replace(/\s+/g, '').replace(/^0x/i, '')
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
  // string / utf8
  return new Blob([value]).size
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace() {
  form.secret = form.secret.replace(/\s+/g, '')
  form.seed = form.seed.replace(/\s+/g, '')
}

function clearAll() {
  form.secret = ''
  form.seed = ''
  form.label = 'master secret'
  form.iterations = 4
  form.hash = 'SHA-256'
  form.secretFormat = 'hex'
  form.seedFormat = 'hex'
  form.formatOut = 'hex'
  result.value = null
}

async function run() {
  if (!form.secret.trim()) {
    ElMessage.warning('请输入 Key')
    return
  }
  if (!form.seed.trim()) {
    ElMessage.warning('请输入 Seed')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/prf/compute', { ...form })
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
.hash-group {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}
.hash-group :deep(.el-radio-button__inner) {
  padding: 5px 12px;
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
