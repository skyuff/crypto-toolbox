<template>
  <el-card>
    <div class="page-title">密钥派生函数 KDF</div>

    <el-alert
      type="info"
      :closable="false"
      style="margin-bottom: 20px"
      title="GM/T KDF（SM2/SM9 规范）：基于哈希的计数器模式密钥派生，Hai=Hash(Z || counter)。"
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

      <!-- 比特串 Z / 输出结果 1 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="比特串 Z">
            <div class="format-row">
              <el-radio-group v-model="form.zFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.z, form.zFormat) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.z)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.z"
              type="textarea"
              :rows="6"
              placeholder="请输入待派生的共享比特串 Z"
            />
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="输出结果 1">
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
              :rows="6"
              readonly
              placeholder="结果将显示在这里"
            />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 输出长度 -->
      <el-form-item label="输出长度（字节）">
        <el-input-number v-model="form.keyLength" :min="1" :max="1024" :precision="0" style="width: 100%" />
      </el-form-item>

      <!-- 操作按钮 -->
      <el-form-item>
        <div class="btn-row">
          <el-button native-type="button" type="primary" :loading="loading" @click="run">执行 KDF</el-button>
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
  z: '',
  keyLength: 32,
  hash: 'SM3',
  zFormat: 'hex',
  formatOut: 'hex'
})

const loading = ref(false)
const result = ref(null)

const resultText = computed(() => {
  if (!result.value) return ''
  return result.value.key
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
  return 0
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace() {
  form.z = form.z.replace(/\s+/g, '')
}

function clearAll() {
  form.z = ''
  form.keyLength = 32
  form.hash = 'SM3'
  form.zFormat = 'hex'
  form.formatOut = 'hex'
  result.value = null
}

async function run() {
  if (!form.z.trim()) {
    ElMessage.warning('请输入比特串 Z')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/kdf/compute', { ...form })
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
