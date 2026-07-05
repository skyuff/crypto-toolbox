<template>
  <el-card>
    <div class="page-title">SM2 加密 k 碰撞分析</div>

    <el-form label-position="top">
      <!-- 密文或 C1 部分 / 公钥 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="密文或 C1 部分">
            <div class="format-row">
              <el-radio-group v-model="form.inputFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.input, form.inputFormat) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.input)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.input"
              type="textarea"
              :rows="6"
              placeholder="请输入完整密文，或仅输入 C1 部分"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              适合测试较小范围随机数 k 的碰撞情况。
            </div>
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="公钥">
            <div class="format-row">
              <el-radio-group v-model="form.publicKeyFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.publicKey, form.publicKeyFormat) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.publicKey)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.publicKey"
              type="textarea"
              :rows="6"
              placeholder="请输入用于加密的公钥"
            />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 输出结果 -->
      <el-form-item label="输出结果">
        <div class="format-row">
          <el-radio-group v-model="form.formatOut" size="small">
            <el-radio-button value="string">字符串</el-radio-button>
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
        <div class="hint">
          <el-icon><InfoFilled /></el-icon>
          输入完整 C1C2C3 密文时可尝试恢复明文，仅输入 C1 时通常用于定位随机数 k。
        </div>
      </el-form-item>

      <!-- 操作按钮 -->
      <el-form-item>
        <div class="btn-row">
          <el-button native-type="button" type="primary" :loading="loading" @click="runCollide">碰撞随机数 k</el-button>
          <el-button native-type="button" type="primary" :loading="loading" @click="runRecover">尝试恢复明文</el-button>
          <el-button native-type="button" @click="cleanWhitespace">清理空格和换行</el-button>
          <el-button native-type="button" @click="clearAll">清空</el-button>
        </div>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { DocumentCopy, InfoFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const form = reactive({
  input: '',
  publicKey: '',
  inputFormat: 'hex',
  publicKeyFormat: 'hex',
  formatOut: 'string'
})

const loading = ref(false)
const result = ref(null)
const operation = ref('')

const resultText = computed(() => {
  if (!result.value) return ''
  if (operation.value === 'collide') {
    if (result.value.found) {
      return `k (hex) = ${result.value.k}\nk (decimal) = ${result.value.kDecimal}`
    }
    return result.value.message || '未找到'
  }
  if (operation.value === 'recover') {
    if (result.value.found) {
      return result.value.plaintext
    }
    return result.value.message || '未找到'
  }
  return ''
})

const resultByteCount = computed(() => {
  if (!result.value) return 0
  if (operation.value === 'recover' && result.value.found) {
    return result.value.byteLength || 0
  }
  return 0
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
  form.input = form.input.replace(/\s+/g, '')
  form.publicKey = form.publicKey.replace(/\s+/g, '')
}

function clearAll() {
  form.input = ''
  form.publicKey = ''
  form.inputFormat = 'hex'
  form.publicKeyFormat = 'hex'
  form.formatOut = 'string'
  result.value = null
  operation.value = ''
}

async function runCollide() {
  if (!form.input.trim()) {
    ElMessage.warning('请输入密文或 C1 部分')
    return
  }
  operation.value = 'collide'
  loading.value = true
  try {
    result.value = await api.post('/sm2k/collide', { ...form })
  } finally {
    loading.value = false
  }
}

async function runRecover() {
  if (!form.input.trim()) {
    ElMessage.warning('请输入完整密文')
    return
  }
  if (!form.publicKey.trim()) {
    ElMessage.warning('请输入公钥')
    return
  }
  operation.value = 'recover'
  loading.value = true
  try {
    result.value = await api.post('/sm2k/recover', { ...form })
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
.hint {
  margin-top: 8px;
  color: #909399;
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 4px;
}
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 8px;
}
</style>
