<template>
  <el-card>
    <div class="page-title">大数运算</div>

    <el-row :gutter="24">
      <!-- 数据 A -->
      <el-col :xs="24" :md="12">
        <el-form label-position="top">
          <el-form-item label="数据 A">
            <div class="format-row">
              <el-radio-group v-model="form.formatA" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCountA }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.a)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.a"
              type="textarea"
              :rows="6"
              placeholder="请输入数据 A"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              还没想好要提示些什么？
            </div>
          </el-form-item>
        </el-form>
      </el-col>

      <!-- 数据 B -->
      <el-col :xs="24" :md="12">
        <el-form label-position="top">
          <el-form-item label="数据 B">
            <div class="format-row">
              <el-radio-group v-model="form.formatB" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCountB }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.b)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.b"
              type="textarea"
              :rows="6"
              placeholder="请输入数据 B"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              还没想好要提示些什么？
            </div>
          </el-form-item>
        </el-form>
      </el-col>
    </el-row>

    <!-- 结果输出 -->
    <el-form label-position="top" class="result-form">
      <el-form-item label="结果输出">
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
        <div class="hint">
          <el-icon><InfoFilled /></el-icon>
          还没想好要提示些什么？
        </div>
      </el-form-item>
    </el-form>

    <!-- 操作按钮 -->
    <div class="btn-row">
      <el-button native-type="button" type="primary" :loading="loading" @click="calc('add')">A + B</el-button>
      <el-button native-type="button" type="primary" :loading="loading" @click="calc('sub')">A - B</el-button>
      <el-button native-type="button" type="primary" :loading="loading" @click="calc('mul')">A * B</el-button>
      <el-button native-type="button" @click="cleanWhitespace">清理空格和换行</el-button>
      <el-button native-type="button" @click="clearAll">清空</el-button>
    </div>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { DocumentCopy, InfoFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const form = reactive({
  a: '',
  b: '',
  formatA: 'hex',
  formatB: 'hex',
  formatOut: 'hex'
})

const loading = ref(false)
const result = ref(null)

const resultText = computed(() => {
  if (!result.value) return ''
  return result.value.result
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

const byteCountA = computed(() => byteCount(form.a, form.formatA))
const byteCountB = computed(() => byteCount(form.b, form.formatB))
const resultByteCount = computed(() => result.value ? result.value.byteLength : 0)

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace() {
  form.a = form.a.replace(/\s+/g, '')
  form.b = form.b.replace(/\s+/g, '')
}

function clearAll() {
  form.a = ''
  form.b = ''
  form.formatA = 'hex'
  form.formatB = 'hex'
  form.formatOut = 'hex'
  result.value = null
}

async function calc(op) {
  if (!form.a.trim()) {
    ElMessage.warning('请输入数据 A')
    return
  }
  if (!form.b.trim()) {
    ElMessage.warning('请输入数据 B')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/bignumber/calc', { ...form, op })
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
.result-form {
  margin-top: 8px;
}
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 8px;
}
</style>
