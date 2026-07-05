<template>
  <el-card>
    <div class="page-title">字节逆序</div>

    <el-form label-position="top">
      <!-- 输入数据 -->
      <el-form-item label="输入数据">
        <div class="format-row">
          <el-radio-group v-model="form.format" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <div class="data-actions">
            <el-tag size="small" type="info">{{ byteCount(form.input, form.format) }} 字节</el-tag>
            <el-button size="small" :icon="DocumentCopy" @click="copy(form.input)">复制</el-button>
          </div>
        </div>
        <el-input
          v-model="form.input"
          type="textarea"
          :rows="6"
          placeholder="请输入待逆序的数据"
        />
      </el-form-item>

      <!-- 分组字节数 -->
      <el-form-item label="分组字节数">
        <el-radio-group v-model="form.unit" size="small">
          <el-radio-button :value="1">1</el-radio-button>
          <el-radio-button :value="2">2</el-radio-button>
          <el-radio-button :value="4">4</el-radio-button>
          <el-radio-button :value="8">8</el-radio-button>
        </el-radio-group>
        <div class="hint">
          <el-icon><InfoFilled /></el-icon>
          unit=1 为整体字节逆序；unit=2/4/8 按每组组内逆序，用于大端/小端转换。
        </div>
      </el-form-item>

      <!-- 结果输出 -->
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
      </el-form-item>

      <!-- 操作按钮 -->
      <el-form-item>
        <div class="btn-row">
          <el-button native-type="button" type="primary" :loading="loading" @click="run">执行逆序</el-button>
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
  format: 'hex',
  formatOut: 'hex',
  unit: 1
})

const loading = ref(false)
const result = ref(null)

const resultText = computed(() => {
  if (!result.value) return ''
  return result.value.result
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
  form.input = form.input.replace(/\s+/g, '')
}

function clearAll() {
  form.input = ''
  form.format = 'hex'
  form.formatOut = 'hex'
  form.unit = 1
  result.value = null
}

async function run() {
  if (!form.input.trim()) {
    ElMessage.warning('请输入待逆序的数据')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/byteorder/reverse', { ...form })
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
