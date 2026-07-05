<template>
  <el-card>
    <div class="page-title">随机数检测工具</div>

    <el-form label-position="top">
      <el-form-item label="待检测数据">
        <div class="format-row">
          <el-radio-group v-model="form.format" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
            <el-radio-button value="utf8">字符串</el-radio-button>
          </el-radio-group>
          <div class="data-actions">
            <el-tag size="small" type="info">{{ byteCount }} 字节</el-tag>
            <el-button size="small" :icon="DocumentCopy" @click="copyInput">复制</el-button>
            <el-upload action="#" :auto-upload="false" :on-change="handleFileChange" :show-file-list="false" style="display: inline-block">
              <el-button size="small" :icon="Upload">上传文件</el-button>
            </el-upload>
          </div>
        </div>
        <el-input
          v-model="form.input"
          type="textarea"
          :rows="6"
          placeholder="请输入待检测的随机数据，或上传二进制文件"
        />
        <div class="hint">
          <el-icon><InfoFilled /></el-icon>
          支持手动输入数据或上传二进制文件，提交时会按当前格式自动转换为检测文件。
        </div>
      </el-form-item>

      <el-form-item label="检测密文序列长度（比特）">
        <el-select v-model="form.bitLength" placeholder="请选择序列长度" style="width: 200px">
          <el-option v-for="len in bitLengthOptions" :key="len" :label="formatBitLength(len)" :value="len" />
        </el-select>
      </el-form-item>

      <el-form-item label="随机数检测方法">
        <div class="method-header">
          <el-checkbox v-model="selectAll" @change="handleSelectAll" :indeterminate="isIndeterminate">
            全选当前可用方法
          </el-checkbox>
          <span class="selected-count">已选 {{ selectedCount }} 项</span>
        </div>
        <el-checkbox-group v-model="form.selectedMethods" class="method-list">
          <div v-for="method in methodList" :key="method.id" class="method-item">
            <el-checkbox :label="method.id" :value="method.id">
              <div class="method-info">
                <span class="method-name">[{{ method.id }}] {{ method.name }}</span>
                <span class="method-desc">{{ method.description }}</span>
              </div>
            </el-checkbox>
          </div>
        </el-checkbox-group>
      </el-form-item>

      <el-form-item>
        <div class="btn-row">
          <el-button native-type="button" type="primary" :loading="loading" @click="run">检测</el-button>
          <el-button native-type="button" @click="loadDemo">加载演示数据</el-button>
          <el-button native-type="button" @click="clear">清空</el-button>
        </div>
      </el-form-item>
    </el-form>

    <div v-if="result" class="result-section">
      <div class="section-title">检测结果</div>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="比特长度">{{ result.bitLength }}</el-descriptions-item>
        <el-descriptions-item label="总体结论">
          <el-tag :type="result.overallPass ? 'success' : 'danger'">
            {{ result.overallPass ? '通过' : '未通过' }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>
      <el-table v-if="result.tests" :data="result.tests" border style="margin-top: 12px" max-height="600">
        <el-table-column prop="id" label="编号" width="70" align="center" />
        <el-table-column prop="name" label="检测项" min-width="260" />
        <el-table-column prop="pValue" label="P-value" width="140">
          <template #default="{ row }">
            <span :class="row.pass ? 'pass-text' : 'fail-text'">{{ formatPValue(row.pValue) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="结论" width="90" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="row.pass ? 'success' : 'danger'">
              {{ row.pass ? 'PASS' : 'FAIL' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="detail" label="详情" min-width="300" show-overflow-tooltip />
      </el-table>
    </div>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { Upload, DocumentCopy, InfoFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const bitLengthOptions = [1000000, 100000, 10000, 1000, 100]

const form = reactive({
  input: '',
  format: 'hex',
  bitLength: 100000,
  selectedMethods: []
})
const methodList = ref([])
const result = ref(null)
const loading = ref(false)

const byteCount = computed(() => {
  if (!form.input) return 0
  if (form.format === 'hex') {
    const s = form.input.replace(/\s+/g, '')
    return Math.floor(s.length / 2)
  }
  if (form.format === 'base64') {
    try {
      const s = form.input.replace(/\s+/g, '')
      return Math.floor(atob(s).length)
    } catch (e) {
      return 0
    }
  }
  return new Blob([form.input]).size
})

const selectedCount = computed(() => form.selectedMethods.length)
const selectAll = computed({
  get: () => methodList.value.length > 0 && form.selectedMethods.length === methodList.value.length,
  set: (val) => {}
})
const isIndeterminate = computed(() => {
  return form.selectedMethods.length > 0 && form.selectedMethods.length < methodList.value.length
})

onMounted(async () => {
  try {
    methodList.value = await api.get('/randomness/methods')
  } catch (e) {
    ElMessage.error('加载检测方法失败')
  }
})

watch(methodList, (list) => {
  if (list.length > 0 && form.selectedMethods.length === 0) {
    form.selectedMethods = list.map(m => m.id)
  }
}, { immediate: true })

function formatBitLength(len) {
  if (len >= 1000000) return (len / 1000000) + ' 000 000 比特'
  if (len >= 1000) return (len / 1000) + ' 000 比特'
  return len + ' 比特'
}

function formatPValue(v) {
  if (v === undefined || v === null) return '-'
  if (v === 0) return '0.000000'
  const n = Number(v)
  if (n < 0.000001) return '<0.000001'
  return n.toFixed(6)
}

function handleSelectAll(val) {
  form.selectedMethods = val ? methodList.value.map(m => m.id) : []
}

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function handleFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    form.format = 'hex'
    form.input = arrayBufferToHex(e.target.result)
    ElMessage.success('文件上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

function copyInput() {
  if (!form.input) return
  navigator.clipboard.writeText(form.input).then(() => ElMessage.success('已复制'))
}

async function loadDemo() {
  // 加载一个已通过全部 28 项检测的 100,000 比特确定性演示样本
  try {
    const res = await fetch('/randomness_demo_100000bits.hex')
    if (!res.ok) throw new Error('演示数据加载失败')
    const hex = await res.text()
    form.format = 'hex'
    form.input = hex.trim()
    form.bitLength = 100000
    if (methodList.value.length > 0) {
      form.selectedMethods = methodList.value.map(m => m.id)
    }
    ElMessage.success('已加载 100,000 比特演示数据（已通过全部 28 项检测）')
  } catch (e) {
    // 回退：本地生成伪随机数据
    const bytes = 12500
    const parts = new Array(bytes)
    for (let i = 0; i < bytes; i++) {
      parts[i] = Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    }
    form.format = 'hex'
    form.input = parts.join('')
    form.bitLength = 100000
    if (methodList.value.length > 0) {
      form.selectedMethods = methodList.value.map(m => m.id)
    }
    ElMessage.warning('确定性演示数据加载失败，已生成本地伪随机数据')
  }
}

async function run() {
  if (!form.input.trim()) {
    ElMessage.warning('请输入待检测数据')
    return
  }
  if (form.selectedMethods.length === 0) {
    ElMessage.warning('请至少选择一种检测方法')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/randomness/test', { ...form })
  } finally {
    loading.value = false
  }
}

function clear() {
  form.input = ''
  form.format = 'hex'
  form.bitLength = 100000
  form.selectedMethods = methodList.value.map(m => m.id)
  result.value = null
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
.method-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid #ebeef5;
}
.selected-count {
  color: #909399;
  font-size: 13px;
}
.method-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 400px;
  overflow-y: auto;
  padding-right: 8px;
}
.method-item {
  padding: 8px 12px;
  border: 1px solid #ebeef5;
  border-radius: 4px;
  background: #fafafa;
}
.method-item :deep(.el-checkbox) {
  align-items: flex-start;
  height: auto;
  white-space: normal;
}
.method-info {
  display: inline-flex;
  flex-direction: column;
  margin-left: 4px;
}
.method-name {
  font-weight: 500;
  color: #303133;
}
.method-desc {
  color: #909399;
  font-size: 12px;
  margin-top: 2px;
}
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
}
.result-section {
  margin-top: 20px;
}
.section-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 12px;
}
.pass-text {
  color: #67c23a;
}
.fail-text {
  color: #f56c6c;
}
</style>
