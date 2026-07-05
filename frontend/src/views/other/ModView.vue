<template>
  <el-card>
    <div class="page-title">取模运算</div>

    <!-- 第一行：数据 A / 数据 B -->
    <el-row :gutter="24">
      <el-col :xs="24" :md="12">
        <el-form label-position="top">
          <el-form-item label="数据 A">
            <div class="format-row">
              <el-radio-group v-model="form.formatA" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.a, form.formatA) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.a)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.a"
              type="textarea"
              :rows="5"
              placeholder="请输入数据 A"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              还没想好要提示些什么？
            </div>
          </el-form-item>
        </el-form>
      </el-col>

      <el-col :xs="24" :md="12">
        <el-form label-position="top">
          <el-form-item label="数据 B">
            <div class="format-row">
              <el-radio-group v-model="form.formatB" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.b, form.formatB) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.b)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.b"
              type="textarea"
              :rows="5"
              placeholder="请输入数据 B（模逆运算忽略此项）"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              还没想好要提示些什么？
            </div>
          </el-form-item>
        </el-form>
      </el-col>
    </el-row>

    <!-- 第二行：模数 P / 结果输出 -->
    <el-row :gutter="24">
      <el-col :xs="24" :md="12">
        <el-form label-position="top">
          <el-form-item label="模数 P">
            <div class="format-row">
              <el-radio-group v-model="form.formatM" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.m, form.formatM) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.m)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.m"
              type="textarea"
              :rows="5"
              placeholder="请输入模数 P"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              还没想好要提示些什么？
            </div>
          </el-form-item>
        </el-form>
      </el-col>

      <el-col :xs="24" :md="12">
        <el-form label-position="top">
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
              :rows="5"
              readonly
              placeholder="结果将显示在这里"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              还没想好要提示些什么？
            </div>
          </el-form-item>
        </el-form>
      </el-col>
    </el-row>

    <!-- 操作按钮 -->
    <div class="btn-row">
      <el-button native-type="button" type="primary" :loading="loading" @click="calc('add')">A + B mod p</el-button>
      <el-button native-type="button" type="primary" :loading="loading" @click="calc('sub')">A - B mod p</el-button>
      <el-button native-type="button" type="primary" :loading="loading" @click="calc('mul')">A * B mod p</el-button>
      <el-button native-type="button" type="primary" :loading="loading" @click="calc('pow')">A ^ B mod p</el-button>
      <el-button native-type="button" type="primary" :loading="loading" @click="calc('inv')">A ^ -1 mod p</el-button>
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
  m: '',
  formatA: 'hex',
  formatB: 'hex',
  formatM: 'hex',
  formatOut: 'hex'
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
  form.a = form.a.replace(/\s+/g, '')
  form.b = form.b.replace(/\s+/g, '')
  form.m = form.m.replace(/\s+/g, '')
}

function clearAll() {
  form.a = ''
  form.b = ''
  form.m = ''
  form.formatA = 'hex'
  form.formatB = 'hex'
  form.formatM = 'hex'
  form.formatOut = 'hex'
  result.value = null
}

async function calc(op) {
  if (!form.a.trim()) {
    ElMessage.warning('请输入数据 A')
    return
  }
  if (op !== 'inv' && !form.b.trim()) {
    ElMessage.warning('请输入数据 B')
    return
  }
  if (!form.m.trim()) {
    ElMessage.warning('请输入模数 P')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/modmath/calc', { ...form, op })
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
  flex-wrap: wrap;
}
</style>
