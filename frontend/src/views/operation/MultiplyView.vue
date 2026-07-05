<template>
  <el-card>
    <div class="page-title">椭圆曲线点运算</div>

    <el-alert
      type="info"
      :closable="false"
      style="margin-bottom: 20px"
      title="椭圆曲线点运算：支持点加 P+Q、点减 P-Q、点乘 [k]P / [k]G。"
    />

    <el-form label-position="top">
      <!-- 两个输入区并排 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="点 G / 自定义点">
            <div class="format-row">
              <el-radio-group v-model="form.inputFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.p) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.p)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.p"
              type="textarea"
              :rows="5"
              placeholder="请输入第一个点（x||y）"
            />
          </el-form-item>
          <div class="hint-row">
            <el-icon><Info-Filled /></el-icon>
            <span>请输入未压缩格式（04 开头）的点坐标。</span>
          </div>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="运算点 / 标量">
            <div class="format-row">
              <el-radio-group v-model="form.inputFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.q) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.q)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.q"
              type="textarea"
              :rows="5"
              placeholder="请输入第二个点，或点乘所需的标量"
            />
          </el-form-item>
          <div class="hint-row">
            <el-icon><Info-Filled /></el-icon>
            <span>点加、点减时输入点坐标；点乘时输入标量 k。</span>
          </div>
        </el-col>
      </el-row>

      <!-- 曲线 / 输出格式 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="曲线">
            <el-select v-model="form.curve" placeholder="请选择曲线" style="width: 100%">
              <el-option label="SM2 推荐曲线 (sm2p256v1)" value="sm2p256v1" />
              <el-option label="secp256r1 (P-256 / prime256v1)" value="secp256r1" />
              <el-option label="secp256k1" value="secp256k1" />
              <el-option label="secp384r1 (P-384)" value="secp384r1" />
              <el-option label="secp521r1 (P-521)" value="secp521r1" />
            </el-select>
          </el-form-item>
        </el-col>
        <el-col :xs="24" :md="12">
          <el-form-item label="输出格式">
            <el-radio-group v-model="form.outputFormat" size="small">
              <el-radio-button value="hex">十六进制</el-radio-button>
              <el-radio-button value="base64">Base64</el-radio-button>
            </el-radio-group>
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 输出结果 -->
      <el-form-item label="输出结果">
        <div class="format-row">
          <div />
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
          <el-button native-type="button" type="primary" :loading="loading" @click="run('add')">点加 +</el-button>
          <el-button native-type="button" type="primary" :loading="loading" @click="run('sub')">点减 -</el-button>
          <el-button native-type="button" type="primary" :loading="loading" @click="run('mul')">点乘 *</el-button>
          <el-button native-type="button" type="primary" @click="cleanWhitespace">清理空格和换行</el-button>
          <el-button native-type="button" type="primary" @click="clearAll">清空</el-button>
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
  curve: 'sm2p256v1',
  p: '',
  q: '',
  inputFormat: 'hex',
  outputFormat: 'hex'
})

const result = ref(null)
const loading = ref(false)

const resultText = computed(() => {
  if (!result.value) return ''
  return result.value.result || ''
})

const resultByteCount = computed(() => {
  return result.value ? (result.value.byteLength || 0) : 0
})

function byteCount(value) {
  if (!value) return 0
  if (form.inputFormat === 'base64') {
    try {
      const s = value.replace(/\s+/g, '')
      return Math.floor(atob(s).length)
    } catch (e) {
      return 0
    }
  }
  const s = value.replace(/\s+/g, '').replace(/^0x/i, '')
  return Math.floor(s.length / 2)
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace() {
  form.p = form.p.replace(/\s+/g, '')
  form.q = form.q.replace(/\s+/g, '')
}

function clearAll() {
  form.curve = 'sm2p256v1'
  form.p = ''
  form.q = ''
  form.inputFormat = 'hex'
  form.outputFormat = 'hex'
  result.value = null
}

async function run(op) {
  if (op !== 'mul' && !form.p.trim()) {
    ElMessage.warning('请输入点 P')
    return
  }
  if (!form.q.trim()) {
    ElMessage.warning(op === 'mul' ? '请输入标量 k' : '请输入点 Q')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/point-op/calc', { ...form, op })
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
.hint-row {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  color: #909399;
  font-size: 13px;
  margin-top: -8px;
  margin-bottom: 12px;
  line-height: 1.5;
}
.hint-row .el-icon {
  margin-top: 1px;
  flex-shrink: 0;
}
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 8px;
}
</style>
