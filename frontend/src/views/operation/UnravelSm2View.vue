<template>
  <el-card>
    <div class="page-title">SM2 随机数重用攻击</div>

    <el-alert
      type="warning"
      :closable="false"
      style="margin-bottom: 20px"
      title="SM2 随机数(k)重用攻击：当两次签名重用相同随机数 k 时，可从两组签名恢复私钥。仅用于密评能力验证与安全测试。"
    />

    <el-form label-position="top">
      <!-- 曲线 / 输入格式 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="曲线">
            <el-select v-model="form.curve" placeholder="请选择曲线" style="width: 100%">
              <el-option label="SM2 推荐曲线 (sm2p256v1)" value="sm2p256v1" />
              <el-option label="secp256k1" value="secp256k1" />
              <el-option label="prime256v1 (P-256 / secp256r1)" value="prime256v1" />
              <el-option label="secp384r1 (P-384)" value="secp384r1" />
              <el-option label="secp521r1 (P-521)" value="secp521r1" />
            </el-select>
          </el-form-item>
        </el-col>
        <el-col :xs="24" :md="12">
          <el-form-item label="输入格式">
            <el-radio-group v-model="form.inputFormat" size="small">
              <el-radio-button value="hex">十六进制</el-radio-button>
              <el-radio-button value="base64">Base64</el-radio-button>
            </el-radio-group>
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 两组签名并排 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-divider content-position="left">第一组签名</el-divider>
          <el-form-item label="r1">
            <div class="format-row">
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.r1) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.r1)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.r1" type="textarea" :rows="3" placeholder="请输入第一组签名 r1" />
          </el-form-item>
          <el-form-item label="s1">
            <div class="format-row">
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.s1) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.s1)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.s1" type="textarea" :rows="3" placeholder="请输入第一组签名 s1" />
          </el-form-item>
          <el-form-item label="e1（消息摘要）">
            <div class="format-row">
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.e1) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.e1)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.e1" type="textarea" :rows="3" placeholder="请输入第一组消息摘要 e1" />
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-divider content-position="left">第二组签名</el-divider>
          <el-form-item label="r2">
            <div class="format-row">
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.r2) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.r2)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.r2" type="textarea" :rows="3" placeholder="请输入第二组签名 r2" />
          </el-form-item>
          <el-form-item label="s2">
            <div class="format-row">
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.s2) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.s2)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.s2" type="textarea" :rows="3" placeholder="请输入第二组签名 s2" />
          </el-form-item>
          <el-form-item label="e2（消息摘要）">
            <div class="format-row">
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.e2) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.e2)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.e2" type="textarea" :rows="3" placeholder="请输入第二组消息摘要 e2" />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 恢复结果 -->
      <template v-if="result">
        <el-divider content-position="left">恢复结果</el-divider>
        <el-form-item>
          <el-tag :type="tagType" size="large">{{ statusText }}</el-tag>
        </el-form-item>
        <el-form-item label="恢复私钥 d">
          <div class="format-row">
            <div class="data-actions">
              <el-tag size="small" type="info">{{ byteCount(result.recoveredPrivateKey) }} 字节</el-tag>
              <el-button size="small" :icon="DocumentCopy" @click="copy(result.recoveredPrivateKey)">复制</el-button>
            </div>
          </div>
          <el-input :model-value="result.recoveredPrivateKey" type="textarea" :rows="3" readonly />
        </el-form-item>
        <el-form-item label="恢复随机数 k">
          <div class="format-row">
            <div class="data-actions">
              <el-tag size="small" type="info">{{ byteCount(result.recoveredK) }} 字节</el-tag>
              <el-button size="small" :icon="DocumentCopy" @click="copy(result.recoveredK)">复制</el-button>
            </div>
          </div>
          <el-input :model-value="result.recoveredK" type="textarea" :rows="3" readonly />
        </el-form-item>
        <el-form-item v-if="result.recoveredPublicKey" label="推导公钥">
          <div class="format-row">
            <div class="data-actions">
              <el-tag size="small" type="info">{{ byteCount(result.recoveredPublicKey) }} 字节</el-tag>
              <el-button size="small" :icon="DocumentCopy" @click="copy(result.recoveredPublicKey)">复制</el-button>
            </div>
          </div>
          <el-input :model-value="result.recoveredPublicKey" type="textarea" :rows="3" readonly />
        </el-form-item>
      </template>

      <!-- 操作按钮 -->
      <el-form-item>
        <div class="btn-row">
          <el-button native-type="button" type="primary" :loading="loading" @click="run">恢复私钥</el-button>
          <el-button native-type="button" :loading="loading" @click="explain">查看原理</el-button>
          <el-button native-type="button" @click="cleanWhitespace">清理空格和换行</el-button>
          <el-button native-type="button" @click="clearAll">清空</el-button>
        </div>
      </el-form-item>

      <el-alert v-if="explanation" :title="explanation" type="info" :closable="false" style="white-space: pre-wrap" />
    </el-form>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { DocumentCopy } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const form = reactive({
  curve: 'sm2p256v1',
  inputFormat: 'hex',
  r1: '',
  s1: '',
  e1: '',
  r2: '',
  s2: '',
  e2: ''
})

const result = ref(null)
const explanation = ref('')
const loading = ref(false)

const tagType = computed(() => {
  if (!result.value) return 'info'
  if (!result.value.success) return 'danger'
  return result.value.verified ? 'success' : 'warning'
})

const statusText = computed(() => {
  if (!result.value) return ''
  if (!result.value.success) return result.value.verifyMessage || '恢复失败'
  if (result.value.verified) return '恢复成功，且签名验证通过'
  return result.value.verifyMessage || '恢复成功，但签名验证未通过'
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
  form.r1 = form.r1.replace(/\s+/g, '')
  form.s1 = form.s1.replace(/\s+/g, '')
  form.e1 = form.e1.replace(/\s+/g, '')
  form.r2 = form.r2.replace(/\s+/g, '')
  form.s2 = form.s2.replace(/\s+/g, '')
  form.e2 = form.e2.replace(/\s+/g, '')
}

function clearAll() {
  form.curve = 'sm2p256v1'
  form.inputFormat = 'hex'
  form.r1 = ''
  form.s1 = ''
  form.e1 = ''
  form.r2 = ''
  form.s2 = ''
  form.e2 = ''
  result.value = null
  explanation.value = ''
}

async function run() {
  if (!form.r1.trim() || !form.s1.trim() || !form.e1.trim() ||
      !form.r2.trim() || !form.s2.trim() || !form.e2.trim()) {
    ElMessage.warning('请完整填写两组签名的 r、s、e')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/sigattack/sm2-nonce-reuse', { ...form })
  } finally {
    loading.value = false
  }
}

async function explain() {
  loading.value = true
  try {
    const r = await api.post('/sigattack/explain', {})
    explanation.value = typeof r === 'string' ? r : (r.explanation || JSON.stringify(r))
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
  justify-content: flex-end;
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
