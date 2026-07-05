<template>
  <el-card class="status-check">
    <div class="title">数字证书状态检查</div>

    <el-row :gutter="24">
      <!-- 左侧：待校验证书 -->
      <el-col :span="12">
        <div class="sub-title">
          <el-icon><Document /></el-icon>
          <span>待校验证书</span>
        </div>
        <div class="row">
          <el-radio-group v-model="form.certFormat" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
            <el-radio-button value="pem">PEM</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ certBytes }}字节</el-tag>
          <el-button size="small" text @click="copyText(form.certPem)">复制</el-button>
          <el-upload
            class="cert-upload"
            action="#"
            :auto-upload="false"
            :show-file-list="false"
            :on-change="handleCertFileChange"
            accept=".cer,.crt,.pem,.der"
          >
            <el-button size="small" text>
              <el-icon><Upload /></el-icon> 上传证书
            </el-button>
          </el-upload>
        </div>
        <el-input
          v-model="form.certPem"
          type="textarea"
          :rows="8"
          placeholder="请输入待校验证书"
        />
      </el-col>

      <!-- 右侧：CRL 文件 -->
      <el-col :span="12">
        <div class="sub-title">
          <el-icon><Folder /></el-icon>
          <span>CRL 文件</span>
        </div>
        <div class="row">
          <el-radio-group v-model="form.crlFormat" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
            <el-radio-button value="pem">PEM</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ crlBytes }}字节</el-tag>
          <el-button size="small" text @click="copyText(form.crlPem)">复制</el-button>
          <el-upload
            class="cert-upload"
            action="#"
            :auto-upload="false"
            :show-file-list="false"
            :on-change="handleCrlFileChange"
            accept=".crl,.pem,.der"
          >
            <el-button size="small" text>
              <el-icon><Upload /></el-icon> 上传 CRL
            </el-button>
          </el-upload>
        </div>
        <el-input
          v-model="form.crlPem"
          type="textarea"
          :rows="8"
          placeholder="请输入 CRL 内容"
        />
      </el-col>
    </el-row>

    <el-row :gutter="24" style="margin-top: 16px">
      <el-col :span="12">
        <div class="label">OCSP 请求地址</div>
        <el-input v-model="form.ocspUrl" placeholder="请输入证书对应的 OCSP 请求地址" />
      </el-col>
      <el-col :span="12">
        <div class="label">OCSP 哈希算法</div>
        <el-select v-model="form.digestAlgorithm" style="width: 100%">
          <el-option label="SM3" value="SM3" />
          <el-option label="SHA1" value="SHA1" />
          <el-option label="SHA256" value="SHA256" />
          <el-option label="SHA384" value="SHA384" />
          <el-option label="SHA512" value="SHA512" />
        </el-select>
      </el-col>
    </el-row>

    <div class="actions">
      <el-button :loading="crlLoading" @click="crlCheck">CRL 检查</el-button>
      <el-button :loading="ocspLoading" @click="ocspCheck">OCSP 检查</el-button>
      <el-button type="primary" @click="cleanWhitespace">清理空格和换行</el-button>
      <el-button type="danger" plain @click="clearAll">清空</el-button>
    </div>

    <template v-if="result">
      <el-divider content-position="left">检查结果</el-divider>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="检查方式">
          <el-tag>{{ result.checkedBy }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="撤销状态" v-if="result.checkedBy === 'CRL'">
          <el-tag :type="result.revoked ? 'danger' : 'success'">
            {{ result.revoked ? '已撤销' : '未撤销' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="证书主题" :span="2">{{ result.certSubject }}</el-descriptions-item>
        <el-descriptions-item label="证书颁发者" :span="2">{{ result.certIssuer }}</el-descriptions-item>
        <el-descriptions-item label="证书序列号">{{ result.certSerialNumber }}</el-descriptions-item>
        <el-descriptions-item label="OCSP 地址" v-if="result.ocspUrl">{{ result.ocspUrl }}</el-descriptions-item>
        <el-descriptions-item label="哈希算法" v-if="result.digestAlgorithm">{{ result.digestAlgorithm }}</el-descriptions-item>
        <el-descriptions-item label="CRL 颁发者" v-if="result.crlIssuer" :span="2">{{ result.crlIssuer }}</el-descriptions-item>
        <el-descriptions-item label="撤销时间" v-if="result.revocationDate">{{ result.revocationDate }}</el-descriptions-item>
        <el-descriptions-item label="撤销原因" v-if="result.revocationReason">{{ result.revocationReason }}</el-descriptions-item>
      </el-descriptions>
      <el-alert
        v-if="result.message"
        :title="result.message"
        :type="result.revoked ? 'error' : 'warning'"
        :closable="false"
        style="margin-top: 12px"
      />
    </template>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { Document, Folder, Upload } from '@element-plus/icons-vue'
import api from '../../api'

const form = reactive({
  certPem: '',
  certFormat: 'hex',
  crlPem: '',
  crlFormat: 'hex',
  ocspUrl: '',
  digestAlgorithm: 'SM3'
})

const result = ref(null)
const crlLoading = ref(false)
const ocspLoading = ref(false)

function cleanInput(s) {
  return (s || '').replace(/[\s\r\n]/g, '')
}

const certBytes = computed(() => {
  const s = cleanInput(form.certPem)
  if (!s) return 0
  if (form.certFormat === 'hex') return Math.floor(s.length / 2)
  if (form.certFormat === 'base64') {
    try { return Math.floor(atob(s).length) } catch { return 0 }
  }
  return 0
})

const crlBytes = computed(() => {
  const s = cleanInput(form.crlPem)
  if (!s) return 0
  if (form.crlFormat === 'hex') return Math.floor(s.length / 2)
  if (form.crlFormat === 'base64') {
    try { return Math.floor(atob(s).length) } catch { return 0 }
  }
  return 0
})

function copyText(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function handleCertFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    form.certPem = arrayBufferToHex(e.target.result)
    form.certFormat = 'hex'
    ElMessage.success('证书上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

function handleCrlFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    form.crlPem = arrayBufferToHex(e.target.result)
    form.crlFormat = 'hex'
    ElMessage.success('CRL 上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

async function crlCheck() {
  if (!form.certPem.trim()) {
    ElMessage.warning('请输入待校验证书')
    return
  }
  crlLoading.value = true
  result.value = null
  try {
    result.value = await api.post('/cert/status/check/crl', {
      certPem: cleanInput(form.certPem),
      certFormat: form.certFormat,
      crlPem: cleanInput(form.crlPem),
      crlFormat: form.crlFormat
    })
  } catch (e) {
    // error handled by interceptor
  } finally {
    crlLoading.value = false
  }
}

async function ocspCheck() {
  if (!form.certPem.trim()) {
    ElMessage.warning('请输入待校验证书')
    return
  }
  ocspLoading.value = true
  result.value = null
  try {
    result.value = await api.post('/cert/status/check/ocsp', {
      certPem: cleanInput(form.certPem),
      certFormat: form.certFormat,
      ocspUrl: form.ocspUrl,
      digestAlgorithm: form.digestAlgorithm
    })
  } catch (e) {
    // error handled by interceptor
  } finally {
    ocspLoading.value = false
  }
}

function cleanWhitespace() {
  form.certPem = cleanInput(form.certPem)
  form.crlPem = cleanInput(form.crlPem)
  ElMessage.success('已清理空格和换行')
}

function clearAll() {
  form.certPem = ''
  form.certFormat = 'hex'
  form.crlPem = ''
  form.crlFormat = 'hex'
  form.ocspUrl = ''
  form.digestAlgorithm = 'SM3'
  result.value = null
}
</script>

<style scoped>
.status-check {
  min-height: 500px;
}
.title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
}
.sub-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
  margin-bottom: 8px;
  font-size: 14px;
}
.row {
  display: flex;
  align-items: center;
  margin-bottom: 8px;
  gap: 8px;
}
.spacer {
  flex: 1;
}
.cert-upload {
  display: inline-flex;
}
.label {
  font-weight: 500;
  margin-bottom: 6px;
  font-size: 14px;
}
.actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  margin: 24px 0 8px;
}
</style>
