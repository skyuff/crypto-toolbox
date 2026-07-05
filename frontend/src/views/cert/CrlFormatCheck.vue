<template>
  <el-card class="crl-check">
    <div class="title">CRL 格式校验</div>

    <el-row :gutter="24">
      <!-- 左侧：待校验 CRL -->
      <el-col :span="12">
        <div class="sub-title">
          <el-icon><Document /></el-icon>
          <span>待校验 CRL</span>
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
          placeholder="请输入待校验 CRL"
        />
      </el-col>

      <!-- 右侧：上级证书 -->
      <el-col :span="12">
        <div class="sub-title">
          <el-icon><User /></el-icon>
          <span>上级证书</span>
        </div>
        <div class="row">
          <el-radio-group v-model="form.issuerCertFormat" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
            <el-radio-button value="pem">PEM</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ issuerBytes }}字节</el-tag>
          <el-button size="small" text @click="copyText(form.issuerCert)">复制</el-button>
          <el-upload
            class="cert-upload"
            action="#"
            :auto-upload="false"
            :show-file-list="false"
            :on-change="handleIssuerFileChange"
            accept=".cer,.crt,.pem,.der"
          >
            <el-button size="small" text>
              <el-icon><Upload /></el-icon> 上传证书
            </el-button>
          </el-upload>
        </div>
        <el-input
          v-model="form.issuerCert"
          type="textarea"
          :rows="8"
          placeholder="请输入上级证书"
        />
      </el-col>
    </el-row>

    <div class="actions">
      <el-button :loading="extractLoading" @click="extractInfo">CRL 信息提取</el-button>
      <el-button :loading="validateLoading" @click="validateCrl">有效性验证</el-button>
      <el-button type="primary" @click="cleanWhitespace">清理空格和换行</el-button>
      <el-button type="danger" plain @click="clearAll">清空</el-button>
    </div>

    <template v-if="result">
      <el-divider content-position="left">CRL 校验结果</el-divider>

      <el-result
        v-if="result.signatureValid !== undefined"
        :icon="result.signatureValid ? 'success' : 'error'"
        :title="result.signatureValid ? 'CRL 签名验证通过' : 'CRL 签名验证失败'"
        :sub-title="result.signatureError || result.issuerMatchError || ''"
      />

      <el-descriptions :column="2" border title="CRL 信息">
        <el-descriptions-item label="颁发者" :span="2">{{ result.issuer }}</el-descriptions-item>
        <el-descriptions-item label="本次更新">{{ result.thisUpdate }}</el-descriptions-item>
        <el-descriptions-item label="下次更新">{{ result.nextUpdate }}</el-descriptions-item>
        <el-descriptions-item label="签名算法">{{ result.signatureAlgorithm }}</el-descriptions-item>
        <el-descriptions-item label="是否过期">
          <el-tag :type="result.expired ? 'danger' : 'success'">{{ result.expired ? '已过期' : '有效' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="吊销条目数">{{ result.revokedCount }}</el-descriptions-item>
      </el-descriptions>

      <el-table v-if="result.checks" :data="result.checks" border style="margin-top: 12px">
        <el-table-column prop="item" label="检查项" width="220" />
        <el-table-column label="结果" width="90">
          <template #default="{ row }">
            <el-tag :type="row.pass ? 'success' : 'danger'" size="small">{{ row.pass ? 'PASS' : 'FAIL' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="message" label="说明" />
      </el-table>

      <el-table v-if="result.revokedCertificates && result.revokedCertificates.length" :data="result.revokedCertificates" border style="margin-top: 12px">
        <el-table-column prop="serialNumber" label="吊销证书序列号" />
        <el-table-column prop="revocationDate" label="吊销时间" width="240" />
        <el-table-column prop="revocationReason" label="吊销原因" />
      </el-table>
    </template>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { Document, User, Upload } from '@element-plus/icons-vue'
import api from '../../api'

const form = reactive({
  crlPem: '',
  crlFormat: 'hex',
  issuerCert: '',
  issuerCertFormat: 'hex'
})

const result = ref(null)
const extractLoading = ref(false)
const validateLoading = ref(false)

function cleanInput(s) {
  return (s || '').replace(/[\s\r\n]/g, '')
}

const crlBytes = computed(() => byteCount(form.crlPem, form.crlFormat))
const issuerBytes = computed(() => byteCount(form.issuerCert, form.issuerCertFormat))

function byteCount(text, format) {
  const s = cleanInput(text)
  if (!s) return 0
  if (format === 'hex') return Math.floor(s.length / 2)
  if (format === 'base64') {
    try { return Math.floor(atob(s).length) } catch { return 0 }
  }
  return 0
}

function copyText(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
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

function handleIssuerFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    form.issuerCert = arrayBufferToHex(e.target.result)
    form.issuerCertFormat = 'hex'
    ElMessage.success('证书上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

async function extractInfo() {
  if (!form.crlPem.trim()) {
    ElMessage.warning('请输入待校验 CRL')
    return
  }
  extractLoading.value = true
  result.value = null
  try {
    result.value = await api.post('/crl/info/extract', {
      crlPem: cleanInput(form.crlPem),
      crlFormat: form.crlFormat
    })
  } catch (e) {
    // error handled by interceptor
  } finally {
    extractLoading.value = false
  }
}

async function validateCrl() {
  if (!form.crlPem.trim()) {
    ElMessage.warning('请输入待校验 CRL')
    return
  }
  validateLoading.value = true
  result.value = null
  try {
    result.value = await api.post('/crl/validate/signature', {
      crlPem: cleanInput(form.crlPem),
      crlFormat: form.crlFormat,
      issuerCert: cleanInput(form.issuerCert),
      issuerCertFormat: form.issuerCertFormat
    })
  } catch (e) {
    // error handled by interceptor
  } finally {
    validateLoading.value = false
  }
}

function cleanWhitespace() {
  form.crlPem = cleanInput(form.crlPem)
  form.issuerCert = cleanInput(form.issuerCert)
  ElMessage.success('已清理空格和换行')
}

function clearAll() {
  form.crlPem = ''
  form.crlFormat = 'hex'
  form.issuerCert = ''
  form.issuerCertFormat = 'hex'
  result.value = null
}
</script>

<style scoped>
.crl-check {
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
.actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  margin: 24px 0 8px;
}
</style>
