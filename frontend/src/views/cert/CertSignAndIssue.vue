<template>
  <el-card class="cert-issue">
    <div class="title">数字证书签发</div>

    <el-tabs v-model="activeTab" type="card">
      <!-- 标签页 1：CSR 生成 -->
      <el-tab-pane label="CSR 生成" name="csr">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="field-label"><span class="req">*</span> 国家/C</div>
            <el-input v-model="csrForm.country" placeholder="CN" />

            <div class="field-label">省份/ST</div>
            <el-input v-model="csrForm.state" placeholder="请输入省份" />

            <div class="field-label">部门/OU</div>
            <el-input v-model="csrForm.organizationalUnit" placeholder="请输入部门" />

            <div class="field-label">邮箱/EmailAddress</div>
            <el-input v-model="csrForm.emailAddress" placeholder="请输入邮箱" />
          </el-col>
          <el-col :span="12">
            <div class="field-label"><span class="req">*</span> 主题名称/CN</div>
            <el-input v-model="csrForm.commonName" placeholder="请输入主题名称" />

            <div class="field-label">城市/L</div>
            <el-input v-model="csrForm.locality" placeholder="请输入城市" />

            <div class="field-label">组织/O</div>
            <el-input v-model="csrForm.organization" placeholder="请输入组织" />

            <div class="field-label">证书算法</div>
            <el-radio-group v-model="csrForm.algorithm">
              <el-radio-button value="SM2">SM2</el-radio-button>
              <el-radio-button value="RSA">RSA</el-radio-button>
            </el-radio-group>
          </el-col>
        </el-row>

        <div class="actions">
          <el-button :loading="csrLoading" type="primary" @click="generateCsr">生成 CSR</el-button>
          <el-button @click="cleanCsrWhitespace">删除空格和换行</el-button>
          <el-button type="danger" plain @click="clearCsr">清除</el-button>
        </div>

        <template v-if="csrResult">
          <el-divider content-position="left">生成结果</el-divider>
          <el-form label-width="80px">
            <el-form-item label="CSR (PEM)">
              <el-input v-model="csrResult.csr" type="textarea" :rows="6" readonly />
            </el-form-item>
            <el-form-item label="私钥 (PEM)">
              <el-input v-model="csrResult.privateKey" type="textarea" :rows="4" readonly />
            </el-form-item>
            <el-form-item label="主题">
              <el-input :model-value="csrResult.subject" readonly />
            </el-form-item>
          </el-form>
        </template>
      </el-tab-pane>

      <!-- 标签页 2：证书签发 -->
      <el-tab-pane label="证书签发" name="issue">
        <el-radio-group v-model="issueForm.issueMode" style="margin-bottom: 16px">
          <el-radio-button value="direct">直接生成 PFX 证书</el-radio-button>
          <el-radio-button value="csr">提交证书请求 P10</el-radio-button>
        </el-radio-group>

        <el-row :gutter="24">
          <!-- 左侧：有效期 + 主题字段 / CSR -->
          <el-col :span="12">
            <div class="field-label"><span class="req">*</span> 有效期</div>
            <el-input-number v-model="issueForm.validMonths" :min="1" :max="120" />
            <span style="margin-left: 8px">月</span>

            <template v-if="issueForm.issueMode === 'direct'">
              <div class="field-label">国家/C</div>
              <el-input v-model="issueForm.country" placeholder="CN" />

              <div class="field-label">省份/ST</div>
              <el-input v-model="issueForm.state" placeholder="请输入省份" />

              <div class="field-label">部门/OU</div>
              <el-input v-model="issueForm.organizationalUnit" placeholder="请输入部门" />

              <div class="field-label">邮箱/EmailAddress</div>
              <el-input v-model="issueForm.emailAddress" placeholder="请输入邮箱" />
            </template>

            <template v-else>
              <div class="field-label"><span class="req">*</span> 证书请求 CSR</div>
              <div class="row">
                <el-tag size="small" type="primary" effect="plain">{{ csrBytes }}字节</el-tag>
                <el-button size="small" text @click="copyText(issueForm.csr)">复制</el-button>
              </div>
              <el-input v-model="issueForm.csr" type="textarea" :rows="10" placeholder="请输入 PEM 格式，复制 P10 文件中的内容至此" />
            </template>
          </el-col>

          <!-- 右侧：证书类型 + PFX 密码 + 主题名称/CN/组织/城市/算法 -->
          <el-col :span="12">
            <div class="field-label">证书类型</div>
            <el-select v-model="issueForm.certType" style="width: 100%">
              <el-option label="用户证书" value="用户证书" />
              <el-option label="CA中间证书" value="CA中间证书" />
              <el-option label="SSL证书" value="SSL证书" />
            </el-select>

            <div class="field-label"><span class="req">*</span> PFX 密码</div>
            <el-input v-model="issueForm.pfxPassword" type="password" show-password placeholder="请输入 PFX 导出密码" />

            <div v-if="issueForm.issueMode === 'direct'" class="field-label"><span class="req">*</span> 主题名称/CN</div>
            <el-input v-if="issueForm.issueMode === 'direct'" v-model="issueForm.commonName" placeholder="请输入主题名称" />

            <div v-if="issueForm.issueMode === 'direct'" class="field-label">城市/L</div>
            <el-input v-if="issueForm.issueMode === 'direct'" v-model="issueForm.locality" placeholder="请输入城市" />

            <div v-if="issueForm.issueMode === 'direct'" class="field-label">组织/O</div>
            <el-input v-if="issueForm.issueMode === 'direct'" v-model="issueForm.organization" placeholder="请输入组织" />

            <div class="field-label">证书算法</div>
            <el-radio-group v-model="issueForm.algorithm">
              <el-radio-button value="SM2">SM2</el-radio-button>
              <el-radio-button value="RSA">RSA</el-radio-button>
            </el-radio-group>
          </el-col>
        </el-row>

        <div class="actions">
          <el-button :loading="issueLoading" type="primary" @click="issueCert">签发证书</el-button>
          <el-button @click="cleanIssueWhitespace">删除空格和换行</el-button>
          <el-button type="danger" plain @click="clearIssue">清除</el-button>
        </div>

        <template v-if="issueResult">
          <el-divider content-position="left">签发结果</el-divider>
          <el-descriptions :column="2" border>
            <el-descriptions-item label="签发方式">{{ issueResult.issueMode === 'direct' ? '直接生成' : 'CSR 签发' }}</el-descriptions-item>
            <el-descriptions-item label="证书类型">{{ issueResult.certType }}</el-descriptions-item>
            <el-descriptions-item label="序列号">{{ issueResult.serialNumber }}</el-descriptions-item>
            <el-descriptions-item label="签名算法">{{ issueResult.signatureAlgorithm }}</el-descriptions-item>
            <el-descriptions-item label="主题">{{ issueResult.subject }}</el-descriptions-item>
            <el-descriptions-item label="颁发者">{{ issueResult.issuer }}</el-descriptions-item>
            <el-descriptions-item label="有效期">{{ issueResult.notBefore }} ~ {{ issueResult.notAfter }}</el-descriptions-item>
          </el-descriptions>

          <el-form label-width="80px" style="margin-top: 12px">
            <el-form-item label="证书 (PEM)">
              <el-input v-model="issueResult.certificate" type="textarea" :rows="6" readonly />
            </el-form-item>
            <el-form-item v-if="issueResult.privateKey" label="私钥 (PEM)">
              <el-input v-model="issueResult.privateKey" type="textarea" :rows="4" readonly />
            </el-form-item>
            <el-form-item v-if="issueResult.pfxBase64" label="PFX (Base64)">
              <el-input v-model="issueResult.pfxBase64" type="textarea" :rows="4" readonly />
              <el-button size="small" text @click="downloadPfx">下载 PFX 文件</el-button>
            </el-form-item>
          </el-form>
        </template>
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const activeTab = ref('csr')

const csrForm = reactive({
  country: 'CN',
  state: '',
  locality: '',
  organization: '',
  organizationalUnit: '',
  commonName: '',
  emailAddress: '',
  algorithm: 'SM2'
})

const issueForm = reactive({
  issueMode: 'direct',
  certType: '用户证书',
  validMonths: 12,
  pfxPassword: '',
  country: 'CN',
  state: '',
  locality: '',
  organization: '',
  organizationalUnit: '',
  commonName: '',
  emailAddress: '',
  algorithm: 'SM2',
  csr: ''
})

const csrResult = ref(null)
const issueResult = ref(null)
const csrLoading = ref(false)
const issueLoading = ref(false)

const csrBytes = computed(() => {
  const s = (issueForm.csr || '').replace(/[\s\r\n]/g, '')
  try { return Math.floor(atob(s).length) } catch { return 0 }
})

function copyText(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}

async function generateCsr() {
  if (!csrForm.commonName) {
    ElMessage.warning('请输入主题名称/CN')
    return
  }
  csrLoading.value = true
  csrResult.value = null
  try {
    csrResult.value = await api.post('/cert/sign/csr', csrForm)
  } catch (e) {
    // error handled by interceptor
  } finally {
    csrLoading.value = false
  }
}

function cleanCsrWhitespace() {
  csrForm.commonName = csrForm.commonName.replace(/\s/g, '')
  ElMessage.success('已删除空格')
}

function clearCsr() {
  csrForm.country = 'CN'
  csrForm.state = ''
  csrForm.locality = ''
  csrForm.organization = ''
  csrForm.organizationalUnit = ''
  csrForm.commonName = ''
  csrForm.emailAddress = ''
  csrForm.algorithm = 'SM2'
  csrResult.value = null
}

async function issueCert() {
  if (issueForm.issueMode === 'direct') {
    if (!issueForm.commonName) {
      ElMessage.warning('请输入主题名称/CN')
      return
    }
    if (!issueForm.pfxPassword) {
      ElMessage.warning('请输入 PFX 密码')
      return
    }
  } else {
    if (!issueForm.csr.trim()) {
      ElMessage.warning('请输入证书请求 CSR')
      return
    }
  }

  issueLoading.value = true
  issueResult.value = null
  try {
    issueResult.value = await api.post('/cert/sign/issue', issueForm)
  } catch (e) {
    // error handled by interceptor
  } finally {
    issueLoading.value = false
  }
}

function cleanIssueWhitespace() {
  issueForm.csr = issueForm.csr.replace(/[\s\r\n]/g, '')
  issueForm.commonName = issueForm.commonName.replace(/\s/g, '')
  ElMessage.success('已删除空格和换行')
}

function clearIssue() {
  issueForm.issueMode = 'direct'
  issueForm.certType = '用户证书'
  issueForm.validMonths = 12
  issueForm.pfxPassword = ''
  issueForm.country = 'CN'
  issueForm.state = ''
  issueForm.locality = ''
  issueForm.organization = ''
  issueForm.organizationalUnit = ''
  issueForm.commonName = ''
  issueForm.emailAddress = ''
  issueForm.algorithm = 'SM2'
  issueForm.csr = ''
  issueResult.value = null
}

function downloadPfx() {
  if (!issueResult.value?.pfxBase64) return
  const blob = new Blob([Uint8Array.from(atob(issueResult.value.pfxBase64), c => c.charCodeAt(0))], { type: 'application/x-pkcs12' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'certificate.pfx'
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<style scoped>
.cert-issue {
  min-height: 500px;
}
.title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
}
.field-label {
  font-weight: 500;
  margin: 12px 0 6px;
  font-size: 14px;
}
.req {
  color: #f56c6c;
  margin-right: 2px;
}
.actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  margin: 24px 0 8px;
}
.row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
</style>
