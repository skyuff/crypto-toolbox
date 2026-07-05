<template>
  <div class="pkcs7-workbench">
    <div class="title">PKCS#7 工具集</div>
    <el-tabs v-model="tab">
      <el-tab-pane label="签名验签" name="sign">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 签名证书</div>
            <div class="row">
              <el-radio-group v-model="sv.certFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ sv.cert.length }}字节</el-tag>
              <el-button size="small" text @click="copy(sv.cert)">复制</el-button>
              <el-button size="small" text><el-icon-upload /> 上传证书</el-button>
            </div>
            <el-input v-model="sv.cert" type="textarea" :rows="4" placeholder="请输入证书" />
          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 私钥</div>
            <div class="row">
              <el-radio-group v-model="sv.privFmt" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ sv.privateKey.length }}字节</el-tag>
              <el-button size="small" text @click="copy(sv.privateKey)">复制</el-button>
            </div>
            <el-input v-model="sv.privateKey" type="textarea" :rows="4" placeholder="请输入私钥" />
          </el-col>
        </el-row>

        <div class="sub" style="margin-top:16px">签名模式</div>
        <el-radio-group v-model="sv.mode" size="small">
          <el-radio-button value="attach">Attach</el-radio-button>
          <el-radio-button value="detach">Detach</el-radio-button>
        </el-radio-group>

        <el-row :gutter="24" style="margin-top:16px">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 消息</div>
            <div class="row">
              <el-radio-group v-model="sv.msgFmt" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ sv.message.length }}字节</el-tag>
              <el-button size="small" text @click="copy(sv.message)">复制</el-button>
            </div>
            <el-input v-model="sv.message" type="textarea" :rows="4" placeholder="请输入待签名的消息" />
          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 签名值</div>
            <div class="row">
              <el-radio-group v-model="sv.sigFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ sv.signature.length }}字节</el-tag>
              <el-button size="small" text @click="copy(sv.signature)">复制</el-button>
            </div>
            <el-input v-model="sv.signature" type="textarea" :rows="4" placeholder="请输入验签数据" />
            <div class="hint2">PKCS#7封装后的数据</div>
          </el-col>
        </el-row>

        <div class="actions">
          <div class="left">
            <el-button type="primary" :loading="loading" @click="doSign">签名</el-button>
            <el-button :loading="loading" @click="doVerify">验签</el-button>
          </div>
          <div class="right">
            <el-button @click="stripWhitespaceSign">删除空格和换行</el-button>
            <el-button type="danger" plain @click="clearSign">清除</el-button>
          </div>
        </div>
        <div v-if="sv.result" class="result mono">{{ sv.result }}</div>
      </el-tab-pane>

      <el-tab-pane label="P7 签名解析" name="parse">
        <div class="label"><span class="req">*</span> p7数据</div>
        <div class="row">
          <el-radio-group v-model="ps.fmt" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ ps.input.length }}字节</el-tag>
          <el-button size="small" text @click="copy(ps.input)">复制</el-button>
        </div>
        <el-input v-model="ps.input" type="textarea" :rows="6" placeholder="请输入或上传p7签名数据" />

        <div class="actions">
          <el-button type="primary" :loading="loading" @click="doParse">开始分析</el-button>
          <div class="right">
            <el-button @click="stripWhitespaceParse">删除空格和换行</el-button>
            <el-button type="danger" plain @click="clearParse">清除</el-button>
          </div>
        </div>

        <div v-if="ps.result" class="parse-result">
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="类型">
              <el-tag :type="ps.result.type === 'attached' ? 'success' : 'warning'" effect="plain">
                {{ ps.result.type === 'attached' ? 'Attached（含原文）' : 'Detached（不含原文）' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="签名者数量">{{ ps.result.signers?.length || 0 }}</el-descriptions-item>
            <el-descriptions-item label="证书数量">{{ ps.result.certificateCount || 0 }}</el-descriptions-item>
            <el-descriptions-item label="内容类型">{{ ps.result.contentTypeOid || '-' }}</el-descriptions-item>
          </el-descriptions>

          <div v-if="ps.result.signers && ps.result.signers.length > 0" class="section">
            <div class="sub">签名者信息</div>
            <el-table :data="ps.result.signers" size="small" border>
              <el-table-column prop="version" label="版本" width="70" />
              <el-table-column prop="digestAlgorithm" label="摘要算法" width="140" />
              <el-table-column prop="signatureAlgorithm" label="签名算法" width="160" />
              <el-table-column label="签名者标识">
                <template #default="{ row }">
                  <div class="mono small">{{ row.signerId?.issuer || '' }}<br/>SN: {{ row.signerId?.serialNumber || '' }}</div>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <div v-if="ps.result.certificates && ps.result.certificates.length > 0" class="section">
            <div class="sub">证书列表</div>
            <el-table :data="ps.result.certificates" size="small" border>
              <el-table-column prop="subject" label="主题" />
              <el-table-column prop="issuer" label="颁发者" />
              <el-table-column prop="serialNumber" label="序列号" width="160">
                <template #default="{ row }">
                  <span class="mono small">{{ row.serialNumber }}</span>
                </template>
              </el-table-column>
              <el-table-column prop="notBefore" label="生效时间" width="180" />
              <el-table-column prop="notAfter" label="过期时间" width="180" />
            </el-table>
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { Upload as ElIconUpload } from '@element-plus/icons-vue'
import api from '../../api'

const tab = ref('sign')
const loading = ref(false)

const sv = reactive({
  cert: '', certFmt: 'hex',
  privateKey: '', privFmt: 'utf8',
  mode: 'attach',
  message: '', msgFmt: 'utf8',
  signature: '', sigFmt: 'hex',
  result: ''
})

const ps = reactive({
  input: '', fmt: 'hex',
  result: null
})

async function run(fn) {
  loading.value = true
  try { return await fn() } finally { loading.value = false }
}

function copy(v) {
  if (!v) return
  navigator.clipboard.writeText(v)
  ElMessage.success('已复制')
}

function strip(s) { return (s || '').replace(/\s/g, '') }

function stripWhitespaceSign() {
  sv.cert = strip(sv.cert)
  sv.privateKey = strip(sv.privateKey)
  sv.message = strip(sv.message)
  sv.signature = strip(sv.signature)
}
function clearSign() {
  sv.cert = ''; sv.privateKey = ''; sv.message = ''; sv.signature = ''; sv.result = ''
}

function stripWhitespaceParse() {
  ps.input = strip(ps.input)
}
function clearParse() {
  ps.input = ''; ps.result = null
}

async function doSign() {
  if (!sv.cert) return ElMessage.warning('请输入签名证书')
  if (!sv.privateKey) return ElMessage.warning('请输入私钥')
  if (!sv.message) return ElMessage.warning('请输入消息')
  const r = await run(() => api.post('/pkcs7/sign', {
    cert: sv.cert, certFormat: sv.certFmt,
    privateKey: sv.privateKey, privateKeyFormat: sv.privFmt,
    message: sv.message, messageFormat: sv.msgFmt,
    mode: sv.mode,
    outputFormat: sv.sigFmt
  }))
  sv.signature = r.signature
  sv.result = `签名成功，模式：${r.mode}`
  ElMessage.success('签名成功')
}

async function doVerify() {
  if (!sv.signature) return ElMessage.warning('请输入签名值')
  const r = await run(() => api.post('/pkcs7/verify', {
    signature: sv.signature, signatureFormat: sv.sigFmt,
    message: sv.mode === 'detach' ? sv.message : '',
    messageFormat: sv.msgFmt
  }))
  sv.result = r.verified ? '验签通过 ✓' : '验签失败 ✗'
  ElMessage[r.verified ? 'success' : 'warning'](sv.result)
}

async function doParse() {
  if (!ps.input) return ElMessage.warning('请输入p7数据')
  const r = await run(() => api.post('/pkcs7/parse', {
    input: ps.input, format: ps.fmt
  }))
  ps.result = r
  ElMessage.success('解析完成')
}
</script>

<style scoped>
.pkcs7-workbench {
  background: #fff;
  border-radius: 12px;
  padding: 20px 24px;
  box-shadow: 0 2px 12px rgba(0,0,0,.05);
}
.title { font-size: 18px; font-weight: 600; margin-bottom: 16px; }
.sub { font-size: 14px; font-weight: 600; margin-bottom: 10px; }
.label { font-size: 13px; color: #606266; margin-bottom: 6px; }
.req { color: #f56c6c; margin-right: 4px; }
.row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.spacer { flex: 1; }
.hint2 {
  margin-top: 6px;
  font-size: 12px;
  color: #909399;
  padding-left: 4px;
}
.actions {
  margin-top: 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
}
.actions .left, .actions .right { display: flex; gap: 8px; }
.result {
  margin-top: 16px;
  padding: 12px 16px;
  background: #f5f7fa;
  border-radius: 6px;
  font-size: 13px;
}
.parse-result { margin-top: 20px; }
.section { margin-top: 20px; }
.mono { font-family: Consolas, Menlo, monospace; word-break: break-all; }
.small { font-size: 12px; }
</style>
