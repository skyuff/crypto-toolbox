<template>
  <div class="ecdsa-workbench">
    <div class="title">ECDSA 算法</div>
    <el-tabs v-model="tab">
      <el-tab-pane label="密钥运算" name="key">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label">公钥</div>
            <div class="row">
              <el-radio-group v-model="ko.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ ko.publicKey.length }}字节</el-tag>
              <el-button size="small" text @click="copy(ko.publicKey)">复制</el-button>
            </div>
            <el-input v-model="ko.publicKey" type="textarea" :rows="5" placeholder="请输入对应数据格式的数据" />
          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 私钥</div>
            <div class="row">
              <el-radio-group v-model="ko.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ ko.privateKey.length }}字节</el-tag>
              <el-button size="small" text @click="copy(ko.privateKey)">复制</el-button>
            </div>
            <el-input v-model="ko.privateKey" type="textarea" :rows="5" placeholder="请输入对应数据格式的数据" />
          </el-col>
        </el-row>
        <el-row :gutter="24" style="margin-top:16px">
          <el-col :span="12">
            <div class="label">椭圆曲线</div>
            <el-select v-model="ko.curve" style="width:100%">
              <el-option label="secp256r1 (P-256)" value="secp256r1" />
              <el-option label="secp384r1 (P-384)" value="secp384r1" />
              <el-option label="secp521r1 (P-521)" value="secp521r1" />
              <el-option label="secp256k1" value="secp256k1" />
            </el-select>
          </el-col>
        </el-row>
        <div class="actions">
          <el-button type="primary" :loading="loading" @click="genKey">生成密钥对</el-button>
          <div class="right">
            <el-button @click="stripWhitespaceKey">删除空格和换行</el-button>
            <el-button type="danger" plain @click="clearKey">清除</el-button>
          </div>
        </div>
      </el-tab-pane>

      <el-tab-pane label="签名验签" name="sign">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label">公钥</div>
            <div class="row">
              <el-radio-group v-model="sg.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ sg.publicKey.length }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.publicKey)">复制</el-button>
            </div>
            <el-input v-model="sg.publicKey" type="textarea" :rows="4" placeholder="请输入对应数据格式的数据" />
          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 私钥</div>
            <div class="row">
              <el-radio-group v-model="sg.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ sg.privateKey.length }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.privateKey)">复制</el-button>
            </div>
            <el-input v-model="sg.privateKey" type="textarea" :rows="4" placeholder="请输入对应数据格式的数据" />
          </el-col>
        </el-row>
        <el-row :gutter="24" style="margin-top:16px">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 消息</div>
            <div class="row">
              <el-radio-group v-model="sg.msgFmt" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ sg.message.length }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.message)">复制</el-button>
            </div>
            <el-input v-model="sg.message" type="textarea" :rows="4" placeholder="请输入对应数据格式的数据" />
          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 签名值</div>
            <div class="row">
              <el-radio-group v-model="sg.sigFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ sg.signature.length }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.signature)">复制</el-button>
            </div>
            <el-input v-model="sg.signature" type="textarea" :rows="4" placeholder="请输入签名值der编码" />
          </el-col>
        </el-row>
        <el-row :gutter="24" style="margin-top:16px">
          <el-col :span="12">
            <div class="label">椭圆曲线</div>
            <el-select v-model="sg.curve" style="width:100%">
              <el-option label="secp256r1 (P-256)" value="secp256r1" />
              <el-option label="secp384r1 (P-384)" value="secp384r1" />
              <el-option label="secp521r1 (P-521)" value="secp521r1" />
              <el-option label="secp256k1" value="secp256k1" />
            </el-select>
          </el-col>
          <el-col :span="12">
            <div class="label">哈希算法</div>
            <el-select v-model="sg.hash" style="width:100%">
              <el-option label="SHA1" value="SHA1" />
              <el-option label="SHA256" value="SHA256" />
              <el-option label="SHA384" value="SHA384" />
              <el-option label="SHA512" value="SHA512" />
            </el-select>
          </el-col>
        </el-row>
        <div class="actions">
          <div class="left">
            <el-button type="primary" :loading="loading" @click="doSign">签名</el-button>
            <el-button :loading="loading" @click="doVerify">验签</el-button>
          </div>
        </div>
        <div v-if="sg.result" class="result mono">{{ sg.result }}</div>
      </el-tab-pane>

      <el-tab-pane label="加密解密" name="enc">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label">公钥</div>
            <div class="row">
              <el-radio-group v-model="en.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ en.publicKey.length }}字节</el-tag>
              <el-button size="small" text @click="copy(en.publicKey)">复制</el-button>
            </div>
            <el-input v-model="en.publicKey" type="textarea" :rows="4" placeholder="请输入对应数据格式的数据" />
          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 私钥</div>
            <div class="row">
              <el-radio-group v-model="en.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ en.privateKey.length }}字节</el-tag>
              <el-button size="small" text @click="copy(en.privateKey)">复制</el-button>
            </div>
            <el-input v-model="en.privateKey" type="textarea" :rows="4" placeholder="请输入对应数据格式的数据" />
          </el-col>
        </el-row>
        <el-row :gutter="24" style="margin-top:16px">
          <el-col :span="12">
            <div class="label">消息</div>
            <div class="row">
              <el-radio-group v-model="en.msgFmt" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ en.message.length }}字节</el-tag>
              <el-button size="small" text @click="copy(en.message)">复制</el-button>
            </div>
            <el-input v-model="en.message" type="textarea" :rows="4" placeholder="请输入对应数据格式的数据" />
          </el-col>
          <el-col :span="12">
            <div class="label">密文</div>
            <div class="row">
              <el-radio-group v-model="en.cipherFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ en.cipher.length }}字节</el-tag>
              <el-button size="small" text @click="copy(en.cipher)">复制</el-button>
            </div>
            <el-input v-model="en.cipher" type="textarea" :rows="4" placeholder="请输入对应数据格式的数据" />
          </el-col>
        </el-row>
        <el-row :gutter="24" style="margin-top:16px">
          <el-col :span="12">
            <div class="label">椭圆曲线</div>
            <el-select v-model="en.curve" style="width:100%">
              <el-option label="secp256r1 (P-256)" value="secp256r1" />
              <el-option label="secp384r1 (P-384)" value="secp384r1" />
              <el-option label="secp521r1 (P-521)" value="secp521r1" />
              <el-option label="secp256k1" value="secp256k1" />
            </el-select>
          </el-col>
        </el-row>
        <div class="actions">
          <div class="left">
            <el-button type="primary" :loading="loading" @click="doEncrypt">加密</el-button>
            <el-button :loading="loading" @click="doDecrypt">解密</el-button>
          </div>
          <div class="right">
            <el-button @click="stripWhitespaceEnc">删除空格和换行</el-button>
            <el-button type="danger" plain @click="clearEnc">清除</el-button>
          </div>
        </div>
        <div v-if="en.result" class="result mono">{{ en.result }}</div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const tab = ref('key')
const loading = ref(false)

const ko = reactive({
  publicKey: '', privateKey: '',
  pubFmt: 'hex', privFmt: 'hex',
  curve: 'secp256r1'
})

const sg = reactive({
  publicKey: '', privateKey: '',
  pubFmt: 'hex', privFmt: 'hex',
  message: '', msgFmt: 'utf8',
  signature: '', sigFmt: 'hex',
  curve: 'secp256r1',
  hash: 'SHA256',
  result: ''
})

const en = reactive({
  publicKey: '', privateKey: '',
  pubFmt: 'hex', privFmt: 'hex',
  message: '', msgFmt: 'utf8',
  cipher: '', cipherFmt: 'hex',
  curve: 'secp256r1',
  result: ''
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

function stripWhitespaceKey() {
  ko.publicKey = strip(ko.publicKey)
  ko.privateKey = strip(ko.privateKey)
}
function clearKey() { ko.publicKey = ''; ko.privateKey = '' }

function stripWhitespaceEnc() {
  en.publicKey = strip(en.publicKey)
  en.privateKey = strip(en.privateKey)
  en.message = strip(en.message)
  en.cipher = strip(en.cipher)
}
function clearEnc() {
  en.publicKey = ''; en.privateKey = ''
  en.message = ''; en.cipher = ''
  en.result = ''
}

async function genKey() {
  const r = await run(() => api.post('/ecdsa/keypair', { curve: ko.curve }))
  if (ko.pubFmt === 'hex') ko.publicKey = r.publicKeyHex
  else ko.publicKey = r.publicKey.replace(/-----\w+ KEY-----/g, '').replace(/\s/g, '')
  if (ko.privFmt === 'hex') ko.privateKey = r.privateKeyHex
  else ko.privateKey = r.privateKey.replace(/-----\w+ KEY-----/g, '').replace(/\s/g, '')
  ElMessage.success('密钥对已生成')
}

async function doSign() {
  if (!sg.privateKey) return ElMessage.warning('请输入私钥')
  if (!sg.message) return ElMessage.warning('请输入消息')
  const r = await run(() => api.post('/ecdsa/sign', {
    privateKey: sg.privateKey,
    privateKeyFormat: sg.privFmt,
    input: sg.message,
    inputFormat: sg.msgFmt,
    outputFormat: sg.sigFmt,
    hash: sg.hash
  }))
  sg.signature = r.signature
  sg.result = `签名成功，算法：${r.algorithm}`
  ElMessage.success('签名成功')
}

async function doVerify() {
  if (!sg.publicKey) return ElMessage.warning('请输入公钥')
  if (!sg.message) return ElMessage.warning('请输入消息')
  if (!sg.signature) return ElMessage.warning('请输入签名值')
  const r = await run(() => api.post('/ecdsa/verify', {
    publicKey: sg.publicKey,
    publicKeyFormat: sg.pubFmt,
    input: sg.message,
    inputFormat: sg.msgFmt,
    signature: sg.signature,
    signatureFormat: sg.sigFmt,
    hash: sg.hash
  }))
  sg.result = r.verified ? '验签通过 ✓' : '验签失败 ✗'
  ElMessage[r.verified ? 'success' : 'warning'](sg.result)
}

async function doEncrypt() {
  if (!en.publicKey) return ElMessage.warning('请输入公钥')
  if (!en.message) return ElMessage.warning('请输入消息')
  const r = await run(() => api.post('/ecdsa/encrypt', {
    publicKey: en.publicKey,
    publicKeyFormat: en.pubFmt,
    input: en.message,
    inputFormat: en.msgFmt,
    outputFormat: en.cipherFmt,
    curve: en.curve
  }))
  en.cipher = r.cipher
  en.result = `加密成功，曲线：${r.curve}`
  ElMessage.success('加密成功')
}

async function doDecrypt() {
  if (!en.privateKey) return ElMessage.warning('请输入私钥')
  if (!en.cipher) return ElMessage.warning('请输入密文')
  const r = await run(() => api.post('/ecdsa/decrypt', {
    privateKey: en.privateKey,
    privateKeyFormat: en.privFmt,
    input: en.cipher,
    inputFormat: en.cipherFmt,
    outputFormat: en.msgFmt,
    curve: en.curve
  }))
  en.message = r.plain
  en.result = `解密成功，曲线：${r.curve}`
  ElMessage.success('解密成功')
}
</script>

<style scoped>
.ecdsa-workbench {
  background: #fff;
  border-radius: 12px;
  padding: 20px 24px;
  box-shadow: 0 2px 12px rgba(0,0,0,.05);
}
.title { font-size: 18px; font-weight: 600; margin-bottom: 16px; }
.label { font-size: 13px; color: #606266; margin-bottom: 6px; }
.req { color: #f56c6c; margin-right: 4px; }
.row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.spacer { flex: 1; }
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
.mono { font-family: Consolas, Menlo, monospace; word-break: break-all; }
</style>
