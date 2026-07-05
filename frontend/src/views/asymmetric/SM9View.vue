<template>
  <el-card>
    <div class="title">SM9 工作台</div>

    <el-tabs v-model="tab">
      <!-- ============ 1 曲线参数 ============ -->
      <el-tab-pane label="曲线参数" name="curve">
        <el-descriptions :column="1" border class="curve">
          <el-descriptions-item label="曲线方程"><span class="mono">{{ curve.curveEquation }}</span></el-descriptions-item>
          <el-descriptions-item label="嵌入度 t"><span class="mono">{{ curve.t }}</span></el-descriptions-item>
          <el-descriptions-item label="素数 p"><span class="mono">{{ curve.p }}</span></el-descriptions-item>
          <el-descriptions-item label="阶 n"><span class="mono">{{ curve.n }}</span></el-descriptions-item>
          <el-descriptions-item label="G1 生成元 x"><span class="mono">{{ curve.g1X }}</span></el-descriptions-item>
          <el-descriptions-item label="G1 生成元 y"><span class="mono">{{ curve.g1Y }}</span></el-descriptions-item>
          <el-descriptions-item label="G2 生成元 x"><span class="mono">{{ curve.g2X }}</span></el-descriptions-item>
          <el-descriptions-item label="G2 生成元 y"><span class="mono">{{ curve.g2Y }}</span></el-descriptions-item>
        </el-descriptions>
      </el-tab-pane>

      <!-- ============ 2 密钥运算 ============ -->
      <el-tab-pane label="密钥运算" name="keyop">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 主公钥</div>
            <div class="row">
              <el-radio-group v-model="ko.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(ko.publicKey) }} 字节</span>
              <el-button size="small" @click="copy(ko.publicKey)">复制</el-button>
            </div>
            <el-input v-model="ko.publicKey" type="textarea" :rows="4" />
          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 主私钥</div>
            <div class="row">
              <el-radio-group v-model="ko.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(ko.privateKey) }} 字节</span>
              <el-button size="small" @click="copy(ko.privateKey)">复制</el-button>
            </div>
            <el-input v-model="ko.privateKey" type="textarea" :rows="2" />
          </el-col>
        </el-row>

        <el-row :gutter="24" style="margin-top:16px">
          <el-col :span="12">
            <div class="label">密钥类型</div>
            <el-radio-group v-model="ko.keyType">
              <el-radio value="sign">签名密钥</el-radio>
              <el-radio value="encrypt">加密密钥</el-radio>
            </el-radio-group>
          </el-col>
          <el-col :span="12">
            <div class="label">用户标识</div>
            <el-input v-model="ko.userId" placeholder="如：test@example.com" />
          </el-col>
        </el-row>

        <el-row :gutter="24" style="margin-top:16px">
          <el-col :span="24">
            <div class="label">用户私钥</div>
            <div class="row">
              <el-radio-group v-model="ko.userPrivFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(ko.userPrivateKey) }} 字节</span>
              <el-button size="small" @click="copy(ko.userPrivateKey)">复制</el-button>
            </div>
            <el-input v-model="ko.userPrivateKey" type="textarea" :rows="3" readonly />
          </el-col>
        </el-row>

        <div class="actions">
          <el-button :loading="loading" @click="genMasterKey">生成主密钥对</el-button>
          <el-button :loading="loading" @click="genUserKey">生成用户私钥</el-button>
          <el-button type="primary" @click="cleanKo">删除空格和换行</el-button>
          <el-button type="danger" plain @click="resetKo">清除</el-button>
        </div>
      </el-tab-pane>

      <!-- ============ 3 签名验签 ============ -->
      <el-tab-pane label="签名验签" name="sign">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 签名主公钥</div>
            <div class="row">
              <el-radio-group v-model="sg.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(sg.publicKey) }} 字节</span>
              <el-button size="small" @click="copy(sg.publicKey)">复制</el-button>
            </div>
            <el-input v-model="sg.publicKey" type="textarea" :rows="3" />

            <div class="label" style="margin-top:12px">用户标识</div>
            <el-input v-model="sg.userId" placeholder="如：test@example.com" />

            <div class="label" style="margin-top:12px"><span class="req">*</span> 消息</div>
            <div class="row">
              <el-radio-group v-model="sg.msgFmt" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ byteLen(sg.message, sg.msgFmt) }} 字节</span>
              <el-button size="small" @click="copy(sg.message)">复制</el-button>
            </div>
            <el-input v-model="sg.message" type="textarea" :rows="3" />
          </el-col>

          <el-col :span="12">
            <div class="label"><span class="req">*</span> 用户签名私钥</div>
            <div class="row">
              <el-radio-group v-model="sg.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(sg.privateKey) }} 字节</span>
              <el-button size="small" @click="copy(sg.privateKey)">复制</el-button>
            </div>
            <el-input v-model="sg.privateKey" type="textarea" :rows="2" />

            <div class="label" style="margin-top:12px"><span class="req">*</span> 签名值</div>
            <div class="row">
              <el-radio-group v-model="sg.sigFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(sg.signature) }} 字节</span>
              <el-button size="small" @click="copy(sg.signature)">复制</el-button>
            </div>
            <el-input v-model="sg.signature" type="textarea" :rows="4" />
          </el-col>
        </el-row>

        <div class="actions">
          <el-button :loading="loading" @click="doSign">签名</el-button>
          <el-button :loading="loading" @click="doVerify">验签</el-button>
          <el-button type="primary" @click="cleanSg">删除空格和换行</el-button>
          <el-button type="danger" plain @click="resetSg">清除</el-button>
        </div>

        <div v-if="sg.result" class="result" :class="sg.resultType">
          {{ sg.result }}
        </div>
      </el-tab-pane>

      <!-- ============ 4 加密解密 ============ -->
      <el-tab-pane label="加密解密" name="encrypt">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 加密主公钥</div>
            <div class="row">
              <el-radio-group v-model="en.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(en.publicKey) }} 字节</span>
              <el-button size="small" @click="copy(en.publicKey)">复制</el-button>
            </div>
            <el-input v-model="en.publicKey" type="textarea" :rows="3" />

            <div class="label" style="margin-top:12px">用户标识</div>
            <el-input v-model="en.userId" placeholder="如：test@example.com" />

            <div class="label" style="margin-top:12px">加密模式</div>
            <el-radio-group v-model="en.mode">
              <el-radio value="block">分组密码</el-radio>
              <el-radio value="stream">流密码</el-radio>
            </el-radio-group>

            <div class="label" style="margin-top:12px"><span class="req">*</span> 明文</div>
            <div class="row">
              <el-radio-group v-model="en.plainFmt" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ byteLen(en.plaintext, en.plainFmt) }} 字节</span>
              <el-button size="small" @click="copy(en.plaintext)">复制</el-button>
            </div>
            <el-input v-model="en.plaintext" type="textarea" :rows="3" />
          </el-col>

          <el-col :span="12">
            <div class="label"><span class="req">*</span> 用户解密私钥</div>
            <div class="row">
              <el-radio-group v-model="en.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(en.privateKey) }} 字节</span>
              <el-button size="small" @click="copy(en.privateKey)">复制</el-button>
            </div>
            <el-input v-model="en.privateKey" type="textarea" :rows="2" />

            <div class="label" style="margin-top:12px"><span class="req">*</span> 密文</div>
            <div class="row">
              <el-radio-group v-model="en.cipherFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(en.ciphertext) }} 字节</span>
              <el-button size="small" @click="copy(en.ciphertext)">复制</el-button>
            </div>
            <el-input v-model="en.ciphertext" type="textarea" :rows="5" />
          </el-col>
        </el-row>

        <div class="actions">
          <el-button :loading="loading" @click="doEncrypt">加密</el-button>
          <el-button :loading="loading" @click="doDecrypt">解密</el-button>
          <el-button type="primary" @click="cleanEn">删除空格和换行</el-button>
          <el-button type="danger" plain @click="resetEn">清除</el-button>
        </div>
      </el-tab-pane>

      <!-- ============ 5 密钥封装 ============ -->
      <el-tab-pane label="密钥封装" name="kem">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 加密主公钥</div>
            <div class="row">
              <el-radio-group v-model="km.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(km.publicKey) }} 字节</span>
              <el-button size="small" @click="copy(km.publicKey)">复制</el-button>
            </div>
            <el-input v-model="km.publicKey" type="textarea" :rows="3" />

            <div class="label" style="margin-top:12px">用户标识</div>
            <el-input v-model="km.userId" placeholder="如：test@example.com" />

            <div class="label" style="margin-top:12px">共享密钥</div>
            <div class="row">
              <el-radio-group v-model="km.keyFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(km.sharedKey) }} 字节</span>
              <el-button size="small" @click="copy(km.sharedKey)">复制</el-button>
            </div>
            <el-input v-model="km.sharedKey" type="textarea" :rows="2" readonly />
          </el-col>

          <el-col :span="12">
            <div class="label"><span class="req">*</span> 用户解封装私钥</div>
            <div class="row">
              <el-radio-group v-model="km.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(km.privateKey) }} 字节</span>
              <el-button size="small" @click="copy(km.privateKey)">复制</el-button>
            </div>
            <el-input v-model="km.privateKey" type="textarea" :rows="2" />

            <div class="label" style="margin-top:12px"><span class="req">*</span> 封装密钥</div>
            <div class="row">
              <el-radio-group v-model="km.cipherFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(km.encapsulatedKey) }} 字节</span>
              <el-button size="small" @click="copy(km.encapsulatedKey)">复制</el-button>
            </div>
            <el-input v-model="km.encapsulatedKey" type="textarea" :rows="3" />
          </el-col>
        </el-row>

        <div class="actions">
          <el-button :loading="loading" @click="doEncapsulate">封装</el-button>
          <el-button :loading="loading" @click="doDecapsulate">解封装</el-button>
          <el-button type="primary" @click="cleanKm">删除空格和换行</el-button>
          <el-button type="danger" plain @click="resetKm">清除</el-button>
        </div>
      </el-tab-pane>

      <!-- ============ 6 密钥协商 ============ -->
      <el-tab-pane label="密钥协商" name="exchange">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 用户A私钥</div>
            <div class="row">
              <el-radio-group v-model="ex.privFmtA" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(ex.privateKeyA) }} 字节</span>
              <el-button size="small" @click="copy(ex.privateKeyA)">复制</el-button>
            </div>
            <el-input v-model="ex.privateKeyA" type="textarea" :rows="2" />

            <div class="label" style="margin-top:12px">用户A标识</div>
            <el-input v-model="ex.userIdA" placeholder="如：alice@example.com" />
          </el-col>

          <el-col :span="12">
            <div class="label"><span class="req">*</span> 用户B主公钥</div>
            <div class="row">
              <el-radio-group v-model="ex.pubFmtB" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" /><span class="bytes">{{ hexBytes(ex.publicKeyB) }} 字节</span>
              <el-button size="small" @click="copy(ex.publicKeyB)">复制</el-button>
            </div>
            <el-input v-model="ex.publicKeyB" type="textarea" :rows="3" />

            <div class="label" style="margin-top:12px">用户B标识</div>
            <el-input v-model="ex.userIdB" placeholder="如：bob@example.com" />
          </el-col>
        </el-row>

        <div class="actions">
          <el-button :loading="loading" @click="doExchange">执行密钥协商</el-button>
          <el-button type="primary" @click="cleanEx">删除空格和换行</el-button>
          <el-button type="danger" plain @click="resetEx">清除</el-button>
        </div>

        <el-descriptions v-if="ex.result" :column="2" border class="result-box">
          <el-descriptions-item label="临时公钥 RA">{{ ex.result.RA }}</el-descriptions-item>
          <el-descriptions-item label="共享密钥">{{ ex.result.sharedKey }}</el-descriptions-item>
          <el-descriptions-item label="密钥长度">{{ ex.result.keyLength }} 字节</el-descriptions-item>
        </el-descriptions>
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const tab = ref('curve')
const loading = ref(false)

// ---------- 通用工具 ----------
function hexBytes(s) { if (!s) return 0; const t = s.replace(/[\s:]/g,''); return Math.floor(t.length/2) }
function byteLen(str, fmt) {
  if (!str) return 0
  try {
    if (fmt === 'hex') return Math.floor(str.replace(/\s/g,'').length/2)
    if (fmt === 'base64') { const s=str.replace(/\s/g,''); return Math.floor(s.replace(/=+$/,'').length*3/4) }
    return new TextEncoder().encode(str).length
  } catch { return 0 }
}
function copy(t) { if (t) navigator.clipboard.writeText(t).then(()=>ElMessage.success('已复制')) }
async function run(fn) { loading.value=true; try { return await fn() } finally { loading.value=false } }

// ---------- 1 曲线参数 ----------
const curve = reactive({ curveEquation:'', t:'', p:'', n:'', g1X:'', g1Y:'', g2X:'', g2Y:'' })
async function loadCurve() {
  try { Object.assign(curve, await api.get('/sm9/curve-params')) } catch {}
}
onMounted(loadCurve)

// ---------- 2 密钥运算 ----------
const ko = reactive({
  publicKey:'', privateKey:'', pubFmt:'hex', privFmt:'hex',
  keyType:'sign', userId:'test@example.com',
  userPrivateKey:'', userPrivFmt:'hex'
})
async function genMasterKey() {
  const k = await run(()=>api.post('/sm9/master-key-pair', { type: ko.keyType }))
  ko.publicKey = k.masterPublicKey; ko.privateKey = k.masterPrivateKey
  ElMessage.success('已生成主密钥对')
}
async function genUserKey() {
  if (!ko.privateKey) return ElMessage.warning('请先生成或填写主私钥')
  if (!ko.userId) return ElMessage.warning('请填写用户标识')
  const r = await run(()=>api.post('/sm9/user-key', { type: ko.keyType, masterPrivateKey: ko.privateKey, userId: ko.userId }))
  ko.userPrivateKey = r.userPrivateKey
  ElMessage.success('已生成用户私钥')
}
function cleanKo() {
  ko.publicKey=ko.publicKey.replace(/[\s\r\n]/g,'')
  ko.privateKey=ko.privateKey.replace(/[\s\r\n]/g,'')
  ko.userPrivateKey=ko.userPrivateKey.replace(/[\s\r\n]/g,'')
}
function resetKo() { ko.publicKey=''; ko.privateKey=''; ko.userPrivateKey=''; ko.userId='test@example.com' }

// ---------- 3 签名验签 ----------
const sg = reactive({
  publicKey:'', privateKey:'', pubFmt:'hex', privFmt:'hex',
  userId:'test@example.com',
  message:'', msgFmt:'utf8',
  signature:'', sigFmt:'hex',
  result:'', resultType:'success'
})
async function doSign() {
  if (!sg.publicKey) return ElMessage.warning('请填写签名主公钥')
  if (!sg.privateKey) return ElMessage.warning('请填写用户签名私钥')
  if (!sg.message) return ElMessage.warning('请填写消息')
  const r = await run(()=>api.post('/sm9/sign', {
    masterPublicKey: sg.publicKey,
    userPrivateKey: sg.privateKey,
    userId: sg.userId,
    message: sg.message
  }))
  sg.signature = r.signature
  sg.result = '签名成功'
  sg.resultType = 'success'
  ElMessage.success('签名成功')
}
async function doVerify() {
  if (!sg.publicKey) return ElMessage.warning('请填写签名主公钥')
  if (!sg.userId) return ElMessage.warning('请填写用户标识')
  if (!sg.message) return ElMessage.warning('请填写消息')
  if (!sg.signature) return ElMessage.warning('请填写签名值')
  const r = await run(()=>api.post('/sm9/verify', {
    masterPublicKey: sg.publicKey,
    userId: sg.userId,
    message: sg.message,
    signature: sg.signature
  }))
  sg.result = r.message
  sg.resultType = r.verified ? 'success' : 'error'
  ElMessage[r.verified ? 'success' : 'error'](r.message)
}
function cleanSg() {
  sg.publicKey=sg.publicKey.replace(/[\s\r\n]/g,'')
  sg.privateKey=sg.privateKey.replace(/[\s\r\n]/g,'')
  sg.message=sg.message.replace(/[\s\r\n]/g,'')
  sg.signature=sg.signature.replace(/[\s\r\n]/g,'')
}
function resetSg() { sg.publicKey=''; sg.privateKey=''; sg.message=''; sg.signature=''; sg.result='' }

// ---------- 4 加密解密 ----------
const en = reactive({
  publicKey:'', privateKey:'', pubFmt:'hex', privFmt:'hex',
  userId:'test@example.com',
  mode:'block',
  plaintext:'', plainFmt:'utf8',
  ciphertext:'', cipherFmt:'hex'
})
async function doEncrypt() {
  if (!en.publicKey) return ElMessage.warning('请填写加密主公钥')
  if (!en.userId) return ElMessage.warning('请填写用户标识')
  if (!en.plaintext) return ElMessage.warning('请填写明文')
  const r = await run(()=>api.post('/sm9/encrypt', {
    masterPublicKey: en.publicKey,
    userId: en.userId,
    message: en.plaintext,
    mode: en.mode
  }))
  en.ciphertext = r.ciphertext
  ElMessage.success('加密成功')
}
async function doDecrypt() {
  if (!en.privateKey) return ElMessage.warning('请填写用户解密私钥')
  if (!en.ciphertext) return ElMessage.warning('请填写密文')
  const r = await run(()=>api.post('/sm9/decrypt', {
    userPrivateKey: en.privateKey,
    ciphertext: en.ciphertext,
    mode: en.mode
  }))
  en.plaintext = r.plaintext
  ElMessage.success('解密成功')
}
function cleanEn() {
  en.publicKey=en.publicKey.replace(/[\s\r\n]/g,'')
  en.privateKey=en.privateKey.replace(/[\s\r\n]/g,'')
  en.plaintext=en.plaintext.replace(/[\s\r\n]/g,'')
  en.ciphertext=en.ciphertext.replace(/[\s\r\n]/g,'')
}
function resetEn() { en.publicKey=''; en.privateKey=''; en.plaintext=''; en.ciphertext='' }

// ---------- 5 密钥封装 ----------
const km = reactive({
  publicKey:'', privateKey:'', pubFmt:'hex', privFmt:'hex',
  userId:'test@example.com',
  sharedKey:'', keyFmt:'hex',
  encapsulatedKey:'', cipherFmt:'hex'
})
async function doEncapsulate() {
  if (!km.publicKey) return ElMessage.warning('请填写加密主公钥')
  if (!km.userId) return ElMessage.warning('请填写用户标识')
  const r = await run(()=>api.post('/sm9/encapsulate', {
    masterPublicKey: km.publicKey,
    userId: km.userId
  }))
  km.encapsulatedKey = r.encapsulatedKey
  km.sharedKey = r.sharedKey
  ElMessage.success('密钥封装成功')
}
async function doDecapsulate() {
  if (!km.privateKey) return ElMessage.warning('请填写用户解封装私钥')
  if (!km.encapsulatedKey) return ElMessage.warning('请填写封装密钥')
  const r = await run(()=>api.post('/sm9/decapsulate', {
    userPrivateKey: km.privateKey,
    encapsulatedKey: km.encapsulatedKey
  }))
  km.sharedKey = r.sharedKey
  ElMessage.success('密钥解封装成功')
}
function cleanKm() {
  km.publicKey=km.publicKey.replace(/[\s\r\n]/g,'')
  km.privateKey=km.privateKey.replace(/[\s\r\n]/g,'')
  km.sharedKey=km.sharedKey.replace(/[\s\r\n]/g,'')
  km.encapsulatedKey=km.encapsulatedKey.replace(/[\s\r\n]/g,'')
}
function resetKm() { km.publicKey=''; km.privateKey=''; km.sharedKey=''; km.encapsulatedKey='' }

// ---------- 6 密钥协商 ----------
const ex = reactive({
  privateKeyA:'', privFmtA:'hex',
  userIdA:'alice@example.com',
  publicKeyB:'', pubFmtB:'hex',
  userIdB:'bob@example.com',
  result: null
})
async function doExchange() {
  if (!ex.privateKeyA) return ElMessage.warning('请填写用户A私钥')
  if (!ex.userIdA) return ElMessage.warning('请填写用户A标识')
  if (!ex.publicKeyB) return ElMessage.warning('请填写用户B主公钥')
  if (!ex.userIdB) return ElMessage.warning('请填写用户B标识')
  const r = await run(()=>api.post('/sm9/key-agreement', {
    privateKeyA: ex.privateKeyA,
    userIdA: ex.userIdA,
    publicKeyB: ex.publicKeyB,
    userIdB: ex.userIdB
  }))
  ex.result = r
  ElMessage.success('密钥协商成功')
}
function cleanEx() {
  ex.privateKeyA=ex.privateKeyA.replace(/[\s\r\n]/g,'')
  ex.publicKeyB=ex.publicKeyB.replace(/[\s\r\n]/g,'')
}
function resetEx() { ex.privateKeyA=''; ex.publicKeyB=''; ex.result=null }
</script>

<style scoped>
.title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
}
.label {
  font-size: 13px;
  color: #606266;
  margin-bottom: 6px;
}
.req {
  color: #f56c6c;
  margin-right: 4px;
}
.row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}
.spacer {
  flex: 1;
}
.bytes {
  color: #909399;
  font-size: 12px;
}
.actions {
  margin-top: 16px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.result {
  margin-top: 12px;
  padding: 10px 14px;
  border-radius: 4px;
  font-size: 14px;
}
.result.success {
  background: #f0f9eb;
  color: #67c23a;
  border: 1px solid #e1f3d8;
}
.result.error {
  background: #fef0f0;
  color: #f56c6c;
  border: 1px solid #fde2e2;
}
.result-box {
  margin-top: 16px;
}
.mono {
  font-family: monospace;
  font-size: 12px;
}
.curve {
  max-width: 900px;
}
</style>
