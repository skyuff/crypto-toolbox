<template>
  <el-card>
    <div class="title">SM2 工作台</div>

    <el-tabs v-model="tab">
      <!-- ============ 1 曲线参数 ============ -->
      <el-tab-pane label="曲线参数" name="curve">
        <el-descriptions :column="1" border class="curve">
          <el-descriptions-item label="曲线名称">{{ curve.name }}</el-descriptions-item>
          <el-descriptions-item label="素数 p"><span class="mono">{{ curve.p }}</span></el-descriptions-item>
          <el-descriptions-item label="系数 a"><span class="mono">{{ curve.a }}</span></el-descriptions-item>
          <el-descriptions-item label="系数 b"><span class="mono">{{ curve.b }}</span></el-descriptions-item>
          <el-descriptions-item label="阶 n"><span class="mono">{{ curve.n }}</span></el-descriptions-item>
          <el-descriptions-item label="基点 G.x"><span class="mono">{{ curve.gx }}</span></el-descriptions-item>
          <el-descriptions-item label="基点 G.y"><span class="mono">{{ curve.gy }}</span></el-descriptions-item>
        </el-descriptions>
      </el-tab-pane>

      <!-- ============ 2 密钥运算 ============ -->
      <el-tab-pane label="密钥运算" name="keyop">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 公钥</div>
            <div class="row">
              <el-radio-group v-model="ko.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(ko.publicKey) }}字节</el-tag>
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
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(ko.privateKey) }}字节</el-tag>
              <el-button size="small" text @click="copy(ko.privateKey)">复制</el-button>
            </div>
            <el-input v-model="ko.privateKey" type="textarea" :rows="5" placeholder="请输入对应数据格式的数据" />
          </el-col>
        </el-row>
        <div class="actions">
          <el-button :loading="loading" @click="genKey">生成密钥对</el-button>
          <el-button @click="validateKey">验证公钥</el-button>
          <el-button @click="computePub">计算公钥</el-button>
          <el-button type="primary" @click="cleanKo">删除空格和换行</el-button>
          <el-button type="danger" plain @click="resetKo">清除</el-button>
        </div>
      </el-tab-pane>

      <!-- ============ 3 计算 e 值 ============ -->
      <el-tab-pane label="计算 e 值" name="evalue">
        <div class="label"><span class="req">*</span> 公钥</div>
        <div class="row">
          <el-radio-group v-model="ev.pubFmt" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ hexBytes(ev.publicKey) }}字节</el-tag>
          <el-button size="small" text @click="copy(ev.publicKey)">复制</el-button>
        </div>
        <el-input v-model="ev.publicKey" type="textarea" :rows="3" placeholder="请输入对应数据格式的数据" />

        <el-row :gutter="24" style="margin-top:12px">
          <el-col :span="12">
            <div class="label">用户标识</div>
            <el-input v-model="ev.userId">
              <template #prepend>
                <el-select v-model="ev.userIdFmt" style="width:100px">
                  <el-option label="十六进制" value="hex" />
                  <el-option label="字符串" value="utf8" />
                </el-select>
              </template>
            </el-input>
          </el-col>
          <el-col :span="12">
            <div class="label">Z值</div>
            <el-input v-model="ev.z" readonly>
              <template #prepend>十六进制</template>
            </el-input>
          </el-col>
        </el-row>

        <el-row :gutter="24" style="margin-top:12px">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 消息</div>
            <div class="row">
              <el-radio-group v-model="ev.inputFormat" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ byteLen(ev.input, ev.inputFormat) }}字节</el-tag>
              <el-button size="small" text @click="copy(ev.input)">复制</el-button>
            </div>
            <el-input v-model="ev.input" type="textarea" :rows="5" placeholder="请输入对应数据格式的数据" />

          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> e值</div>
            <div class="row">
              <el-radio-group v-model="ev.eFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(ev.e) }}字节</el-tag>
              <el-button size="small" text @click="copy(ev.e)">复制</el-button>
            </div>
            <el-input v-model="ev.e" type="textarea" :rows="5" readonly placeholder="请输入对应数据格式的数据" />

          </el-col>
        </el-row>
        <div class="actions">
          <el-button :loading="loading" @click="computeEValue">计算</el-button>
          <el-button type="primary" @click="cleanEv">删除空格和换行</el-button>
          <el-button type="danger" plain @click="resetEv">清除</el-button>
        </div>
      </el-tab-pane>

      <!-- ============ 4 私钥解析 ============ -->
      <el-tab-pane label="私钥解析" name="parse">
        <div class="label"><span class="req">*</span> 私钥PEM</div>
        <div class="row">
          <el-radio-group v-model="pp.inputFmt" size="small">
            <el-radio-button value="str">字符串</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ pp.input.length }}字节</el-tag>
          <el-button size="small" text @click="copy(pp.input)">复制</el-button>
        </div>
        <el-input v-model="pp.input" type="textarea" :rows="4" placeholder="支持 64 位 hex 私钥，或 PKCS8/SEC1 PEM/DER" />

        <el-row :gutter="24" style="margin-top:12px">
          <el-col :span="12">
            <div class="label">私钥</div>
            <div class="row">
              <el-radio-group v-model="pp.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(pp.privateKey) }}字节</el-tag>
              <el-button size="small" text @click="copy(pp.privateKey)">复制</el-button>
            </div>
            <el-input v-model="pp.privateKey" type="textarea" :rows="3" readonly />

          </el-col>
          <el-col :span="12">
            <div class="label">公钥</div>
            <div class="row">
              <el-radio-group v-model="pp.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(pp.publicKey) }}字节</el-tag>
              <el-button size="small" text @click="copy(pp.publicKey)">复制</el-button>
            </div>
            <el-input v-model="pp.publicKey" type="textarea" :rows="3" readonly />

          </el-col>
        </el-row>
        <div class="actions">
          <el-button :loading="loading" @click="parsePriv">解析</el-button>
          <el-button type="danger" plain @click="resetPp">清除</el-button>
        </div>
      </el-tab-pane>

      <!-- ============ 5 签名验签 ============ -->
      <el-tab-pane label="签名验签" name="sign">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 公钥</div>
            <div class="row">
              <el-radio-group v-model="sg.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
                <el-radio-button value="cert">公钥</el-radio-button>
                <el-radio-button value="pem">证书</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-button size="small" text><el-icon-upload />上传证书</el-button>
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(sg.publicKey) }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.publicKey)">复制</el-button>
            </div>
            <el-input v-model="sg.publicKey" type="textarea" :rows="3" placeholder="请输入公钥" />

          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 私钥</div>
            <div class="row">
              <el-radio-group v-model="sg.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <el-button size="small" text @click="computePubForSign">计算公钥</el-button>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(sg.privateKey) }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.privateKey)">复制</el-button>
            </div>
            <el-input v-model="sg.privateKey" type="textarea" :rows="3" placeholder="请输入私钥" />

          </el-col>
        </el-row>

        <el-row :gutter="24" style="margin-top:12px">
          <el-col :span="12">
            <div class="label">签名模式</div>
            <el-radio-group v-model="sg.signMode">
              <el-radio value="message">基于消息</el-radio>
              <el-radio value="evalue">基于e值</el-radio>
            </el-radio-group>
          </el-col>
          <el-col :span="12">
            <div class="label">用户标识</div>
            <el-input v-model="sg.userId">
              <template #prepend>
                <el-select v-model="sg.userIdFmt" style="width:100px">
                  <el-option label="十六进制" value="hex" />
                  <el-option label="字符串" value="utf8" />
                </el-select>
              </template>
            </el-input>
          </el-col>
        </el-row>

        <!-- 第一组 -->
        <el-row :gutter="24" style="margin-top:12px">
          <el-col :span="12">
            <div class="label">* {{ sg.signMode==='evalue' ? 'e 值（第一组）' : '消息（第一组）' }}</div>
            <div class="row">
              <el-radio-group v-model="sg.msg1Fmt" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ byteLen(sg.msg1, sg.msg1Fmt) }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.msg1)">复制</el-button>
            </div>
            <el-input v-model="sg.msg1" type="textarea" :rows="4" placeholder="请输入待签名的消息" />

          </el-col>
          <el-col :span="12">
            <div class="label">* 签名值R||S（第一组）</div>
            <div class="row">
              <el-radio-group v-model="sg.sig1Fmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <el-button size="small" text @click="convSig(1,'der')">转DER编码</el-button>
              <el-button size="small" text @click="convSig(1,'rs')">转R||S格式</el-button>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(sg.sig1) }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.sig1)">复制</el-button>
            </div>
            <el-input v-model="sg.sig1" type="textarea" :rows="4" placeholder="请输入签名值RS" />
          </el-col>
        </el-row>

        <!-- 第二组 -->
        <el-row :gutter="24" style="margin-top:12px">
          <el-col :span="12">
            <div class="label">* {{ sg.signMode==='evalue' ? 'e 值（第二组）' : '消息（第二组）' }}</div>
            <div class="row">
              <el-radio-group v-model="sg.msg2Fmt" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ byteLen(sg.msg2, sg.msg2Fmt) }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.msg2)">复制</el-button>
            </div>
            <el-input v-model="sg.msg2" type="textarea" :rows="4" placeholder="请输入待签名的消息" />

          </el-col>
          <el-col :span="12">
            <div class="label">* 签名值R||S（第二组）</div>
            <div class="row">
              <el-radio-group v-model="sg.sig2Fmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <el-button size="small" text @click="convSig(2,'der')">转DER编码</el-button>
              <el-button size="small" text @click="convSig(2,'rs')">转R||S格式</el-button>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(sg.sig2) }}字节</el-tag>
              <el-button size="small" text @click="copy(sg.sig2)">复制</el-button>
            </div>
            <el-input v-model="sg.sig2" type="textarea" :rows="4" placeholder="请输入签名值RS" />
          </el-col>
        </el-row>

        <div class="actions">
          <el-button type="primary" plain @click="genKeyForSign">生成密钥对</el-button>
          <div class="right">
            <el-button @click="doSign">签名</el-button>
            <el-button @click="doVerify">验签</el-button>
            <el-button @click="doAttack">验签并攻击</el-button>
            <el-button type="primary" @click="cleanSign">删除空格和换行</el-button>
            <el-button type="danger" plain @click="resetSign">清除</el-button>
          </div>
        </div>

        <el-alert v-if="sg.result" :title="sg.result" :type="sg.resultType" show-icon
                  style="margin-top:12px" @close="sg.result=''" />
      </el-tab-pane>

      <!-- ============ 6 加密解密 ============ -->
      <el-tab-pane label="加密解密" name="crypto">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 公钥</div>
            <div class="row">
              <el-radio-group v-model="cr.pubFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(cr.publicKey) }}字节</el-tag>
              <el-button size="small" text @click="copy(cr.publicKey)">复制</el-button>
            </div>
            <el-input v-model="cr.publicKey" type="textarea" :rows="3" placeholder="请输入对应数据格式的数据" />

          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 私钥</div>
            <div class="row">
              <el-radio-group v-model="cr.privFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(cr.privateKey) }}字节</el-tag>
              <el-button size="small" text @click="copy(cr.privateKey)">复制</el-button>
            </div>
            <el-input v-model="cr.privateKey" type="textarea" :rows="3" placeholder="请输入对应数据格式的数据" />

          </el-col>
        </el-row>

        <div class="label" style="margin-top:12px">加密类型</div>
        <el-radio-group v-model="cr.mode">
          <el-radio-button value="C1C3C2">C1||C3||C2</el-radio-button>
          <el-radio-button value="C1C2C3">C1||C2||C3</el-radio-button>
        </el-radio-group>

        <el-row :gutter="24" style="margin-top:12px">
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 明文</div>
            <div class="row">
              <el-radio-group v-model="cr.inputFormat" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ byteLen(cr.input, cr.inputFormat) }}字节</el-tag>
              <el-button size="small" text @click="copy(cr.input)">复制</el-button>
            </div>
            <el-input v-model="cr.input" type="textarea" :rows="5" placeholder="请输入对应数据格式的数据" />

          </el-col>
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 密文</div>
            <div class="row">
              <el-radio-group v-model="cr.cipherFmt" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <el-button size="small" text @click="convCipher('der')">转DER编码</el-button>
              <el-button size="small" text @click="convCipher('raw')">转密文</el-button>
              <div class="spacer" />
              <el-tag size="small" type="primary" effect="plain">{{ hexBytes(cr.cipher) }}字节</el-tag>
              <el-button size="small" text @click="copy(cr.cipher)">复制</el-button>
            </div>
            <el-input v-model="cr.cipher" type="textarea" :rows="5" placeholder="请输入对应数据格式的数据" />

          </el-col>
        </el-row>
        <div class="actions">
          <el-button type="primary" plain @click="genKeyForCrypto">生成密钥对</el-button>
          <div class="right">
            <el-button @click="doEncrypt">加密</el-button>
            <el-button @click="doDecrypt">解密</el-button>
            <el-button type="primary" @click="cleanCrypto">删除空格和换行</el-button>
            <el-button type="danger" plain @click="resetCrypto">清除</el-button>
          </div>
        </div>
      </el-tab-pane>

      <!-- ============ 7 密钥协商 ============ -->
      <el-tab-pane label="密钥协商" name="exchange">
        <el-row :gutter="24">
          <el-col :span="12">
            <div class="sub">发起方 A</div>
            <div class="label">A 标识</div><el-input v-model="ex.idA" />
            <div class="label" style="margin-top:8px">A 私钥</div><el-input v-model="ex.privateKeyA" />
            <div class="label" style="margin-top:8px">A 公钥</div><el-input v-model="ex.publicKeyA" />
          </el-col>
          <el-col :span="12">
            <div class="sub">响应方 B</div>
            <div class="label">B 标识</div><el-input v-model="ex.idB" />
            <div class="label" style="margin-top:8px">B 私钥</div><el-input v-model="ex.privateKeyB" />
            <div class="label" style="margin-top:8px">B 公钥</div><el-input v-model="ex.publicKeyB" />
          </el-col>
        </el-row>
        <div class="label" style="margin-top:12px">协商密钥长度（字节）</div>
        <el-input-number v-model="ex.keyLength" :min="1" :max="256" />
        <div class="actions">
          <el-button :loading="loading" @click="fillExchange">用两组新密钥填充</el-button>
          <el-button type="primary" @click="doExchange">执行密钥交换</el-button>
        </div>
        <el-alert v-if="ex.result" :title="ex.result" :type="ex.consistent?'success':'error'" show-icon
                  style="margin-top:12px;white-space:pre-line" @close="ex.result=''" />
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Upload as ElIconUpload } from '@element-plus/icons-vue'
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
const curve = reactive({ name:'', p:'', a:'', b:'', n:'', gx:'', gy:'' })
async function loadCurve() {
  try { Object.assign(curve, await api.get('/sm2/curve')) } catch {}
}
onMounted(loadCurve)

// ---------- 2 密钥运算 ----------
const ko = reactive({ publicKey:'', privateKey:'', pubFmt:'hex', privFmt:'hex' })
async function genKey() {
  const kp = await run(()=>api.post('/sm2/keypair', {}))
  ko.publicKey = kp.publicKey; ko.privateKey = kp.privateKey
  ElMessage.success('已生成密钥对')
}
async function validateKey() {
  if (!ko.publicKey) return ElMessage.warning('请填写公钥')
  const r = await run(()=>api.post('/sm2/validateKey', { publicKey: ko.publicKey }))
  r.valid ? ElMessage.success(r.message) : ElMessage.error(r.message)
}
async function computePub() {
  if (!ko.privateKey) return ElMessage.warning('请填写私钥')
  const r = await run(()=>api.post('/sm2/publicKey', { privateKey: ko.privateKey }))
  ko.publicKey = r.publicKey; ElMessage.success('已由私钥计算出公钥')
}
function cleanKo() {
  ko.publicKey=ko.publicKey.replace(/[\s\r\n]/g,'')
  ko.privateKey=ko.privateKey.replace(/[\s\r\n]/g,'')
}
function resetKo() { ko.publicKey=''; ko.privateKey='' }

// ---------- 3 计算 e 值 ----------
const ev = reactive({
  publicKey:'', pubFmt:'hex',
  userId:'31323334353637383132333435363738', userIdFmt:'hex',
  z:'', e:'', eFmt:'hex',
  input:'', inputFormat:'utf8'
})
async function computeEValue() {
  if (!ev.publicKey) return ElMessage.warning('请填写公钥')
  const r = await run(()=>api.post('/sm2/eValue', {
    publicKey: ev.publicKey, userId: userIdValue(ev.userId, ev.userIdFmt),
    input: ev.input, inputFormat: ev.inputFormat
  }))
  ev.z = r.z; ev.e = r.e; ElMessage.success('已计算 Z 值与 e 值')
}
function cleanEv() {
  ev.publicKey=ev.publicKey.replace(/[\s\r\n]/g,'')
  ev.input=ev.input.replace(/[\s\r\n]/g,'')
  ev.e=ev.e.replace(/[\s\r\n]/g,'')
}
function resetEv() { ev.input=''; ev.e=''; ev.z='' }

// ---------- 4 私钥解析 ----------
const pp = reactive({
  input:'', inputFmt:'str',
  privateKey:'', publicKey:'',
  privFmt:'hex', pubFmt:'hex'
})
async function parsePriv() {
  if (!pp.input) return ElMessage.warning('请填写私钥')
  try {
    const r = await run(()=>api.post('/sm2/parsePrivateKey', { privateKey: pp.input }))
    pp.privateKey = r.privateKey; pp.publicKey = r.publicKey; ElMessage.success('解析成功')
  } catch (e) { ElMessage.error('解析失败：' + (e?.message||'')) }
}
function resetPp() { pp.input=''; pp.privateKey=''; pp.publicKey='' }

// ---------- 5 签名验签 ----------
const sg = reactive({
  publicKey:'', privateKey:'', pubFmt:'hex', privFmt:'hex',
  signMode:'message',
  userId:'31323334353637383132333435363738', userIdFmt:'hex',
  msg1:'', msg1Fmt:'utf8', sig1:'', sig1Fmt:'hex',
  msg2:'', msg2Fmt:'utf8', sig2:'', sig2Fmt:'hex',
  result:'', resultType:'success'
})
async function genKeyForSign() {
  const kp = await run(()=>api.post('/sm2/keypair', {}))
  sg.publicKey = kp.publicKey; sg.privateKey = kp.privateKey; ElMessage.success('已生成密钥对')
}
async function computePubForSign() {
  if (!sg.privateKey) return ElMessage.warning('请填写私钥')
  const r = await run(()=>api.post('/sm2/publicKey', { privateKey: sg.privateKey }))
  sg.publicKey = r.publicKey
}
async function doSign() {
  if (!sg.privateKey) return ElMessage.warning('请填写私钥')
  try {
    sg.sig1 = await signOne(sg.msg1, sg.msg1Fmt)
    if (sg.msg2) sg.sig2 = await signOne(sg.msg2, sg.msg2Fmt)
    setResult('签名完成', 'success'); ElMessage.success('签名完成')
  } catch (e) { ElMessage.error(e?.message||'签名失败') }
}
async function signOne(msg, fmt) {
  const body = { privateKey: sg.privateKey, signMode: sg.signMode, sigEncoding: 'rs',
    userId: userIdValue(sg.userId, sg.userIdFmt), outputFormat: 'hex' }
  if (sg.signMode === 'evalue') body.eValue = msg.replace(/\s/g,'')
  else { body.input = msg; body.inputFormat = fmt }
  const r = await run(()=>api.post('/sm2/sign', body))
  return r.signature
}
async function doVerify() {
  if (!sg.publicKey) return ElMessage.warning('请填写公钥')
  try {
    if (sg.msg2 && sg.sig2) {
      const r = await run(()=>api.post('/sm2/verifyTwo', verifyTwoBody()))
      setResult(r.message, r.allPassed?'success':'error')
    } else {
      const ok = await verifyOne(sg.msg1, sg.msg1Fmt, sg.sig1, sg.sig1Fmt)
      setResult(ok?'验签通过 ✓':'验签失败 ✗', ok?'success':'error')
    }
  } catch (e) { ElMessage.error(e?.message||'验签失败') }
}
async function verifyOne(msg, mfmt, sig, sfmt) {
  const body = { publicKey: sg.publicKey, signMode: sg.signMode,
    userId: userIdValue(sg.userId, sg.userIdFmt), signature: sig, signatureFormat: sfmt }
  if (sg.signMode === 'evalue') body.eValue = msg.replace(/\s/g,'')
  else { body.input = msg; body.inputFormat = mfmt }
  const r = await run(()=>api.post('/sm2/verify', body))
  return r.verified
}
function verifyTwoBody() {
  return { publicKey: sg.publicKey, userId: userIdValue(sg.userId, sg.userIdFmt),
    message1: sg.msg1, message1Format: sg.msg1Fmt, signature1: sg.sig1, signature1Format: sg.sig1Fmt,
    message2: sg.msg2, message2Format: sg.msg2Fmt, signature2: sg.sig2, signature2Format: sg.sig2Fmt }
}
async function doAttack() {
  if (!sg.sig1 || !sg.sig2) return ElMessage.warning('验签并攻击需要两组签名')
  const r = await run(()=>api.post('/sm2/verifyAndAttack', verifyTwoBody()))
  if (r.attacked) setResult(r.message + ' 私钥: ' + r.recoveredPrivateKey, 'warning')
  else setResult(r.message, 'info')
}
async function convSig(idx, target) {
  const cur = idx===1 ? sg.sig1 : sg.sig2
  const fmt = idx===1 ? sg.sig1Fmt : sg.sig2Fmt
  if (!cur) return
  const r = await run(()=>api.post('/sm2/convertSignature', { sigInput: cur, sigInputFormat: fmt }))
  const val = target==='der' ? r.der : r.rs
  if (idx===1) { sg.sig1 = val; sg.sig1Fmt='hex' } else { sg.sig2 = val; sg.sig2Fmt='hex' }
}
function setResult(msg, type) { sg.result = msg; sg.resultType = type }
function cleanSign() {
  ['msg1','msg2','sig1','sig2','publicKey','privateKey'].forEach(k=>sg[k]=sg[k].replace(/[\s\r\n]/g,''))
}
function resetSign() { ['msg1','msg2','sig1','sig2','result'].forEach(k=>sg[k]='') }

// ---------- 6 加密解密 ----------
const cr = reactive({
  publicKey:'', privateKey:'', pubFmt:'hex', privFmt:'hex',
  mode:'C1C3C2',
  input:'', inputFormat:'utf8',
  cipher:'', cipherFmt:'hex'
})
async function genKeyForCrypto() {
  const kp = await run(()=>api.post('/sm2/keypair', {}))
  cr.publicKey = kp.publicKey; cr.privateKey = kp.privateKey; ElMessage.success('已生成密钥对')
}
async function doEncrypt() {
  if (!cr.publicKey) return ElMessage.warning('请填写公钥')
  const r = await run(()=>api.post('/sm2/encrypt', { publicKey: cr.publicKey, mode: cr.mode,
    input: cr.input, inputFormat: cr.inputFormat, outputFormat: cr.cipherFmt }))
  cr.cipher = r.cipher; ElMessage.success('加密成功')
}
async function doDecrypt() {
  if (!cr.privateKey) return ElMessage.warning('请填写私钥')
  const r = await run(()=>api.post('/sm2/decrypt', { privateKey: cr.privateKey, mode: cr.mode,
    input: cr.cipher, inputFormat: cr.cipherFmt, outputFormat: cr.inputFormat }))
  cr.input = r.plain; ElMessage.success('解密成功')
}
async function convCipher(target) {
  if (!cr.cipher) return ElMessage.warning('请先填写密文')
  const r = await run(()=>api.post('/sm2/convertCipher', { mode: cr.mode,
    sigInput: cr.cipher, sigInputFormat: cr.cipherFmt }))
  cr.cipher = target==='der' ? r.der : r.raw; cr.cipherFmt = 'hex'
  ElMessage.success(target==='der' ? '已转 DER 编码' : '已转裸密文格式')
}
function cleanCrypto() {
  cr.input=cr.input.replace(/[\s\r\n]/g,'')
  cr.cipher=cr.cipher.replace(/[\s\r\n]/g,'')
}
function resetCrypto() { cr.input=''; cr.cipher='' }

// ---------- 7 密钥协商 ----------
const ex = reactive({
  idA:'Alice', idB:'Bob',
  privateKeyA:'', publicKeyA:'',
  privateKeyB:'', publicKeyB:'',
  keyLength:16,
  result:'', consistent:false
})
async function fillExchange() {
  const a = await run(()=>api.post('/sm2/keypair', {}))
  const b = await run(()=>api.post('/sm2/keypair', {}))
  ex.privateKeyA=a.privateKey; ex.publicKeyA=a.publicKey
  ex.privateKeyB=b.privateKey; ex.publicKeyB=b.publicKey
  ElMessage.success('已填充 A、B 两组密钥')
}
async function doExchange() {
  const r = await run(()=>api.post('/sm2/keyExchange', ex))
  ex.consistent = r.consistent
  ex.result = `共享密钥A: ${r.sharedKeyA}\n共享密钥B: ${r.sharedKeyB}\n双方一致: ${r.consistent?'是 ✓':'否 ✗'}`
}

// userId 编码转换
function userIdValue(v, fmt) {
  if (fmt === 'hex') {
    try {
      const bytes = v.replace(/\s/g,'').match(/.{1,2}/g)?.map(b=>parseInt(b,16)) || []
      return String.fromCharCode(...bytes)
    } catch { return v }
  }
  return v
}
</script>

<style scoped>
.title { font-size: 18px; font-weight: 600; margin-bottom: 16px; }
.sub { font-size: 14px; font-weight: 600; margin-bottom: 10px; }
.label { font-size: 13px; color: #606266; margin-bottom: 6px; }
.req { color: #f56c6c; margin-right: 4px; }
.row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.spacer { flex: 1; }
.actions {
  margin-top: 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.actions .right { display: flex; gap: 8px; }
.mono { font-family: Consolas, Menlo, monospace; word-break: break-all; }
.curve { max-width: 900px; }
.curve :deep(.el-descriptions__label) { width: 120px; }
</style>
