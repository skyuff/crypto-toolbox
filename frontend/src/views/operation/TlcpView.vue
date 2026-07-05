<template>
  <el-card>
    <div class="page-title">TLCP / TLS 密钥生成</div>

    <el-alert
      type="info"
      :closable="false"
      style="margin-bottom: 20px"
      title="模拟 TLS/TLCP：PreMasterSecret → MasterSecret(48B) → KeyBlock 的密钥派生全过程。"
    />

    <el-form label-position="top">
      <!-- 摘要算法 -->
      <el-form-item label="摘要算法">
        <el-radio-group v-model="form.hash" size="small" class="hash-group">
          <el-radio-button value="SM3">SM3</el-radio-button>
          <el-radio-button value="SHA-224">SHA-224</el-radio-button>
          <el-radio-button value="SHA-256">SHA-256</el-radio-button>
          <el-radio-button value="SHA-384">SHA-384</el-radio-button>
          <el-radio-button value="SHA-512">SHA-512</el-radio-button>
          <el-radio-button value="SHA3-224">SHA3-224</el-radio-button>
          <el-radio-button value="SHA3-256">SHA3-256</el-radio-button>
          <el-radio-button value="SHA3-384">SHA3-384</el-radio-button>
          <el-radio-button value="SHA3-512">SHA3-512</el-radio-button>
          <el-radio-button value="SHA-1">SHA-1</el-radio-button>
          <el-radio-button value="MD5">MD5</el-radio-button>
        </el-radio-group>
      </el-form-item>

      <!-- 客户端随机数 / 服务端随机数 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="客户端随机数（十六进制）">
            <div class="format-row">
              <span class="byte-tag">{{ byteCount(form.clientRandom) }} 字节</span>
              <el-button size="small" :icon="DocumentCopy" @click="copy(form.clientRandom)">复制</el-button>
            </div>
            <el-input
              v-model="form.clientRandom"
              placeholder="请输入 ClientHello.random"
            />
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="服务端随机数（十六进制）">
            <div class="format-row">
              <span class="byte-tag">{{ byteCount(form.serverRandom) }} 字节</span>
              <el-button size="small" :icon="DocumentCopy" @click="copy(form.serverRandom)">复制</el-button>
            </div>
            <el-input
              v-model="form.serverRandom"
              placeholder="请输入 ServerHello.random"
            />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 预主密钥 / 密码套件类型 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="预主密钥（十六进制）">
            <div class="format-row">
              <span class="byte-tag">{{ byteCount(form.preMasterSecret) }} 字节</span>
              <el-button size="small" :icon="DocumentCopy" @click="copy(form.preMasterSecret)">复制</el-button>
            </div>
            <el-input
              v-model="form.preMasterSecret"
              placeholder="请输入 pre_master_secret"
            />
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="密码套件类型">
            <el-radio-group v-model="form.suiteType">
              <el-radio-button value="block">分组算法</el-radio-button>
              <el-radio-button value="aead">GCM（AEAD）</el-radio-button>
            </el-radio-group>
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 常量字符串 1 / 常量字符串 2 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="常量字符串 1">
            <el-input v-model="form.label1" placeholder="master secret" />
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="常量字符串 2">
            <el-input v-model="form.label2" placeholder="key expansion" />
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 主密钥输出 -->
      <el-form-item label="主密钥">
        <div class="format-row">
          <el-radio-group v-model="form.formatOut" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
          </el-radio-group>
          <div class="data-actions">
            <el-tag size="small" type="info">{{ masterByteCount }} 字节</el-tag>
            <el-button size="small" :icon="DocumentCopy" @click="copy(masterText)">复制</el-button>
          </div>
        </div>
        <el-input
          v-model="masterText"
          type="textarea"
          :rows="2"
          readonly
          placeholder="点击“计算主密钥”后可自动回填"
        />
      </el-form-item>

      <!-- 会话密钥块输出 -->
      <el-form-item v-if="result && result.keyBlock" label="会话密钥块（KeyBlock）">
        <div class="format-row">
          <div class="data-actions">
            <el-tag size="small" type="info">{{ result.keyBlockLength }} 字节</el-tag>
            <el-button size="small" :icon="DocumentCopy" @click="copy(result.keyBlock)">复制</el-button>
          </div>
        </div>
        <el-input
          :model-value="result.keyBlock"
          type="textarea"
          :rows="3"
          readonly
        />
      </el-form-item>

      <!-- 操作按钮 -->
      <el-form-item>
        <div class="btn-row">
          <el-button native-type="button" type="primary" :loading="loading" @click="runMaster">计算主密钥</el-button>
          <el-button native-type="button" type="primary" :loading="loading" @click="runKeyBlock">计算会话密钥</el-button>
          <el-button native-type="button" @click="cleanWhitespace">清理空格和换行</el-button>
          <el-button native-type="button" @click="clearAll">清空</el-button>
        </div>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { DocumentCopy } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const form = reactive({
  preMasterSecret: '03030102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627282930313233343536',
  clientRandom: '1122334455667788112233445566778811223344556677881122334455667788',
  serverRandom: '8877665544332211887766554433221188776655443322118877665544332211',
  hash: 'SM3',
  label1: 'master secret',
  label2: 'key expansion',
  suiteType: 'block',
  formatOut: 'hex'
})

const loading = ref(false)
const result = ref(null)

const masterText = computed({
  get() {
    return result.value ? result.value.masterSecret : ''
  },
  set() {}
})

const masterByteCount = computed(() => {
  return result.value ? result.value.masterSecretLength : 0
})

function byteCount(hex) {
  if (!hex) return 0
  const s = hex.replace(/\s+/g, '').replace(/^0x/i, '')
  return Math.floor(s.length / 2)
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace() {
  form.preMasterSecret = form.preMasterSecret.replace(/\s+/g, '')
  form.clientRandom = form.clientRandom.replace(/\s+/g, '')
  form.serverRandom = form.serverRandom.replace(/\s+/g, '')
}

function clearAll() {
  form.preMasterSecret = ''
  form.clientRandom = ''
  form.serverRandom = ''
  form.hash = 'SM3'
  form.label1 = 'master secret'
  form.label2 = 'key expansion'
  form.suiteType = 'block'
  form.formatOut = 'hex'
  result.value = null
}

async function runMaster() {
  await derive('master')
}

async function runKeyBlock() {
  await derive('keyblock')
}

async function derive(operation) {
  if (!form.preMasterSecret.trim()) {
    ElMessage.warning('请输入预主密钥')
    return
  }
  if (!form.clientRandom.trim()) {
    ElMessage.warning('请输入客户端随机数')
    return
  }
  if (!form.serverRandom.trim()) {
    ElMessage.warning('请输入服务端随机数')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/tlskey/derive', { ...form, operation })
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
.hash-group {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}
.hash-group :deep(.el-radio-button__inner) {
  padding: 5px 12px;
}
.format-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}
.byte-tag {
  font-size: 12px;
  color: #606266;
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
