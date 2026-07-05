<template>
  <el-card>
    <div class="title">杂凑算法猜测</div>

    <el-tabs v-model="tab">
      <!-- 消息比对猜测 -->
      <el-tab-pane label="消息比对猜测" name="compare">
        <el-row :gutter="24">
          <!-- 输入消息 -->
          <el-col :span="12">
            <div class="label"><span class="req">*</span> 输入消息</div>
            <div class="row">
              <el-radio-group v-model="inputFormat" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <span class="bytes">{{ byteLen(input, inputFormat) }} 字节</span>
              <el-button size="small" @click="copy(input)">复制</el-button>
            </div>
            <el-input v-model="input" type="textarea" :rows="5" />
            <div class="hint">左侧为待计算消息格式，右侧原始摘要格式单独控制。</div>
          </el-col>

          <!-- 原始摘要 -->
          <el-col :span="12">
            <div class="label">原始摘要</div>
            <div class="row">
              <el-radio-group v-model="digestFormat" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="spacer" />
              <span class="bytes">{{ byteLen(digest, digestFormat) }} 字节</span>
              <el-button size="small" @click="copy(digest)">复制</el-button>
            </div>
            <el-input v-model="digest" type="textarea" :rows="5" placeholder="可选，填入后自动在结果表格中标记匹配算法" />
            <div class="hint">输入摘要后会在结果表格中自动标记匹配算法。</div>
          </el-col>
        </el-row>

        <div class="actions">
          <el-button :loading="loading" @click="computeAll">计算杂凑</el-button>
          <el-button type="primary" @click="clean">清理空格和换行</el-button>
          <el-button type="danger" plain @click="clear">清空</el-button>
        </div>

        <el-table v-if="rows.length" :data="rows" border style="margin-top: 12px"
                  :row-class-name="rowClass">
          <el-table-column type="index" label="序号" width="70" align="center" />
          <el-table-column prop="algorithm" label="杂凑算法" width="140" />
          <el-table-column prop="hex" label="杂凑值">
            <template #default="{ row }">
              <span class="mono">{{ digestFormat === 'base64' ? row.base64 : row.hex.toUpperCase() }}</span>
            </template>
          </el-table-column>
          <el-table-column label="比对结果" width="120" align="center">
            <template #default="{ row }">
              <span v-if="!hasTarget" class="muted">—</span>
              <span v-else-if="row.matched" class="ok">✓ 匹配</span>
              <span v-else class="no">✗ 不匹配</span>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- 按长度猜测（原有功能） -->
      <el-tab-pane label="按长度猜测" name="length">
        <div class="label">哈希值（十六进制）</div>
        <el-input v-model="hash" type="textarea" :rows="3" placeholder="粘贴哈希值（hex），按长度/特征猜测算法" />
        <div class="actions">
          <el-button type="primary" :loading="loading2" @click="guess">猜测算法</el-button>
        </div>
        <template v-if="guessResult">
          <el-descriptions :column="2" border>
            <el-descriptions-item label="十六进制长度">{{ guessResult.hexLength ?? (hash.trim().length) }}</el-descriptions-item>
            <el-descriptions-item label="位长">{{ guessResult.bitLength }}</el-descriptions-item>
          </el-descriptions>
          <el-table v-if="guessResult.candidates" :data="candidates" border style="margin-top: 12px">
            <el-table-column prop="name" label="可能的算法" />
            <el-table-column prop="bits" label="输出位长" width="120" />
          </el-table>
        </template>
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const tab = ref('compare')

// ===== 消息比对猜测 =====
const input = ref('')
const inputFormat = ref('utf8')
const digest = ref('')
const digestFormat = ref('hex')
const rows = ref([])
const loading = ref(false)

const hasTarget = computed(() => !!digest.value.trim())

// 目标摘要归一化为小写 hex
const targetHex = computed(() => {
  const v = digest.value.trim()
  if (!v) return ''
  try {
    if (digestFormat.value === 'base64') {
      const bin = atob(v.replace(/\s/g, ''))
      let hex = ''
      for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, '0')
      return hex.toLowerCase()
    }
    return v.replace(/\s/g, '').toLowerCase()
  } catch { return '' }
})

async function computeAll() {
  loading.value = true
  try {
    const list = await api.post('/hash/digest/all', { input: input.value, inputFormat: inputFormat.value })
    rows.value = list.map(x => ({
      ...x,
      base64: hexToBase64(x.hex),
      matched: !!targetHex.value && x.hex.toLowerCase() === targetHex.value
    }))
  } catch (e) {
    ElMessage.error(e?.message || '计算失败')
  } finally { loading.value = false }
}

function rowClass({ row }) {
  return hasTarget.value && row.matched ? 'match-row' : ''
}

function hexToBase64(hex) {
  const bytes = hex.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || []
  return btoa(String.fromCharCode(...bytes))
}

function byteLen(str, fmt) {
  if (!str) return 0
  try {
    if (fmt === 'hex') return Math.floor(str.replace(/\s/g, '').length / 2)
    if (fmt === 'base64') {
      const s = str.replace(/\s/g, '')
      return Math.floor(s.replace(/=+$/, '').length * 3 / 4)
    }
    return new TextEncoder().encode(str).length
  } catch { return 0 }
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function clean() {
  input.value = input.value.replace(/[\s\r\n]/g, '')
  digest.value = digest.value.replace(/[\s\r\n]/g, '')
}

function clear() {
  input.value = ''
  digest.value = ''
  rows.value = []
}

// ===== 按长度猜测（原有） =====
const hash = ref('')
const guessResult = ref(null)
const loading2 = ref(false)

const candidates = computed(() => {
  if (!guessResult.value) return []
  const c = guessResult.value.candidates
  if (Array.isArray(c)) {
    return c.map(x => typeof x === 'string' ? { name: x, bits: guessResult.value.bitLength } : x)
  }
  return []
})

async function guess() {
  loading2.value = true
  try {
    guessResult.value = await api.get('/hash/guess', { params: { hash: hash.value.trim() } })
  } finally { loading2.value = false }
}
</script>

<style scoped>
.title { font-size: 16px; font-weight: 600; margin-bottom: 8px; }
.label { font-size: 13px; color: #333; margin-bottom: 8px; }
.req { color: #f56c6c; margin-right: 2px; }
.row { display: flex; align-items: center; margin-bottom: 8px; }
.spacer { flex: 1; }
.bytes { color: #409eff; font-size: 12px; margin-right: 8px; }
.hint { color: #909399; font-size: 12px; margin-top: 4px; }
.actions { margin-top: 20px; margin-bottom: 8px; text-align: center; }
.actions .el-button { margin: 0 6px; }
.mono { font-family: Consolas, Menlo, monospace; word-break: break-all; }
.ok { color: #67c23a; }
.no { color: #f56c6c; }
.muted { color: #c0c4cc; }
:deep(.match-row) { background: #f0f9eb; }
</style>
