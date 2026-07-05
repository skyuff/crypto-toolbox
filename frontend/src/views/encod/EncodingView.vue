<template>
  <el-card class="encoding-workbench">
    <div class="page-title">编码转换工具</div>

    <el-tabs v-model="activeTab" type="border-card">
      <!-- 编码转换 -->
      <el-tab-pane label="编码转换" name="convert">
        <div class="section-title">
          <el-icon><InfoFilled /></el-icon>
          <span>输入内容</span>
          <el-tooltip content="还没想好要提示些什么？" placement="top">
            <el-icon class="info-icon"><QuestionFilled /></el-icon>
          </el-tooltip>
        </div>

        <div class="row">
          <span class="row-label">源编码</span>
          <el-select v-model="convertForm.fromFormat" style="width: 180px">
            <el-option v-for="opt in formatOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
          </el-select>
          <span class="row-label" style="margin-left: 16px">目标编码</span>
          <el-select v-model="convertForm.toFormat" style="width: 180px">
            <el-option v-for="opt in formatOptions" :key="opt.value" :label="opt.label" :value="opt.value" />
          </el-select>
        </div>

        <el-input
          v-model="convertForm.input"
          type="textarea"
          :rows="5"
          placeholder="请输入待转换内容"
        />

        <div class="actions">
          <el-button type="primary" :loading="loading" @click="doConvert">
            <el-icon><Refresh /></el-icon> 转换
          </el-button>
          <el-button :loading="loading" @click="doAll">
            <el-icon><Grid /></el-icon> 全部表示
          </el-button>
          <el-button @click="cleanInput(convertForm)">
            <el-icon><Brush /></el-icon> 清理空格和换行
          </el-button>
          <el-button type="danger" plain @click="clearConvert">
            <el-icon><Delete /></el-icon> 清空
          </el-button>
        </div>

        <div v-if="convertOutput != null" class="result-section">
          <div class="section-title">
            <el-icon><Document /></el-icon>
            <span>转换结果</span>
            <span class="byte-tag">{{ convertOutput.byteLength }} 字节</span>
            <el-button size="small" text @click="copyText(convertOutput.output)">
              <el-icon><CopyDocument /></el-icon> 复制
            </el-button>
          </div>
          <el-input v-model="convertOutput.output" type="textarea" :rows="4" readonly />
        </div>

        <div v-if="allMap" class="result-section">
          <div class="section-title">
            <el-icon><Grid /></el-icon>
            <span>多向表示</span>
            <span class="byte-tag">{{ allMap.byteLength }} 字节 / {{ allMap.bitLength }} 位</span>
          </div>
          <el-descriptions :column="1" border>
            <el-descriptions-item label="字符串">{{ allMap.string }}</el-descriptions-item>
            <el-descriptions-item label="十六进制">{{ allMap.hex }}</el-descriptions-item>
            <el-descriptions-item label="Base64">{{ allMap.base64 }}</el-descriptions-item>
            <el-descriptions-item label="二进制">{{ allMap.binary }}</el-descriptions-item>
            <el-descriptions-item label="哈希算法猜测">{{ allMap.detections?.hash }}</el-descriptions-item>
            <el-descriptions-item label="对称算法猜测">{{ allMap.detections?.symmetric }}</el-descriptions-item>
            <el-descriptions-item label="非对称算法猜测">{{ allMap.detections?.asymmetric }}</el-descriptions-item>
          </el-descriptions>
        </div>
      </el-tab-pane>

      <!-- URL 编解码 -->
      <el-tab-pane label="URL 编解码" name="url">
        <div class="section-title">
          <el-icon><InfoFilled /></el-icon>
          <span>输入内容</span>
          <el-tooltip content="还没想好要提示些什么？" placement="top">
            <el-icon class="info-icon"><QuestionFilled /></el-icon>
          </el-tooltip>
        </div>

        <el-input
          v-model="urlForm.input"
          type="textarea"
          :rows="6"
          placeholder="请输入待编码或解码的内容"
        />

        <div class="actions">
          <el-button type="primary" :loading="loading" @click="doUrl(true)">
            <el-icon><Refresh /></el-icon> URL 编码
          </el-button>
          <el-button type="primary" :loading="loading" @click="doUrl(false)">
            <el-icon><Refresh /></el-icon> URL 解码
          </el-button>
          <el-button @click="cleanInput(urlForm)">
            <el-icon><Brush /></el-icon> 清理空格和换行
          </el-button>
          <el-button type="danger" plain @click="clearUrl">
            <el-icon><Delete /></el-icon> 清空
          </el-button>
        </div>

        <div v-if="urlOutput != null" class="result-section">
          <div class="section-title">
            <el-icon><Document /></el-icon>
            <span>结果</span>
            <span class="byte-tag">{{ urlOutput.byteLength }} 字节</span>
            <el-button size="small" text @click="copyText(urlOutput.output)">
              <el-icon><CopyDocument /></el-icon> 复制
            </el-button>
          </div>
          <el-input v-model="urlOutput.output" type="textarea" :rows="4" readonly />
        </div>
      </el-tab-pane>

      <!-- 字符集转换 -->
      <el-tab-pane label="字符集转换" name="charset">
        <div class="section-title">
          <el-icon><InfoFilled /></el-icon>
          <span>输入内容</span>
          <el-tooltip content="还没想好要提示些什么？" placement="top">
            <el-icon class="info-icon"><QuestionFilled /></el-icon>
          </el-tooltip>
        </div>

        <div class="row">
          <span class="row-label">源字符集</span>
          <el-select v-model="charsetForm.fromCharset" filterable clearable placeholder="请选择字符集" style="width: 220px">
            <el-option v-for="c in charsetOptions" :key="c" :label="c" :value="c" />
          </el-select>
          <span class="row-label" style="margin-left: 16px">目标字符集</span>
          <el-select v-model="charsetForm.toCharset" filterable clearable placeholder="请选择字符集" style="width: 220px">
            <el-option v-for="c in charsetOptions" :key="c" :label="c" :value="c" />
          </el-select>
        </div>

        <el-input
          v-model="charsetForm.input"
          type="textarea"
          :rows="6"
          placeholder="请输入待转换的文本"
        />

        <div class="actions">
          <el-button type="primary" :loading="loading" @click="doCharset">
            <el-icon><Refresh /></el-icon> 转换
          </el-button>
          <el-button type="danger" plain @click="clearCharset">
            <el-icon><Delete /></el-icon> 清空
          </el-button>
        </div>

        <div v-if="charsetOutput != null" class="result-section">
          <div class="section-title">
            <el-icon><Document /></el-icon>
            <span>转换结果</span>
            <span class="byte-tag">{{ charsetOutput.byteLength }} 字节</span>
            <el-button size="small" text @click="copyText(charsetOutput.output)">
              <el-icon><CopyDocument /></el-icon> 复制
            </el-button>
          </div>
          <el-input v-model="charsetOutput.output" type="textarea" :rows="4" readonly />
        </div>
      </el-tab-pane>

      <!-- ASN.1 解析 -->
      <el-tab-pane label="ASN.1 解析" name="asn1">
        <div class="section-title">
          <el-icon><Document /></el-icon>
          <span>ASN.1 数据</span>
          <el-tooltip content="还没想好要提示些什么？" placement="top">
            <el-icon class="info-icon"><QuestionFilled /></el-icon>
          </el-tooltip>
        </div>

        <div class="row">
          <el-radio-group v-model="asn1Form.format" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
            <el-radio-button value="base64">Base64</el-radio-button>
            <el-radio-button value="pem">PEM</el-radio-button>
            <el-radio-button value="auto">自动识别</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ asn1Bytes }} 字节</el-tag>
          <el-button size="small" text @click="copyText(asn1Form.input)">
            <el-icon><CopyDocument /></el-icon> 复制
          </el-button>
          <el-upload
            class="inline-upload"
            action="#"
            :auto-upload="false"
            :show-file-list="false"
            :on-change="handleAsn1File"
            accept=".cer,.crt,.pem,.der,.p10,.csr,.p7b,.p7c"
          >
            <el-button size="small" text>
              <el-icon><Upload /></el-icon> 上传文件
            </el-button>
          </el-upload>
        </div>

        <el-input
          v-model="asn1Form.input"
          type="textarea"
          :rows="6"
          placeholder="请输入 PEM / Base64 / 十六进制 编码的 DER 数据"
        />

        <div class="actions">
          <el-button type="primary" :loading="loading" @click="doAsn1">
            <el-icon><Refresh /></el-icon> 解析 ASN.1
          </el-button>
          <el-button @click="cleanInput(asn1Form)">
            <el-icon><Brush /></el-icon> 清理空格和换行
          </el-button>
          <el-button type="danger" plain @click="clearAsn1">
            <el-icon><Delete /></el-icon> 清空
          </el-button>
        </div>

        <template v-if="treeData.length">
          <div class="section-title" style="margin-top: 16px">
            <el-icon><List /></el-icon>
            <span>ASN.1 结构</span>
          </div>
          <el-tree
            :data="treeData"
            :props="{ label: 'label', children: 'children' }"
            default-expand-all
            node-key="id"
          >
            <template #default="{ data }">
              <span class="tree-node">
                <span class="node-type">{{ data.type }}</span>
                <span v-if="data.length != null" class="node-len">（长度: {{ data.length }}）</span>
                <span v-if="data.value" class="node-val">{{ data.value }}</span>
                <el-button v-if="data.value" size="small" text class="copy-btn" @click.stop="copyText(data.value)">
                  Copy
                </el-button>
              </span>
            </template>
          </el-tree>
        </template>
      </el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import {
  InfoFilled,
  QuestionFilled,
  Refresh,
  Grid,
  Brush,
  Delete,
  Document,
  CopyDocument,
  Upload,
  List
} from '@element-plus/icons-vue'
import api from '../../api'

const activeTab = ref('convert')
const loading = ref(false)

const formatOptions = [
  { value: 'utf8', label: 'UTF-8 文本' },
  { value: 'hex', label: '十六进制 (Hex)' },
  { value: 'base64', label: 'Base64' },
  { value: 'base64url', label: 'Base64URL' },
  { value: 'url', label: 'URL 编码' },
  { value: 'base58', label: 'Base58' },
  { value: 'binary', label: '二进制 (Binary)' },
  { value: 'decimal', label: '十进制大整数 (Decimal)' },
  { value: 'bytes', label: '字节数组 (Bytes)' }
]

const charsetOptions = [
  'UTF-8',
  'GBK',
  'GB2312',
  'GB18030',
  'Big5',
  'Big5-HKSCS',
  'CESU-8',
  'EUC-JP',
  'EUC-KR',
  'Shift_JIS',
  'ISO-2022-JP',
  'ISO-2022-JP-2',
  'ISO-2022-KR',
  'ISO-2022-CN',
  'ISO-8859-1',
  'ISO-8859-2',
  'ISO-8859-3',
  'ISO-8859-4',
  'ISO-8859-5',
  'ISO-8859-6',
  'ISO-8859-7',
  'ISO-8859-8',
  'ISO-8859-9',
  'ISO-8859-13',
  'ISO-8859-15',
  'ISO-8859-16',
  'US-ASCII',
  'UTF-16',
  'UTF-16BE',
  'UTF-16LE',
  'UTF-32',
  'UTF-32BE',
  'UTF-32LE',
  'KOI8-R',
  'KOI8-U',
  'TIS-620',
  'windows-1250',
  'windows-1251',
  'windows-1252',
  'windows-1253',
  'windows-1254',
  'windows-1255',
  'windows-1256',
  'windows-1257',
  'windows-1258',
  'windows-31j',
  'IBM-Thai',
  'IBM00858',
  'IBM01140',
  'IBM01141',
  'IBM01142',
  'IBM01143',
  'IBM01144',
  'IBM01145',
  'IBM01146',
  'IBM01147',
  'IBM01148',
  'IBM01149',
  'IBM037',
  'IBM1026',
  'IBM1047',
  'IBM273',
  'IBM277',
  'IBM278',
  'IBM280',
  'IBM284',
  'IBM285',
  'IBM297',
  'IBM420',
  'IBM424',
  'IBM437',
  'IBM500',
  'IBM775',
  'IBM850',
  'IBM852',
  'IBM855',
  'IBM857',
  'IBM860',
  'IBM861',
  'IBM862',
  'IBM863',
  'IBM864',
  'IBM865',
  'IBM866',
  'IBM868',
  'IBM869',
  'IBM870',
  'IBM871',
  'IBM918',
  'Macintosh',
  'MacCentralEurope',
  'MacCroatian',
  'MacCyrillic',
  'MacDingbats',
  'MacGreek',
  'MacIceland',
  'MacRoman',
  'MacRomania',
  'MacSymbol',
  'MacThai',
  'MacTurkish',
  'MacUkraine',
  'x-Big5-HKSCS-2001',
  'x-Big5-Solaris',
  'x-COMPOUND_TEXT',
  'x-euc-jp-linux',
  'x-EUC-TW',
  'x-eucJP-Open',
  'x-IBM1006',
  'x-IBM1025',
  'x-IBM1046',
  'x-IBM1097',
  'x-IBM1098',
  'x-IBM1112',
  'x-IBM1122',
  'x-IBM1123',
  'x-IBM1124',
  'x-IBM1166',
  'x-IBM1364',
  'x-IBM1381',
  'x-IBM1383',
  'x-IBM300',
  'x-IBM33722',
  'x-IBM737',
  'x-IBM833',
  'x-IBM834',
  'x-IBM856',
  'x-IBM874',
  'x-IBM875',
  'x-IBM921',
  'x-IBM922',
  'x-IBM930',
  'x-IBM933',
  'x-IBM935',
  'x-IBM937',
  'x-IBM939',
  'x-IBM942',
  'x-IBM942C',
  'x-IBM943',
  'x-IBM943C',
  'x-IBM948',
  'x-IBM949',
  'x-IBM949C',
  'x-IBM950',
  'x-IBM964',
  'x-IBM970',
  'x-ISCII91',
  'x-ISO-2022-CN-CNS',
  'x-ISO-2022-CN-GB',
  'x-iso-8859-11',
  'x-JIS0208',
  'x-JISAutoDetect',
  'x-Johab',
  'x-MacArabic',
  'x-MacHebrew',
  'x-MacSimplifiedChinese',
  'x-MacTraditionalChinese',
  'x-MS932_0213',
  'x-MS950-HKSCS',
  'x-MS950-HKSCS-XP',
  'x-mswin-936',
  'x-PCK',
  'x-SJIS_0213',
  'x-UTF-16LE-BOM',
  'X-UTF-32BE-BOM',
  'X-UTF-32LE-BOM',
  'x-windows-50220',
  'x-windows-50221',
  'x-windows-874',
  'x-windows-949',
  'x-windows-950'
]

const convertForm = reactive({
  input: 'hello',
  fromFormat: 'utf8',
  toFormat: 'hex'
})
const convertOutput = ref(null)
const allMap = ref(null)

const urlForm = reactive({ input: '' })
const urlOutput = ref(null)

const charsetForm = reactive({
  input: '',
  fromCharset: 'UTF-8',
  toCharset: 'GBK'
})
const charsetOutput = ref(null)

const asn1Form = reactive({
  input: '',
  format: 'hex'
})
const treeData = ref([])
let idSeq = 0

const asn1Bytes = computed(() => {
  const s = (asn1Form.input || '').replace(/[\s\r\n]/g, '')
  if (!s) return 0
  if (asn1Form.format === 'hex') return Math.floor(s.length / 2)
  try { return Math.floor(atob(s).length) } catch { return 0 }
})

function copyText(text) {
  if (text == null || text === '') return
  navigator.clipboard.writeText(String(text))
  ElMessage.success('已复制')
}

function cleanInput(form) {
  form.input = form.input.replace(/[\s\r\n]/g, '')
  ElMessage.success('已清理空格和换行')
}

function clearConvert() {
  convertForm.input = ''
  convertOutput.value = null
  allMap.value = null
}

function clearUrl() {
  urlForm.input = ''
  urlOutput.value = null
}

function clearCharset() {
  charsetForm.input = ''
  charsetOutput.value = null
}

function clearAsn1() {
  asn1Form.input = ''
  asn1Form.format = 'hex'
  treeData.value = []
}

async function doConvert() {
  if (!convertForm.input) {
    ElMessage.warning('请输入待转换内容')
    return
  }
  loading.value = true
  allMap.value = null
  try {
    convertOutput.value = await api.post('/encode/convert', convertForm)
  } finally {
    loading.value = false
  }
}

async function doAll() {
  if (!convertForm.input) {
    ElMessage.warning('请输入待转换内容')
    return
  }
  loading.value = true
  convertOutput.value = null
  try {
    allMap.value = await api.post('/encode/all', {
      input: convertForm.input,
      fromFormat: convertForm.fromFormat
    })
  } finally {
    loading.value = false
  }
}

async function doUrl(encode) {
  if (!urlForm.input) {
    ElMessage.warning('请输入待编码/解码内容')
    return
  }
  loading.value = true
  try {
    urlOutput.value = await api.post('/encode/convert', {
      input: urlForm.input,
      fromFormat: encode ? 'utf8' : 'url',
      toFormat: encode ? 'url' : 'utf8'
    })
  } finally {
    loading.value = false
  }
}

async function doCharset() {
  if (!charsetForm.input) {
    ElMessage.warning('请输入待转换文本')
    return
  }
  loading.value = true
  try {
    charsetOutput.value = await api.post('/encode/charset/convert', charsetForm)
  } finally {
    loading.value = false
  }
}

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function handleAsn1File(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    const bytes = new Uint8Array(e.target.result)
    const text = new TextDecoder().decode(bytes)
    if (text.includes('-----BEGIN')) {
      const base64 = text.replace(/-----BEGIN[^-]+-----/g, '').replace(/-----END[^-]+-----/g, '').replace(/[\s\r\n]/g, '')
      const der = Uint8Array.from(atob(base64), c => c.charCodeAt(0))
      asn1Form.input = Array.from(der).map(b => b.toString(16).padStart(2, '0')).join('')
    } else {
      asn1Form.input = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    }
    asn1Form.format = 'hex'
    ElMessage.success('文件上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

function toTree(node) {
  return {
    id: idSeq++,
    label: node.type,
    type: node.type,
    value: node.value,
    length: node.length,
    children: (node.children || []).map(toTree)
  }
}

async function doAsn1() {
  if (!asn1Form.input.trim()) {
    ElMessage.warning('请输入 ASN.1 数据')
    return
  }
  loading.value = true
  treeData.value = []
  try {
    idSeq = 0
    const input = asn1Form.input.replace(/[\s\r\n]/g, '')
    const r = await api.post('/asn1/parse', { input, format: asn1Form.format })
    if (Array.isArray(r.root)) {
      treeData.value = r.root.map(toTree)
    } else {
      treeData.value = r.root ? [toTree(r.root)] : []
    }
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.encoding-workbench {
  min-height: 600px;
}
.page-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
}
.section-title {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
  margin-bottom: 12px;
  font-size: 14px;
}
.info-icon {
  color: #909399;
  cursor: help;
}
.row {
  display: flex;
  align-items: center;
  margin-bottom: 12px;
  gap: 8px;
}
.row-label {
  font-size: 14px;
  color: #606266;
}
.spacer {
  flex: 1;
}
.actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  margin: 20px 0 8px;
}
.result-section {
  margin-top: 20px;
}
.byte-tag {
  margin-left: 8px;
  color: #409eff;
  font-weight: 500;
  font-size: 13px;
}
.inline-upload {
  display: inline-flex;
}
.tree-node {
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: 'Courier New', monospace;
  font-size: 13px;
}
.node-type {
  color: #409eff;
  font-weight: 500;
}
.node-len {
  color: #909399;
}
.node-val {
  color: #303133;
  word-break: break-all;
}
.copy-btn {
  margin-left: auto;
}
</style>
