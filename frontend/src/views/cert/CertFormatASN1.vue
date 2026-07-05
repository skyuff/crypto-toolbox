<template>
  <el-card class="asn1-parse">
    <div class="title">ASN.1 证书解析</div>

    <div class="sub-title">
      <el-icon><Document /></el-icon>
      <span>证书数据</span>
    </div>

    <div class="row">
      <el-radio-group v-model="form.format" size="small">
        <el-radio-button value="hex">十六进制</el-radio-button>
        <el-radio-button value="base64">Base64</el-radio-button>
      </el-radio-group>
      <div class="spacer" />
      <el-tag size="small" type="primary" effect="plain">{{ totalBytes }}字节</el-tag>
      <el-button size="small" text @click="copyText(form.input)">复制</el-button>
      <el-upload
        class="cert-upload"
        action="#"
        :auto-upload="false"
        :show-file-list="false"
        :on-change="handleFileChange"
        accept=".cer,.crt,.pem,.der,.p10,.csr,.p7b,.p7c"
      >
        <el-button size="small" text>
          <el-icon><Upload /></el-icon> 上传证书
        </el-button>
      </el-upload>
    </div>

    <el-input
      v-model="form.input"
      type="textarea"
      :rows="6"
      placeholder="请输入证书数据"
    />

    <div class="actions">
      <el-button :loading="loading" type="primary" @click="parse">解析 ASN.1</el-button>
      <el-button @click="cleanWhitespace">清理空格和换行</el-button>
      <el-button type="danger" plain @click="clearAll">清空</el-button>
    </div>

    <template v-if="treeData.length">
      <div class="sub-title" style="margin-top: 16px">
        <el-icon><List /></el-icon>
        <span>ASN.1 结构</span>
      </div>
      <el-tree
        :data="treeData"
        :props="{ label: 'label', children: 'children' }"
        default-expand-all
        node-key="id"
      >
        <template #default="{ node, data }">
          <span class="tree-node">
            <span class="node-type">{{ data.type }}</span>
            <span v-if="data.length != null" class="node-len">（长度: {{ data.length }}）</span>
            <span v-if="data.value" class="node-val">{{ data.value }}</span>
            <el-button v-if="data.value" size="small" text class="copy-btn" @click.stop="copyText(data.value)">Copy</el-button>
          </span>
        </template>
      </el-tree>
    </template>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { Document, Upload, List } from '@element-plus/icons-vue'
import api from '../../api'

const form = reactive({
  input: '',
  format: 'hex'
})

const treeData = ref([])
const loading = ref(false)
let idSeq = 0

const totalBytes = computed(() => {
  const s = (form.input || '').replace(/[\s\r\n]/g, '')
  if (!s) return 0
  if (form.format === 'hex') return Math.floor(s.length / 2)
  try { return Math.floor(atob(s).length) } catch { return 0 }
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

function handleFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    const bytes = new Uint8Array(e.target.result)
    const text = new TextDecoder().decode(bytes)
    if (text.includes('-----BEGIN')) {
      // PEM 文件：提取 base64 内容，解码为 DER 后再转 hex
      const base64 = text.replace(/-----BEGIN[^-]+-----/g, '').replace(/-----END[^-]+-----/g, '').replace(/[\s\r\n]/g, '')
      const der = Uint8Array.from(atob(base64), c => c.charCodeAt(0))
      form.input = Array.from(der).map(b => b.toString(16).padStart(2, '0')).join('')
    } else {
      // 二进制 DER 文件：直接转 hex
      form.input = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
    }
    form.format = 'hex'
    ElMessage.success('证书上传成功')
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

async function parse() {
  if (!form.input.trim()) {
    ElMessage.warning('请输入证书数据')
    return
  }
  loading.value = true
  treeData.value = []
  try {
    idSeq = 0
    const input = form.input.replace(/[\s\r\n]/g, '')
    const r = await api.post('/asn1/parse', { input, format: form.format })
    if (Array.isArray(r.root)) {
      treeData.value = r.root.map(toTree)
    } else {
      treeData.value = r.root ? [toTree(r.root)] : []
    }
  } catch (e) {
    // error handled by interceptor
  } finally {
    loading.value = false
  }
}

function cleanWhitespace() {
  form.input = form.input.replace(/[\s\r\n]/g, '')
  ElMessage.success('已清理空格和换行')
}

function clearAll() {
  form.input = ''
  form.format = 'hex'
  treeData.value = []
}
</script>

<style scoped>
.asn1-parse {
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
