<template>
  <el-card class="cert-check">
    <div class="title">证书格式检查</div>

    <el-row :gutter="24" class="main-row">
      <!-- 左侧：证书链结构 + 节点编辑 -->
      <el-col :span="10" class="left-panel">
        <div class="panel-title">证书链结构</div>
        <div class="tree-actions">
          <el-button type="primary" size="small" @click="addChildNode">
            <el-icon><Plus /></el-icon> 子节点
          </el-button>
          <el-button size="small" @click="addSiblingNode">
            <el-icon><Plus /></el-icon> 同级节点
          </el-button>
          <el-button type="danger" size="small" plain @click="removeCurrentNode">
            <el-icon><Delete /></el-icon> 删除节点
          </el-button>
          <el-button size="small" @click="resetTree">
            <el-icon><RefreshRight /></el-icon>
          </el-button>
        </div>

        <div class="tree-wrap">
          <el-tree
            ref="treeRef"
            :data="treeData"
            node-key="id"
            highlight-current
            default-expand-all
            :expand-on-click-node="false"
            :props="{ label: 'name', children: 'children' }"
            @node-click="handleNodeClick"
          >
            <template #default="{ node, data }">
              <span class="tree-node">
                <el-icon v-if="data.children && data.children.length"><Folder /></el-icon>
                <el-icon v-else><Document /></el-icon>
                <span class="node-label">{{ node.label }}</span>
                <el-tag v-if="!data.cert" size="small" type="info" effect="plain" class="upload-tag">未上传</el-tag>
                <el-tag v-else size="small" type="success" effect="plain" class="upload-tag">已上传</el-tag>
              </span>
            </template>
          </el-tree>
        </div>

        <div class="node-edit">
          <div class="label"><span class="req">*</span> 当前节点名称</div>
          <el-input v-model="currentNode.name" placeholder="请输入当前节点名称" />

          <div class="label" style="margin-top: 12px"><span class="req">*</span> 当前节点证书</div>
          <div class="row">
            <el-radio-group v-model="currentNode.format" size="small">
              <el-radio-button value="hex">十六进制</el-radio-button>
              <el-radio-button value="base64">Base64</el-radio-button>
            </el-radio-group>
            <div class="spacer" />
            <el-tag size="small" type="primary" effect="plain">{{ certBytes }}字节</el-tag>
            <el-button size="small" text @click="copyText(currentNode.cert)">复制</el-button>
            <el-upload
              class="cert-upload"
              action="#"
              :auto-upload="false"
              :show-file-list="false"
              :on-change="handleFileChange"
              accept=".cer,.crt,.pem,.der"
            >
              <el-button size="small" text>
                <el-icon><Upload /></el-icon> 上传证书
              </el-button>
            </el-upload>
          </div>
          <el-input
            v-model="currentNode.cert"
            type="textarea"
            :rows="8"
            placeholder="请输入当前节点证书内容"
          />
        </div>

        <div class="actions">
          <el-button type="primary" :loading="checking" @click="formatCheck">
            <el-icon><Checked /></el-icon> 格式验证
          </el-button>
          <el-button :loading="chainChecking" @click="chainCheck">
            <el-icon><Connection /></el-icon> 证书链验证
          </el-button>
          <el-button type="danger" plain @click="clearCurrentNode">清空当前节点</el-button>
        </div>
      </el-col>

      <!-- 右侧：验证结果 -->
      <el-col :span="14" class="right-panel">
        <div class="panel-title">
          {{ currentNode.name || '当前节点' }} - 格式验证结果
        </div>

        <div v-if="!result && !chainResult" class="empty-result">
          <el-empty description="当前节点暂无格式验证结果，请点击“格式验证”" />
        </div>

        <template v-if="result">
          <el-descriptions :column="2" border title="基本信息">
            <el-descriptions-item label="版本">{{ result.version }}</el-descriptions-item>
            <el-descriptions-item label="是否SM2">
              <el-tag :type="result.isSm2 ? 'success' : 'info'">{{ result.isSm2 ? '是' : '否' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="序列号">{{ result.serialNumber }}</el-descriptions-item>
            <el-descriptions-item label="签名算法">{{ fmtAlg(result.signatureAlgorithm) }}</el-descriptions-item>
            <el-descriptions-item label="颁发者" :span="2">{{ result.issuer }}</el-descriptions-item>
            <el-descriptions-item label="使用者" :span="2">{{ result.subject }}</el-descriptions-item>
            <el-descriptions-item label="生效">{{ result.notBefore }}</el-descriptions-item>
            <el-descriptions-item label="失效">{{ result.notAfter }}</el-descriptions-item>
            <el-descriptions-item label="是否过期">
              <el-tag :type="result.expired ? 'danger' : 'success'">{{ result.expired ? '已过期' : '有效' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="公钥算法">{{ result.publicKeyAlgorithm }}</el-descriptions-item>
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

          <el-table v-if="result.extensions" :data="result.extensions" border style="margin-top: 12px">
            <el-table-column prop="name" label="扩展项" width="200" />
            <el-table-column prop="oid" label="OID" width="200" />
            <el-table-column prop="critical" label="关键" width="70" />
            <el-table-column prop="description" label="内容" />
          </el-table>
        </template>

        <template v-if="chainResult">
          <el-divider content-position="left">证书链验证结果</el-divider>
          <el-result
            :icon="chainResult.chainValid ? 'success' : 'error'"
            :title="chainResult.chainValid ? '证书链验证通过' : '证书链验证失败'"
            :sub-title="`共 ${chainResult.chainLength} 个节点`"
          />
          <el-alert
            v-if="chainResult.errors && chainResult.errors.length"
            :title="'错误信息'"
            type="error"
            :description="chainResult.errors.join('\n')"
            show-icon
            style="margin-bottom: 12px"
          />
          <el-table :data="chainResult.nodes" border>
            <el-table-column prop="index" label="层级" width="70" />
            <el-table-column prop="subject" label="主题" show-overflow-tooltip />
            <el-table-column prop="issuer" label="颁发者" show-overflow-tooltip />
            <el-table-column label="签名验证" width="100">
              <template #default="{ row }">
                <el-tag :type="row.signatureValid ? 'success' : 'danger'" size="small">
                  {{ row.signatureValid ? '通过' : '失败' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="有效期" width="90">
              <template #default="{ row }">
                <el-tag :type="row.expired ? 'danger' : 'success'" size="small">
                  {{ row.expired ? '过期' : '有效' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="signatureError" label="错误说明" show-overflow-tooltip />
          </el-table>
        </template>
      </el-col>
    </el-row>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed, nextTick } from 'vue'
import { ElMessage } from 'element-plus'
import {
  Plus, Delete, RefreshRight, Upload, Checked, Connection, Folder, Document
} from '@element-plus/icons-vue'
import api from '../../api'

let idCounter = 1

const treeRef = ref(null)
const treeData = ref([
  {
    id: 1,
    name: '根证书',
    cert: '',
    format: 'hex',
    children: [
      {
        id: 2,
        name: '中间证书',
        cert: '',
        format: 'hex',
        children: [
          {
            id: 3,
            name: '终端证书',
            cert: '',
            format: 'hex',
            children: []
          }
        ]
      }
    ]
  }
])

const currentNode = reactive({
  id: null,
  name: '',
  cert: '',
  format: 'hex'
})

const result = ref(null)
const chainResult = ref(null)
const checking = ref(false)
const chainChecking = ref(false)

const certBytes = computed(() => {
  const s = (currentNode.cert || '').replace(/[\s\r\n]/g, '')
  if (currentNode.format === 'hex') return Math.floor(s.length / 2)
  try {
    return Math.floor(atob(s).length)
  } catch {
    return 0
  }
})

function findNode(nodes, id) {
  for (const n of nodes) {
    if (n.id === id) return n
    if (n.children) {
      const found = findNode(n.children, id)
      if (found) return found
    }
  }
  return null
}

function findParent(nodes, id, parent = null) {
  for (const n of nodes) {
    if (n.id === id) return parent
    if (n.children) {
      const found = findParent(n.children, id, n)
      if (found) return found
    }
  }
  return null
}

function handleNodeClick(data) {
  syncCurrentToTree()
  currentNode.id = data.id
  currentNode.name = data.name
  currentNode.cert = data.cert
  currentNode.format = data.format || 'hex'
}

function syncCurrentToTree() {
  if (currentNode.id == null) return
  const node = findNode(treeData.value, currentNode.id)
  if (node) {
    node.name = currentNode.name
    node.cert = currentNode.cert
    node.format = currentNode.format
  }
}

function addChildNode() {
  syncCurrentToTree()
  const parentId = currentNode.id || treeData.value[0]?.id
  const parent = findNode(treeData.value, parentId)
  if (!parent) {
    ElMessage.warning('请先选择一个节点')
    return
  }
  if (!parent.children) parent.children = []
  const newNode = {
    id: ++idCounter,
    name: '新节点',
    cert: '',
    format: 'hex',
    children: []
  }
  parent.children.push(newNode)
  nextTick(() => {
    treeRef.value.setCurrentKey(newNode.id)
    handleNodeClick(newNode)
  })
}

function addSiblingNode() {
  syncCurrentToTree()
  if (currentNode.id == null) {
    ElMessage.warning('请先选择一个节点')
    return
  }
  const parent = findParent(treeData.value, currentNode.id)
  const siblings = parent ? parent.children : treeData.value
  const newNode = {
    id: ++idCounter,
    name: '新节点',
    cert: '',
    format: 'hex',
    children: []
  }
  siblings.push(newNode)
  nextTick(() => {
    treeRef.value.setCurrentKey(newNode.id)
    handleNodeClick(newNode)
  })
}

function removeCurrentNode() {
  if (currentNode.id == null) {
    ElMessage.warning('请先选择一个节点')
    return
  }
  const parent = findParent(treeData.value, currentNode.id)
  const siblings = parent ? parent.children : treeData.value
  const idx = siblings.findIndex(n => n.id === currentNode.id)
  if (idx === -1) return
  siblings.splice(idx, 1)
  currentNode.id = null
  currentNode.name = ''
  currentNode.cert = ''
  currentNode.format = 'hex'
  result.value = null
  chainResult.value = null
  if (treeData.value.length && !currentNode.id) {
    nextTick(() => {
      const first = treeData.value[0]
      treeRef.value.setCurrentKey(first.id)
      handleNodeClick(first)
    })
  }
}

function resetTree() {
  idCounter = 3
  treeData.value = [
    {
      id: 1,
      name: '根证书',
      cert: '',
      format: 'hex',
      children: [
        {
          id: 2,
          name: '中间证书',
          cert: '',
          format: 'hex',
          children: [
            {
              id: 3,
              name: '终端证书',
              cert: '',
              format: 'hex',
              children: []
            }
          ]
        }
      ]
    }
  ]
  currentNode.id = 1
  currentNode.name = '根证书'
  currentNode.cert = ''
  currentNode.format = 'hex'
  result.value = null
  chainResult.value = null
  nextTick(() => treeRef.value.setCurrentKey(1))
}

function handleFileChange(file) {
  const reader = new FileReader()
  reader.onload = (e) => {
    const content = e.target.result
    currentNode.cert = arrayBufferToHex(content)
    currentNode.format = 'hex'
    ElMessage.success('证书上传成功')
  }
  reader.readAsArrayBuffer(file.raw)
}

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function copyText(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}

function fmtAlg(a) {
  if (!a) return ''
  if (typeof a === 'string') return a
  return `${a.name || ''} (${a.oid || ''})`
}

function collectChain(nodes, list) {
  for (const n of nodes) {
    list.push(n)
    if (n.children && n.children.length) {
      collectChain(n.children, list)
    }
  }
}

async function formatCheck() {
  syncCurrentToTree()
  if (!currentNode.cert.trim()) {
    ElMessage.warning('请输入当前节点证书内容')
    return
  }
  checking.value = true
  result.value = null
  chainResult.value = null
  try {
    const certInput = buildCertInput(currentNode.cert, currentNode.format)
    result.value = await api.post('/cert/format/check', { certPem: certInput })
  } catch (e) {
    // error handled by interceptor
  } finally {
    checking.value = false
  }
}

async function chainCheck() {
  syncCurrentToTree()
  const list = []
  collectChain(treeData.value, list)
  const certs = list
    .filter(n => n.cert && n.cert.trim())
    .map(n => buildCertInput(n.cert, n.format))
  if (certs.length === 0) {
    ElMessage.warning('请至少上传一个证书节点')
    return
  }
  chainChecking.value = true
  result.value = null
  chainResult.value = null
  try {
    chainResult.value = await api.post('/cert/chain/validate', { certs })
  } catch (e) {
    // error handled by interceptor
  } finally {
    chainChecking.value = false
  }
}

function buildCertInput(cert, format) {
  const cleaned = cert.replace(/[\s\r\n]/g, '')
  if (format === 'base64') {
    return cleaned
  }
  return cleaned
}

function clearCurrentNode() {
  currentNode.cert = ''
  syncCurrentToTree()
  result.value = null
  chainResult.value = null
  ElMessage.success('已清空当前节点')
}

// 初始化选中根证书
nextTick(() => {
  const first = treeData.value[0]
  if (first) {
    treeRef.value.setCurrentKey(first.id)
    handleNodeClick(first)
  }
})
</script>

<style scoped>
.cert-check {
  min-height: 600px;
}
.title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 16px;
}
.main-row {
  min-height: 520px;
}
.left-panel, .right-panel {
  border: 1px solid #e4e7ed;
  border-radius: 8px;
  padding: 16px;
  background: #fafafa;
}
.right-panel {
  background: #fff;
}
.panel-title {
  font-weight: 600;
  margin-bottom: 12px;
  font-size: 15px;
}
.tree-actions {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.tree-wrap {
  max-height: 180px;
  overflow: auto;
  background: #fff;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  padding: 8px;
  margin-bottom: 16px;
}
.tree-node {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: 1;
}
.node-label {
  flex: 1;
}
.upload-tag {
  margin-left: auto;
}
.node-edit {
  background: #fff;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  padding: 12px;
  margin-bottom: 16px;
}
.label {
  font-weight: 500;
  margin-bottom: 6px;
  font-size: 14px;
}
.req {
  color: #f56c6c;
  margin-right: 2px;
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
  flex-wrap: wrap;
  justify-content: center;
}
.empty-result {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 300px;
}
</style>
