<template>
  <el-card>
    <div class="page-title">工作模式检测</div>

    <el-alert type="info" :closable="false" style="margin-bottom: 12px"
      title="密文合规检测：无需密钥，静态分析密文分组重复（ECB 泄露特征）、长度对齐及两组密文对比，判断工作模式风险。" />

    <el-form label-position="top">
      <!-- 两个输入区并排 -->
      <el-row :gutter="24">
        <el-col :xs="24" :md="12">
          <el-form-item label="密文 1">
            <div class="format-row">
              <el-radio-group v-model="form.format1" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.ciphertext1, form.format1) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.ciphertext1)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.ciphertext1" type="textarea" :rows="4" placeholder="请输入第一组密文数据" />
            <div class="hint-row">
              <el-icon><Info-Filled /></el-icon>
              <span>输入第一组密文，用于比较分析。</span>
            </div>
          </el-form-item>
        </el-col>

        <el-col :xs="24" :md="12">
          <el-form-item label="密文 2">
            <div class="format-row">
              <el-radio-group v-model="form.format2" size="small">
                <el-radio-button value="hex">十六进制</el-radio-button>
                <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount(form.ciphertext2, form.format2) }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.ciphertext2)">复制</el-button>
              </div>
            </div>
            <el-input v-model="form.ciphertext2" type="textarea" :rows="4" placeholder="请输入第二组密文数据" />
            <div class="hint-row">
              <el-icon><Info-Filled /></el-icon>
              <span>输入第二组密文，用于比较分析。</span>
            </div>
          </el-form-item>
        </el-col>
      </el-row>

      <!-- 分组大小 -->
      <el-form-item label="分组大小">
        <el-select v-model="form.blockSize" style="width: 160px">
          <el-option :value="16" label="16 (SM4/AES)" />
          <el-option :value="8" label="8 (DES/3DES)" />
        </el-select>
      </el-form-item>

      <!-- 操作按钮 -->
      <el-form-item>
        <div class="btn-row">
          <el-button type="primary" :loading="loading" @click="run">开始检测</el-button>
          <el-button @click="cleanWhitespace">清理空格和换行</el-button>
          <el-button type="danger" plain @click="clearAll">清空</el-button>
        </div>
      </el-form-item>

      <!-- 结果展示 -->
      <template v-if="result">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="分组大小">{{ result.blockSize }} 字节</el-descriptions-item>
          <el-descriptions-item label="共同分组数">{{ result.commonBlocks }}</el-descriptions-item>
          <el-descriptions-item label="分组相似度">{{ result.similarity }}%</el-descriptions-item>
          <el-descriptions-item label="密文1 分组数">{{ result.blockCount1 }}</el-descriptions-item>
          <el-descriptions-item label="密文1 重复分组">{{ result.duplicateBlocks1 }}</el-descriptions-item>
          <el-descriptions-item label="密文1 长度对齐">{{ result.isBlockAligned1 ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="密文1 疑似ECB">
            <el-tag :type="result.suspectedEcb1 ? 'danger' : 'success'">{{ result.suspectedEcb1 ? '是（有风险）' : '否' }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="密文2 分组数">{{ result.blockCount2 }}</el-descriptions-item>
          <el-descriptions-item label="密文2 重复分组">{{ result.duplicateBlocks2 }}</el-descriptions-item>
          <el-descriptions-item label="密文2 长度对齐">{{ result.isBlockAligned2 ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item label="密文2 疑似ECB">
            <el-tag :type="result.suspectedEcb2 ? 'danger' : 'success'">{{ result.suspectedEcb2 ? '是（有风险）' : '否' }}</el-tag>
          </el-descriptions-item>
        </el-descriptions>
        <el-table v-if="result.findings" :data="result.findings" border style="margin-top: 12px">
          <el-table-column prop="level" label="级别" width="90">
            <template #default="{ row }">
              <el-tag size="small" :type="row.level === 'risk' ? 'danger' : row.level === 'warn' ? 'warning' : 'info'">{{ row.level }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="item" label="检查项" width="180" />
          <el-table-column prop="message" label="说明" />
        </el-table>
      </template>
    </el-form>
  </el-card>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { DocumentCopy, InfoFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const form = reactive({
  ciphertext1: '',
  format1: 'hex',
  ciphertext2: '',
  format2: 'hex',
  blockSize: 16
})

const result = ref(null)
const loading = ref(false)

function byteCount(value, format) {
  if (!value) return 0
  const fmt = (format || 'hex').toLowerCase()
  if (fmt === 'base64') {
    try {
      const s = value.replace(/\s+/g, '')
      return Math.floor(atob(s).length)
    } catch (e) {
      return 0
    }
  }
  const s = value.replace(/\s+/g, '').replace(/^0x/i, '')
  return Math.floor(s.length / 2)
}

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace() {
  form.ciphertext1 = form.ciphertext1.replace(/\s+/g, '')
  form.ciphertext2 = form.ciphertext2.replace(/\s+/g, '')
}

function clearAll() {
  form.ciphertext1 = ''
  form.format1 = 'hex'
  form.ciphertext2 = ''
  form.format2 = 'hex'
  form.blockSize = 16
  result.value = null
}

async function run() {
  if (!form.ciphertext1.trim() && !form.ciphertext2.trim()) {
    ElMessage.warning('请至少输入一组密文')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/cipher-mode/detect', form)
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
.format-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}
.data-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}
.hint-row {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  color: #909399;
  font-size: 13px;
  margin-top: 6px;
  line-height: 1.5;
}
.hint-row .el-icon {
  margin-top: 1px;
  flex-shrink: 0;
}
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
  margin-top: 8px;
}
</style>
