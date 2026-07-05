<template>
  <el-card>
    <div class="page-title">电子签章校验</div>
    <el-form label-position="top">
      <el-form-item label="签章文件">
        <el-upload
          drag
          action="#"
          :auto-upload="false"
          :on-change="handleFileChange"
          :on-remove="handleRemove"
          :file-list="fileList"
          accept=".ofd,.pdf"
          style="width: 100%"
        >
          <el-icon class="el-icon--upload"><Upload /></el-icon>
          <div class="el-upload__text">点击或拖拽文件到此区域上传</div>
          <template #tip>
            <div class="el-upload__tip">支持 OFD / PDF 文件，单个文件大小不超过 10 MB。</div>
          </template>
        </el-upload>
      </el-form-item>

      <el-form-item>
        <div class="btn-row">
          <el-button type="primary" :loading="loading" @click="run">解析</el-button>
          <el-button @click="clear">清空</el-button>
        </div>
      </el-form-item>
    </el-form>

    <div v-if="result" class="result-section">
      <div class="section-title">校验结果</div>
      <el-alert v-if="result.error" :title="result.error" type="error" :closable="false" show-icon />
      <div v-else>
        <el-descriptions :column="2" border>
          <el-descriptions-item label="文件类型">{{ result.fileType }}</el-descriptions-item>
          <el-descriptions-item label="解析状态">{{ result.parsed ? '成功' : '失败' }}</el-descriptions-item>
          <el-descriptions-item label="签章数量">{{ result.extra?.signatureCount ?? 0 }}</el-descriptions-item>
          <el-descriptions-item v-if="result.extra?.tip" label="提示">{{ result.extra.tip }}</el-descriptions-item>
        </el-descriptions>

        <div v-for="(sig, idx) in result.signatures" :key="idx" class="sign-item">
          <div class="sign-title">签章 #{{ sig.index }}</div>
          <el-descriptions :column="2" border>
            <el-descriptions-item label="签章人">{{ sig.name || '-' }}</el-descriptions-item>
            <el-descriptions-item label="签章地点">{{ sig.location || '-' }}</el-descriptions-item>
            <el-descriptions-item label="签章原因">{{ sig.reason || '-' }}</el-descriptions-item>
            <el-descriptions-item label="签名时间">{{ sig.signTime || '-' }}</el-descriptions-item>
            <el-descriptions-item label="子过滤器">{{ sig.subFilter || '-' }}</el-descriptions-item>
            <el-descriptions-item label="签名值长度">{{ sig.signatureValueLength }} 字节</el-descriptions-item>
            <el-descriptions-item label="验证结果">
              <el-tag :type="sig.verified ? 'success' : 'danger'">{{ sig.verifyMessage }}</el-tag>
            </el-descriptions-item>
          </el-descriptions>

          <div v-if="sig.certificate && Object.keys(sig.certificate).length" class="cert-section">
            <div class="sub-title">签章人证书</div>
            <el-descriptions :column="2" border>
              <el-descriptions-item label="证书主题">{{ sig.certificate.subject || '-' }}</el-descriptions-item>
              <el-descriptions-item label="颁发者">{{ sig.certificate.issuer || '-' }}</el-descriptions-item>
              <el-descriptions-item label="序列号">{{ sig.certificate.serialNumber || '-' }}</el-descriptions-item>
              <el-descriptions-item label="有效期起">{{ sig.certificate.notBefore || '-' }}</el-descriptions-item>
              <el-descriptions-item label="有效期止">{{ sig.certificate.notAfter || '-' }}</el-descriptions-item>
              <el-descriptions-item label="签名算法">{{ sig.certificate.algorithm || '-' }}</el-descriptions-item>
            </el-descriptions>
          </div>
        </div>
      </div>
    </div>
  </el-card>
</template>

<script setup>
import { ref } from 'vue'
import { Upload } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const fileList = ref([])
const currentFile = ref(null)
const result = ref(null)
const loading = ref(false)

function handleFileChange(file) {
  fileList.value = [file]
  currentFile.value = file.raw
}

function handleRemove() {
  fileList.value = []
  currentFile.value = null
}

async function run() {
  if (!currentFile.value) {
    ElMessage.warning('请先上传签章文件')
    return
  }
  loading.value = true
  try {
    const formData = new FormData()
    formData.append('file', currentFile.value)
    result.value = await api.post('/seal/verify-file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
  } finally {
    loading.value = false
  }
}

function clear() {
  fileList.value = []
  currentFile.value = null
  result.value = null
}
</script>

<style scoped>
.page-title {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 20px;
}
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
}
.result-section {
  margin-top: 20px;
}
.section-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 12px;
}
.sign-item {
  margin-top: 16px;
  padding: 12px;
  border: 1px solid #ebeef5;
  border-radius: 4px;
}
.sign-title {
  font-weight: 600;
  margin-bottom: 10px;
}
.cert-section {
  margin-top: 12px;
}
.sub-title {
  font-weight: 600;
  margin-bottom: 8px;
  font-size: 14px;
}
</style>
