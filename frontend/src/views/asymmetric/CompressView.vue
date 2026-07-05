<template>
  <el-card>
    <div class="title">SM2 / SM9 点压缩与解压</div>

    <el-row :gutter="24">
      <el-col :span="12">
        <div class="sub-title">
          <el-icon><Link /></el-icon>
          <span>未压缩公钥（04 开头）</span>
        </div>
        <div class="row">
          <el-radio-group v-model="uncomprFmt" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ hexBytes(uncompressed) }}字节</el-tag>
          <el-button size="small" text @click="copyText(uncompressed)">复制</el-button>
        </div>
        <el-input
          v-model="uncompressed"
          type="textarea"
          :rows="6"
          placeholder="请输入待压缩的未压缩公钥"
        />
      </el-col>

      <el-col :span="12">
        <div class="sub-title">
          <el-icon><Link /></el-icon>
          <span>压缩公钥（02 / 03 开头）</span>
        </div>
        <div class="row">
          <el-radio-group v-model="comprFmt" size="small">
            <el-radio-button value="hex">十六进制</el-radio-button>
          </el-radio-group>
          <div class="spacer" />
          <el-tag size="small" type="primary" effect="plain">{{ hexBytes(compressed) }}字节</el-tag>
          <el-button size="small" text @click="copyText(compressed)">复制</el-button>
        </div>
        <el-input
          v-model="compressed"
          type="textarea"
          :rows="6"
          placeholder="请输入待解压的压缩公钥"
        />
      </el-col>
    </el-row>

    <div class="curve-type">
      <span class="label">曲线类型</span>
      <el-radio-group v-model="curveType">
        <el-radio-button value="sm2p256v1">SM2 曲线</el-radio-button>
        <el-radio-button value="sm9">SM9 曲线</el-radio-button>
      </el-radio-group>
    </div>

    <div class="actions">
      <el-button :loading="loading" @click="doCompress">压缩公钥</el-button>
      <el-button :loading="loading" @click="doDecompress">解压公钥</el-button>
      <el-button type="primary" @click="cleanWhitespace">清理空格和换行</el-button>
      <el-button type="danger" plain @click="clearAll">清空</el-button>
    </div>
  </el-card>
</template>

<script setup>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Link } from '@element-plus/icons-vue'
import api from '../../api'

const curveType = ref('sm2p256v1')
const uncomprFmt = ref('hex')
const comprFmt = ref('hex')
const uncompressed = ref('')
const compressed = ref('')
const loading = ref(false)

function cleanHex(s) {
  return (s || '').replace(/[\s\r\n]/g, '')
}

function hexBytes(s) {
  const h = cleanHex(s)
  return Math.floor(h.length / 2)
}

function copyText(text) {
  if (!text) return
  navigator.clipboard.writeText(text)
  ElMessage.success('已复制')
}

async function doCompress() {
  const point = cleanHex(uncompressed.value)
  if (!point) {
    ElMessage.warning('请输入未压缩公钥')
    return
  }
  loading.value = true
  try {
    const data = await api.post('/point/compress-public-key', {
      curve: curveType.value,
      point
    })
    if (data.valid) {
      compressed.value = data.compressed
      ElMessage.success('压缩成功')
    } else {
      ElMessage.error('公钥无效：' + (data.error || '点不在曲线上'))
    }
  } catch (e) {
    ElMessage.error('压缩失败：' + e.message)
  } finally {
    loading.value = false
  }
}

async function doDecompress() {
  const point = cleanHex(compressed.value)
  if (!point) {
    ElMessage.warning('请输入压缩公钥')
    return
  }
  loading.value = true
  try {
    const data = await api.post('/point/decompress-public-key', {
      curve: curveType.value,
      point
    })
    if (data.valid) {
      uncompressed.value = data.uncompressed
      ElMessage.success('解压成功')
    } else {
      ElMessage.error('公钥无效：' + (data.error || '点不在曲线上'))
    }
  } catch (e) {
    ElMessage.error('解压失败：' + e.message)
  } finally {
    loading.value = false
  }
}

function cleanWhitespace() {
  uncompressed.value = cleanHex(uncompressed.value)
  compressed.value = cleanHex(compressed.value)
  ElMessage.success('已清理空格和换行')
}

function clearAll() {
  uncompressed.value = ''
  compressed.value = ''
}
</script>

<style scoped>
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
}
.spacer {
  flex: 1;
}
.curve-type {
  margin: 20px 0;
  display: flex;
  align-items: center;
  gap: 12px;
}
.curve-type .label {
  font-weight: 500;
  min-width: 70px;
}
.actions {
  display: flex;
  gap: 12px;
  justify-content: center;
  margin: 8px 0 20px;
}
</style>
