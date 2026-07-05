<template>
  <el-card>
    <div class="page-title">常见密文长度分析</div>

    <el-row :gutter="24">
      <!-- 左侧输入 -->
      <el-col :xs="24" :md="12">
        <el-form label-position="top">
          <el-form-item label="输入数据">
            <div class="format-row">
              <el-radio-group v-model="form.format" size="small">
                <el-radio-button value="utf8">字符串</el-radio-button>
              <el-radio-button value="hex">十六进制</el-radio-button>
              <el-radio-button value="base64">Base64</el-radio-button>
              </el-radio-group>
              <div class="data-actions">
                <el-tag size="small" type="info">{{ byteCount }} 字节</el-tag>
                <el-button size="small" :icon="DocumentCopy" @click="copy(form.input)">复制</el-button>
              </div>
            </div>
            <el-input
              v-model="form.input"
              type="textarea"
              :rows="8"
              placeholder="请输入待分析的密文或数据"
            />
            <div class="hint">
              <el-icon><InfoFilled /></el-icon>
              还没想好要提示些什么？
            </div>
          </el-form-item>

          <el-form-item>
            <div class="btn-row">
              <el-button native-type="button" type="primary" :loading="loading" @click="runAnalyze">开始分析</el-button>
              <el-button native-type="button" @click="cleanWhitespace">清理空格和换行</el-button>
              <el-button native-type="button" @click="clearAll">清空</el-button>
            </div>
          </el-form-item>
        </el-form>
      </el-col>

      <!-- 右侧分析结果 -->
      <el-col :xs="24" :md="12">
        <div class="section-title">分析结果</div>
        <div v-if="!result" class="empty-result">请输入数据并点击“开始分析”</div>
        <div v-else class="result-panel">
          <div class="result-category">
            <div class="category-title">哈希算法</div>
            <div v-if="result.matches.hash.length === 0" class="no-match">暂无匹配结果</div>
            <div v-else class="match-list">
              <div v-for="item in result.matches.hash" :key="item.name" class="match-item">
                {{ item.name }}
                <span v-if="item.securityBits" class="security-tag">(安全强度：{{ item.securityBits }})</span>
              </div>
            </div>
          </div>

          <div class="result-category">
            <div class="category-title">对称算法</div>
            <div v-if="result.matches.symmetric.length === 0" class="no-match">暂无匹配结果</div>
            <div v-else class="match-list">
              <div v-for="item in result.matches.symmetric" :key="item.name" class="match-item">
                {{ item.name }}
                <span v-if="item.securityBits" class="security-tag">(安全强度：{{ item.securityBits }})</span>
              </div>
            </div>
          </div>

          <div class="result-category">
            <div class="category-title">非对称算法</div>
            <div v-if="result.matches.asymmetric.length === 0" class="no-match">暂无匹配结果</div>
            <div v-else class="match-list">
              <div v-for="item in result.matches.asymmetric" :key="item.name" class="match-item">
                {{ item.name }}
                <span v-if="item.securityBits" class="security-tag">(安全强度：{{ item.securityBits }})</span>
              </div>
            </div>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 下方算法分组与安全强度 -->
    <div class="algorithm-section">
      <div class="section-title">各算法分组与安全强度</div>
      <el-tabs v-model="activeCategory" type="border-card">
        <el-tab-pane label="哈希算法" name="hash">
          <el-table :data="pagedAlgorithms" stripe style="width: 100%">
            <el-table-column prop="name" label="算法" min-width="180" />
            <el-table-column prop="lengthDescription" label="密文/分组长度" min-width="220" />
            <el-table-column prop="securityBits" label="安全强度" min-width="120">
              <template #default="{ row }">
                {{ row.securityBits ?? '-' }}
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
        <el-tab-pane label="对称算法" name="symmetric">
          <el-table :data="pagedAlgorithms" stripe style="width: 100%">
            <el-table-column prop="name" label="算法" min-width="180" />
            <el-table-column prop="lengthDescription" label="密文/分组长度" min-width="220" />
            <el-table-column prop="securityBits" label="安全强度" min-width="120">
              <template #default="{ row }">
                {{ row.securityBits ?? '-' }}
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
        <el-tab-pane label="非对称算法" name="asymmetric">
          <el-table :data="pagedAlgorithms" stripe style="width: 100%">
            <el-table-column prop="name" label="算法" min-width="180" />
            <el-table-column prop="lengthDescription" label="密文/分组长度" min-width="220" />
            <el-table-column prop="securityBits" label="安全强度" min-width="120">
              <template #default="{ row }">
                {{ row.securityBits ?? '-' }}
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
      <el-pagination
        v-model:current-page="page"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        :total="filteredAlgorithms.length"
        class="pagination"
      />
    </div>
  </el-card>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { DocumentCopy, InfoFilled } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '../../api'

const form = reactive({
  input: '',
  format: 'utf8'
})

const loading = ref(false)
const result = ref(null)
const allAlgorithms = ref([])
const activeCategory = ref('hash')
const page = ref(1)
const pageSize = ref(10)

onMounted(async () => {
  try {
    allAlgorithms.value = await api.get('/cipher-length/algorithms')
  } catch (e) {
    ElMessage.error('算法列表加载失败')
  }
})

const byteCount = computed(() => {
  if (!form.input) return 0
  if (form.format === 'hex') {
    const s = form.input.replace(/\s+/g, '')
    return Math.floor(s.length / 2)
  }
  if (form.format === 'base64') {
    try {
      const s = form.input.replace(/\s+/g, '')
      return Math.floor(atob(s).length)
    } catch (e) {
      return 0
    }
  }
  // utf8 / string
  return new Blob([form.input]).size
})

const filteredAlgorithms = computed(() => {
  return allAlgorithms.value.filter(item => item.category === activeCategory.value)
})

const pagedAlgorithms = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return filteredAlgorithms.value.slice(start, start + pageSize.value)
})

watch(activeCategory, () => {
  page.value = 1
})

function copy(text) {
  if (!text) return
  navigator.clipboard.writeText(text).then(() => ElMessage.success('已复制'))
}

function cleanWhitespace() {
  form.input = form.input.replace(/\s+/g, '')
}

function clearAll() {
  form.input = ''
  form.format = 'utf8'
  result.value = null
  activeCategory.value = 'hash'
  page.value = 1
}

async function runAnalyze() {
  if (!form.input.trim()) {
    ElMessage.warning('请输入待分析的数据')
    return
  }
  loading.value = true
  try {
    result.value = await api.post('/cipher-length/analyze', { ...form })
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
.section-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 12px;
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
.hint {
  margin-top: 8px;
  color: #909399;
  font-size: 12px;
  display: flex;
  align-items: center;
  gap: 4px;
}
.btn-row {
  width: 100%;
  display: flex;
  justify-content: center;
  gap: 12px;
}
.empty-result {
  color: #909399;
  padding: 40px 0;
  text-align: center;
}
.result-panel {
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  padding: 16px;
  min-height: 300px;
}
.result-category {
  margin-bottom: 20px;
}
.result-category:last-child {
  margin-bottom: 0;
}
.category-title {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 8px;
  color: #303133;
}
.no-match {
  color: #909399;
  font-size: 13px;
}
.match-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.match-item {
  font-size: 13px;
  color: #303133;
}
.security-tag {
  color: #606266;
  margin-left: 4px;
}
.algorithm-section {
  margin-top: 24px;
}
.algorithm-section :deep(.el-tabs__nav) {
  float: right;
}
.pagination {
  margin-top: 12px;
  justify-content: flex-end;
}
</style>
