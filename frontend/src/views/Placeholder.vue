<template>
  <el-card>
    <el-empty :description="`「${$route.meta.title}」功能开发中`">
      <template #image>
        <el-icon :size="60" color="#c0c4cc"><Tools /></el-icon>
      </template>
      <p class="hint">该模块已在功能清单中登记，后端 API 与页面将分批交付。</p>
    </el-empty>
  </el-card>
</template>

<script setup>
</script>

<style scoped>
.hint { color: #909399; font-size: 13px; }
</style>
