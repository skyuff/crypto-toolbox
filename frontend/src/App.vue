<template>
  <el-container class="app-container">
    <el-aside width="240px" class="sidebar">
      <div class="logo">商用密码检测工具箱</div>
      <div class="search-box">
        <el-select
          v-model="searchValue"
          filterable
          clearable
          placeholder="搜索功能，如 SM4 / 证书 / 哈希"
          :filter-method="filterFn"
          popper-class="fn-search-popper"
          @change="onSelect"
        >
          <el-option-group
            v-for="group in filteredMenus"
            :key="group.title"
            :label="group.title"
          >
            <el-option
              v-for="item in group.children"
              :key="item.path"
              :label="item.title"
              :value="item.path"
            >
              <span class="opt-title">{{ item.title }}</span>
              <span class="opt-group">{{ group.title }}</span>
            </el-option>
          </el-option-group>
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-select>
      </div>
      <el-menu
        :default-active="$route.path"
        router
        class="menu"
        unique-opened
      >
        <el-sub-menu
          v-for="(group, gi) in menus"
          :key="gi"
          :index="'g' + gi"
        >
          <template #title>{{ group.title }}</template>
          <el-menu-item
            v-for="item in group.children"
            :key="item.path"
            :index="item.path"
          >
            {{ item.title }}
          </el-menu-item>
        </el-sub-menu>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="header">
        <span class="title">{{ $route.meta.title || '首页' }}</span>
        <span class="group">{{ $route.meta.group }}</span>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { menus } from './menus'

const router = useRouter()
const searchValue = ref('')
const keyword = ref('')

// el-select 的过滤方法：记录输入关键词，用于按标题+分组名过滤
function filterFn(query) {
  keyword.value = (query || '').trim().toLowerCase()
}

// 根据关键词过滤菜单（匹配功能名或所属分组名），保留分组结构
const filteredMenus = computed(() => {
  const kw = keyword.value
  if (!kw) return menus
  return menus
    .map((group) => {
      const groupHit = group.title.toLowerCase().includes(kw)
      const children = group.children.filter(
        (item) => groupHit || item.title.toLowerCase().includes(kw)
      )
      return { ...group, children }
    })
    .filter((group) => group.children.length > 0)
})

// 选中某功能后跳转到对应路由，并清空搜索框
function onSelect(path) {
  if (path) {
    router.push(path)
    searchValue.value = ''
    keyword.value = ''
  }
}
</script>

<style>
html, body, #app { height: 100%; margin: 0; }
.app-container { height: 100vh; }
.sidebar {
  background: #001529;
  overflow-y: auto;
}
.logo {
  color: #fff;
  font-size: 16px;
  font-weight: bold;
  text-align: center;
  padding: 18px 8px;
  border-bottom: 1px solid #1f3350;
}
.search-box {
  padding: 12px 10px;
  border-bottom: 1px solid #1f3350;
}
.search-box .el-select {
  width: 100%;
}
.fn-search-popper .opt-title {
  font-weight: 500;
}
.fn-search-popper .opt-group {
  float: right;
  color: #909399;
  font-size: 12px;
}
.menu {
  border-right: none;
  background: #001529;
}
.el-sub-menu__title, .menu .el-menu-item {
  color: #c0c4cc !important;
}
.header {
  display: flex;
  align-items: baseline;
  gap: 12px;
  border-bottom: 1px solid #ebeef5;
  background: #fff;
}
.header .title { font-size: 18px; font-weight: 600; }
.header .group { color: #909399; font-size: 13px; }
.el-main { background: #f5f7fa; }
</style>
