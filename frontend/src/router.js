import { createRouter, createWebHistory } from 'vue-router'
import { menus } from './menus'
import Placeholder from './views/Placeholder.vue'

// 自动收集 views 下所有已实现的页面组件
const modules = import.meta.glob('./views/**/*.vue')

function resolveComponent(view) {
  const key = `./views/${view}.vue`
  if (modules[key]) {
    return modules[key]
  }
  // 未实现的功能回退到占位页
  return Placeholder
}

const routes = [
  { path: '/', redirect: '/group' }
]

for (const group of menus) {
  for (const item of group.children) {
    routes.push({
      path: item.path,
      name: item.path,
      component: resolveComponent(item.view),
      meta: { title: item.title, group: group.title }
    })
  }
}

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router
