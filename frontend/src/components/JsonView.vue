<template>
  <div class="json-view">
    <template v-for="(val, key) in data" :key="key">
      <div class="row">
        <span class="key">{{ key }}</span>
        <template v-if="isPrimitive(val)">
          <span class="val">{{ format(val) }}</span>
        </template>
        <template v-else-if="Array.isArray(val)">
          <div class="nested">
            <template v-if="val.length === 0"><span class="empty">[]</span></template>
            <template v-else-if="isPrimitive(val[0])">
              <el-tag v-for="(x, i) in val" :key="i" size="small" style="margin: 2px">{{ format(x) }}</el-tag>
            </template>
            <template v-else>
              <div v-for="(x, i) in val" :key="i" class="arr-item">
                <JsonView :data="x" />
              </div>
            </template>
          </div>
        </template>
        <template v-else>
          <div class="nested"><JsonView :data="val" /></div>
        </template>
      </div>
    </template>
  </div>
</template>

<script setup>
defineProps({ data: { type: [Object, Array], required: true } })
function isPrimitive(v) {
  return v === null || typeof v !== 'object'
}
function format(v) {
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  return String(v)
}
</script>

<style scoped>
.json-view { font-size: 13px; }
.row { display: flex; padding: 3px 0; border-bottom: 1px dashed #f0f0f0; }
.key { color: #409eff; font-weight: 600; min-width: 160px; flex-shrink: 0; }
.val { color: #303133; font-family: monospace; word-break: break-all; }
.nested { flex: 1; padding-left: 12px; }
.arr-item { border-left: 2px solid #ebeef5; padding-left: 8px; margin: 4px 0; }
.empty { color: #c0c4cc; }
</style>
