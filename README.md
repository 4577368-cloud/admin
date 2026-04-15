# backend-local

Local-only backend for Supabase data operations.

## Why this folder exists

- 默认在本地运行；也可**单独**部署到 **Vercel**（本目录为 Project Root），与主站分离。
- 使用 **Supabase Service Role**，务必只在受信环境配置，勿提交到 Git。

## Setup

1. Copy env file:
   - `cp .env.example .env`
2. Fill in:
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY`
3. Install dependencies:
   - `npm install`
4. Start local backend:
   - `npm run dev`

Default URL: `http://localhost:8787`
Admin page: `http://localhost:8787/admin`

## 部署到 Vercel（单独项目）

1. 在 [Vercel](https://vercel.com) 新建 Project，**Root Directory** 选仓库里的 `backend-local`（或将本目录单独推成一个仓库）。
2. **Environment Variables**（Production / Preview 按需）至少配置：
   - `SUPABASE_URL` — 与线上 Supabase 项目一致。
   - `SUPABASE_SERVICE_ROLE_KEY` — **服务端密钥**，勿暴露给浏览器。
   - `LOCAL_BACKEND_ORIGIN` — 填你部署后的 Admin 根地址，例如 `https://your-admin.vercel.app`（用于 CORS；若只从同域名打开后台，与静态页同源，一般也可不设，但建议显式写上）。
   - 若使用自然语言查询（NLQ）：`VLLM_BASE_URL`、`VLLM_API_KEY`、`VLLM_MODEL_ID`。
3. Vercel 使用官方 **Express** 模式：根目录 `index.mjs` **默认导出** `app`（见 [Express on Vercel](https://vercel.com/docs/frameworks/backend/express)）。业务代码放在 **`admin-server.mjs`**（勿使用 `server.mjs` 文件名）。**`index.mjs` 内需保留 `import express from 'express'`** 以便框架检测。
4. **`vercel.json` 请保持为 `{}`**。不要自行写 `version: 2` + `routes` 且**不配** `builds`：那样会把请求指到未构建的 `index.mjs`，CLI 常报 `Cannot read properties of undefined (reading 'fsPath')`。
5. 部署完成后访问：`https://<你的域名>/admin`（或 `/admin/index.html`）。管理端静态页位于 **`public/admin/index.html`**，由 Vercel **CDN** 提供；线上 **不要** 依赖 `sendFile` 读 `public/index.html`（Serverless 包内常无该文件，易 404）。
6. **注意**：
   - Serverless 文件系统除 `/tmp` 外只读；NLQ schema 刷新会写入 `/tmp`（见 `admin-server.mjs`），冷启动后仍以仓库内 `admin_nlq_schema.md` 为准。
   - Hobby 套餐单函数默认 **10s** 超时，长耗时 NLQ 可能超时；若需更长可在 `vercel.json` 配置 `functions` 的 `maxDuration`（高阶套餐才生效）。

## Endpoints

- `GET /health`
- `GET /admin/api/overview`
- `GET /admin/api/users?page=1&pageSize=20&keyword=&vipOnly=0`
  - If RPC `admin_users` fails (SQL 未执行或版本不一致)，会自动回退到 **Auth Admin API** + `user_stats` 拼表（响应里 `data._source === 'auth_admin_fallback'`）。
  - 建议在 Supabase 执行 `supabase/sql/009_admin_users_group_by.sql` 修复 `admin_users`（多行 `user_stats` 时去重）。
- `GET /admin/api/trends?days=30`
- `POST /supabase/rpc/:fn`
  - body: `{ "args": { ... } }`
- `POST /supabase/query`
  - body:
    - `table`: string (required)
    - `select`: string (optional, default `*`)
    - `filters`: array (optional), each item: `{ "column": "user_id", "op": "eq", "value": "..." }`
    - `order`: object (optional), e.g. `{ "column": "created_at", "ascending": false }`
    - `limit`: number (optional)
    - `single`: boolean (optional)
- `POST /supabase/upsert`
  - body: `{ "table": "...", "rows": {...} | [{...}], "onConflict": "id" }`

This backend is local-only by design and uses service-role key to handle privileged Supabase operations off the frontend.
