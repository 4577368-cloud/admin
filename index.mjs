/**
 * Vercel Serverless Function 入口
 *
 * 1. 使用静态 import 替代顶层 await import，避免 Vercel 运行时不支持顶层 await 的问题。
 * 2. 显式写出 import express，触发 Vercel CLI 的 Express 框架检测正则。
 * 3. 不再引用 createServer（Vercel 不需要，删除避免误导构建器）。
 */

import express from 'express';           // ← 必须保留，Vercel CLI 靠这行识别 Express 框架
import app from '../admin-server.mjs';   // 静态导入，拿到已注册完所有路由的 app

export default function handler(req, res) {
  return app(req, res);
}