import express from 'express';
import app from './admin-server.mjs';

export default function handler(req, res) {
  return app(req, res);
}
