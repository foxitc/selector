"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApp = createApp;
// app.ts
const express_1 = __importDefault(require("express"));
const helmet_1 = __importDefault(require("helmet"));
const cors_1 = __importDefault(require("cors"));
const morgan_1 = __importDefault(require("morgan"));
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const env_js_1 = require("./config/env.js");
const routes_js_1 = __importDefault(require("./v1/routes.js"));
function createApp() {
    const app = (0, express_1.default)();
    app.use((0, helmet_1.default)({ contentSecurityPolicy: false }));
    app.set('trust proxy', 1);
    const origins = env_js_1.env.ALLOWED_ORIGINS.split(',').map(o => o.trim());
    app.use((0, cors_1.default)({
        origin: (origin, cb) => (!origin || origins.includes(origin) ? cb(null, true) : cb(new Error('CORS'))),
        credentials: true,
    }));
    app.use((0, express_rate_limit_1.default)({ windowMs: 60_000, max: 300, standardHeaders: true, legacyHeaders: false }));
    app.use(express_1.default.json({
      limit: '2mb',
      verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
      }
    }));
    app.use((0, morgan_1.default)(env_js_1.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
    app.get('/health', (_, res) => res.json({
        status: 'ok',
        service: 'Test Player API',
        timestamp: new Date().toISOString(),
    }));
    app.use('/api/v1', routes_js_1.default);
    app.use((err, _req, res, _next) => {
        if (err.name === 'ZodError') {
            return res.status(400).json({ data: null, error: { message: 'Validation error', details: err.message } });
        }
        console.error('[Error]', err);
        res.status(500).json({ data: null, error: { message: env_js_1.env.NODE_ENV === 'production' ? 'Internal error' : err.message } });
    });
    return app;
}
