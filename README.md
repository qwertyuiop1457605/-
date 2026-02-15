#!/usr/bin/env bash
set -e
ROOT_DIR="order-system"
ZIP_NAME="order-system.zip"

if [ -d "$ROOT_DIR" ]; then
  echo "目录 $ROOT_DIR 已存在，先删除以重新生成..."
  rm -rf "$ROOT_DIR"
fi

mkdir -p "$ROOT_DIR"
cd "$ROOT_DIR"

echo "创建项目目录结构..."
mkdir -p backend/src backend/data frontend/src frontend/src/components

echo "写入文件: docker-compose.yml"
cat > docker-compose.yml <<'EOF'
version: "3.8"
services:
  backend:
    build: ./backend
    ports:
      - "3000:3000"
    environment:
      - JWT_SECRET=devsecret
      - DATABASE_FILE=/data/db.sqlite
    volumes:
      - backend_data:/data
      - ./backend:/app
  frontend:
    build: ./frontend
    ports:
      - "5173:5173"
    environment:
      - VITE_API_BASE=http://localhost:3000/api
volumes:
  backend_data:
EOF

echo "写入文件: README.md"
cat > README.md <<'EOF'
# 点餐系统 - 最小可运行 Demo

说明（简体中文）：
- 前端：Vue 3 + Vite，运行端口 5173
- 后端：Node.js + Express，运行端口 3000
- 数据库：SQLite（文件存储在 backend_data 卷）
- 支付：模拟（下单后自动标为已支付）

快速启动（需 Docker 与 docker-compose）：
1. 在本项目根目录执行：
   docker-compose up --build
2. 打开浏览器访问前端：
   http://localhost:5173

如果不使用 Docker：
1. 后端：
   cd backend
   npm install
   npm run dev
2. 前端：
   cd frontend
   npm install
   npm run dev

测试账户：
- 注册新用户（前端界面有注册），或使用任意手机号码注册登录。

后端 API 主要端点：
- POST /api/auth/register {name, phone, password}
- POST /api/auth/login {phone, password} -> { token }
- GET /api/items
- GET /api/cart (auth)
- POST /api/cart { item_id, qty } (auth)
- POST /api/orders/checkout (auth) -> 创建订单并模拟支付
- GET /api/orders (auth)
- GET /api/merchant/orders -> 商家查看所有订单（演示用，无商家鉴权）

说明与安全提示
- 该 demo 为最小实现，许多生产级别的功能（输入校验、更完善的错误处理、权限校验、商家鉴权、图片存储、支付签名等）未实现，仅用于演示与本地开发。
- 在生产环境请务必：
  - 使用强 JWT_SECRET 且从环境变量读取；
  - 对密码使用可靠的 hash（本示例使用 bcryptjs）并添加速率限制；
  - 对用户输入进行验证与防注入；
  - 将 SQLite 替换为 PostgreSQL 或 MySQL（并添加迁移脚本）。
EOF

echo "写入文件: backend/package.json"
cat > backend/package.json <<'EOF'
{
  "name": "order-system-backend",
  "version": "1.0.0",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon --watch src --exec node src/server.js"
  },
  "dependencies": {
    "better-sqlite3": "^8.5.0",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}
EOF

echo "写入文件: backend/Dockerfile"
cat > backend/Dockerfile <<'EOF'
FROM node:18-slim
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "src/server.js"]
EOF

echo "写入文件: backend/src/db.js"
cat > backend/src/db.js <<'EOF'
const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const dbFile = process.env.DATABASE_FILE || path.join(__dirname, '..', 'data', 'db.sqlite');
const dir = path.dirname(dbFile);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(dbFile);

// 初始化表
db.exec(`
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  phone TEXT UNIQUE,
  password_hash TEXT,
  role TEXT DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS shops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  merchant_id INTEGER,
  address TEXT
);
CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop_id INTEGER,
  name TEXT,
  description TEXT,
  price_cents INTEGER,
  stock INTEGER DEFAULT 999,
  image_url TEXT
);
CREATE TABLE IF NOT EXISTS carts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  item_id INTEGER,
  qty INTEGER
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  shop_id INTEGER,
  total_cents INTEGER,
  status TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER,
  item_id INTEGER,
  qty INTEGER,
  price_cents INTEGER
);
`);

// seed demo shop/items if empty
const countItems = db.prepare('SELECT COUNT(*) as c FROM items').get().c;
if (countItems === 0) {
  const shop = db.prepare('INSERT INTO shops (name, merchant_id, address) VALUES (?, ?, ?)').run('示例门店', 1, '示例地址');
  const shopId = shop.lastInsertRowid;
  const insert = db.prepare('INSERT INTO items (shop_id, name, description, price_cents, stock, image_url) VALUES (?, ?, ?, ?, ?, ?)');
  insert.run(shopId, '宫保鸡丁', '经典川味宫保鸡丁', 3200, 50, '');
  insert.run(shopId, '鱼香肉丝', '下饭必备', 2800, 60, '');
  insert.run(shopId, '酸辣土豆丝', '清爽', 1500, 80, '');
}

module.exports = db;
EOF

echo "写入文件: backend/src/middleware/auth.js"
cat > backend/src/middleware/auth.js <<'EOF'
const jwt = require('jsonwebtoken');
const secret = process.env.JWT_SECRET || 'devsecret';

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'missing token' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'bad auth' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, secret);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

module.exports = { authMiddleware, secret };
EOF

echo "写入文件: backend/src/routes/auth.js"
cat > backend/src/routes/auth.js <<'EOF'
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { secret } = require('../middleware/auth');

router.post('/register', (req, res) => {
  const { name, phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: 'phone & password required' });
  const hash = bcrypt.hashSync(password, 8);
  try {
    const info = db.prepare('INSERT INTO users (name, phone, password_hash) VALUES (?, ?, ?)').run(name || phone, phone, hash);
    const user = { id: info.lastInsertRowid, name: name || phone, phone };
    const token = jwt.sign(user, secret, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (e) {
    res.status(400).json({ error: 'phone exists' });
  }
});

router.post('/login', (req, res) => {
  const { phone, password } = req.body;
  const row = db.prepare('SELECT id, name, phone, password_hash FROM users WHERE phone = ?').get(phone);
  if (!row) return res.status(400).json({ error: 'invalid credentials' });
  if (!bcrypt.compareSync(password, row.password_hash)) return res.status(400).json({ error: 'invalid credentials' });
  const user = { id: row.id, name: row.name, phone: row.phone };
  const token = jwt.sign(user, secret, { expiresIn: '7d' });
  res.json({ token, user });
});

module.exports = router;
EOF

echo "写入文件: backend/src/routes/items.js"
cat > backend/src/routes/items.js <<'EOF'
const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/', (req, res) => {
  const items = db.prepare('SELECT items.*, shops.name as shop_name FROM items LEFT JOIN shops ON items.shop_id = shops.id').all();
  res.json({ items });
});

module.exports = router;
EOF

echo "写入文件: backend/src/routes/cart.js"
cat > backend/src/routes/cart.js <<'EOF'
const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/', (req, res) => {
  const userId = req.user.id;
  const rows = db.prepare('SELECT carts.id as cart_id, items.*, carts.qty FROM carts JOIN items ON carts.item_id = items.id WHERE carts.user_id = ?').all(userId);
  res.json({ cart: rows });
});

router.post('/', (req, res) => {
  const userId = req.user.id;
  const { item_id, qty } = req.body;
  const existing = db.prepare('SELECT id, qty FROM carts WHERE user_id = ? AND item_id = ?').get(userId, item_id);
  if (existing) {
    db.prepare('UPDATE carts SET qty = ? WHERE id = ?').run(existing.qty + (qty || 1), existing.id);
  } else {
    db.prepare('INSERT INTO carts (user_id, item_id, qty) VALUES (?, ?, ?)').run(userId, item_id, qty || 1);
  }
  res.json({ ok: true });
});

router.delete('/:cartId', (req, res) => {
  const userId = req.user.id;
  const cartId = req.params.cartId;
  db.prepare('DELETE FROM carts WHERE id = ? AND user_id = ?').run(cartId, userId);
  res.json({ ok: true });
});

module.exports = router;
EOF

echo "写入文件: backend/src/routes/orders.js"
cat > backend/src/routes/orders.js <<'EOF'
const express = require('express');
const router = express.Router();
const db = require('../db');

router.post('/checkout', (req, res) => {
  const userId = req.user.id;
  // 获取购物车
  const items = db.prepare('SELECT carts.id as cart_id, items.*, carts.qty FROM carts JOIN items ON carts.item_id = items.id WHERE carts.user_id = ?').all(userId);
  if (items.length === 0) return res.status(400).json({ error: 'cart empty' });
  // 计算总价（简单：取第一个 item 的 shop_id 作为 shop）
  const shopId = items[0].shop_id;
  const total = items.reduce((s, it) => s + it.price_cents * it.qty, 0);
  const info = db.prepare('INSERT INTO orders (user_id, shop_id, total_cents, status) VALUES (?, ?, ?, ?)').run(userId, shopId, total, 'paid'); // 模拟已支付
  const orderId = info.lastInsertRowid;
  const insertItem = db.prepare('INSERT INTO order_items (order_id, item_id, qty, price_cents) VALUES (?, ?, ?, ?)');
  const delCart = db.prepare('DELETE FROM carts WHERE id = ?');
  for (const it of items) {
    insertItem.run(orderId, it.id, it.qty, it.price_cents);
    delCart.run(it.cart_id);
  }
  res.json({ ok: true, orderId });
});

router.get('/', (req, res) => {
  const userId = req.user.id;
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC').all(userId);
  res.json({ orders });
});

// 商家查看所有订单（演示用）
router.get('/merchant/all', (req, res) => {
  const orders = db.prepare('SELECT orders.*, users.name as user_name FROM orders LEFT JOIN users ON orders.user_id = users.id ORDER BY created_at DESC').all();
  res.json({ orders });
});

module.exports = router;
EOF

echo "写入文件: backend/src/server.js"
cat > backend/src/server.js <<'EOF'
const express = require('express');
const cors = require('cors');
const bodyParser = require('express').json;
const db = require('./db');

const authRoutes = require('./routes/auth');
const itemsRoutes = require('./routes/items');
const cartRoutes = require('./routes/cart');
const ordersRoutes = require('./routes/orders');
const { authMiddleware } = require('./middleware/auth');

const app = express();
app.use(cors());
app.use(bodyParser());

// public api
app.use('/api/auth', authRoutes);
app.use('/api/items', itemsRoutes);

// protected
app.use('/api/cart', authMiddleware, cartRoutes);
app.use('/api/orders', authMiddleware, ordersRoutes);

// merchant endpoints (demo)
app.use('/api/merchant', ordersRoutes);

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log('Backend listening on', port);
});
EOF

echo "写入文件: frontend/package.json"
cat > frontend/package.json <<'EOF'
{
  "name": "order-system-frontend",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview --port 5173"
  },
  "dependencies": {
    "axios": "^1.4.0",
    "vue": "^3.3.4"
  },
  "devDependencies": {
    "vite": "^5.2.0"
  }
}
EOF

echo "写入文件: frontend/Dockerfile"
cat > frontend/Dockerfile <<'EOF'
FROM node:18-slim
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev"]
EOF

echo "写入文件: frontend/index.html"
cat > frontend/index.html <<'EOF'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>点餐系统 Demo</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.js"></script>
  </body>
</html>
EOF

echo "写入文件: frontend/src/main.js"
cat > frontend/src/main.js <<'EOF'
import { createApp } from 'vue';
import App from './App.vue';

createApp(App).mount('#app');
EOF

echo "写入文件: frontend/src/api.js"
cat > frontend/src/api.js <<'EOF'
import axios from 'axios';
const apiBase = import.meta.env.VITE_API_BASE || 'http://localhost:3000/api';
const api = axios.create({ baseURL: apiBase });

export function setToken(token) {
  if (token) api.defaults.headers.common['Authorization'] = 'Bearer ' + token;
  else delete api.defaults.headers.common['Authorization'];
}

export default api;
EOF

echo "写入文件: frontend/src/App.vue"
cat > frontend/src/App.vue <<'EOF'
<template>
  <div style="max-width:900px;margin:0 auto;padding:20px;">
    <h1>点餐系统 Demo</h1>
    <div style="margin-bottom:12px;">
      <template v-if="!user">
        <input v-model="phone" placeholder="手机号" />
        <input v-model="password" type="password" placeholder="密码" />
        <button @click="login">登录</button>
        <button @click="register">注册</button>
      </template>
      <template v-else>
        欢迎，{{ user.name }} （{{ user.phone }}） <button @click="logout">登出</button>
      </template>
    </div>

    <div style="display:flex;gap:20px;">
      <div style="flex:1;">
        <ItemList @added="onAdded" />
      </div>
      <div style="width:320px;">
        <Cart :user="user" @checked="onChecked" />
      </div>
    </div>

    <div style="margin-top:20px;">
      <h3>我的订单</h3>
      <Orders :user="user" />
    </div>
  </div>
</template>

<script>
import api, { setToken } from './api';
import ItemList from './components/ItemList.vue';
import Cart from './components/Cart.vue';
import Orders from './components/Orders.vue';

export default {
  components: { ItemList, Cart, Orders },
  data() {
    return {
      user: null,
      phone: '',
      password: ''
    };
  },
  mounted() {
    const raw = localStorage.getItem('user');
    const token = localStorage.getItem('token');
    if (raw && token) {
      this.user = JSON.parse(raw);
      setToken(token);
    }
  },
  methods: {
    async login() {
      try {
        const r = await api.post('/auth/login', { phone: this.phone, password: this.password });
        localStorage.setItem('token', r.data.token);
        localStorage.setItem('user', JSON.stringify(r.data.user));
        setToken(r.data.token);
        this.user = r.data.user;
      } catch (e) {
        alert('登录失败：' + (e.response?.data?.error || e.message));
      }
    },
    async register() {
      try {
        const r = await api.post('/auth/register', { name: this.phone, phone: this.phone, password: this.password });
        localStorage.setItem('token', r.data.token);
        localStorage.setItem('user', JSON.stringify(r.data.user));
        setToken(r.data.token);
        this.user = r.data.user;
      } catch (e) {
        alert('注册失败：' + (e.response?.data?.error || e.message));
      }
    },
    logout() {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      setToken(null);
      this.user = null;
    },
    onAdded() {
      // 可用于刷新 cart
    },
    onChecked() {
      // 结算后刷新订单
    }
  }
};
</script>
EOF

echo "写入文件: frontend/src/components/ItemList.vue"
cat > frontend/src/components/ItemList.vue <<'EOF'
<template>
  <div>
    <h3>菜品列表</h3>
    <div v-if="items.length === 0">加载中...</div>
    <div v-for="it in items" :key="it.id" style="border-bottom:1px solid #eee;padding:8px 0;">
      <div style="display:flex;justify-content:space-between;">
        <div>
          <strong>{{ it.name }}</strong>
          <div style="color:#666">{{ it.description }}</div>
        </div>
        <div style="text-align:right;">
          <div style="font-weight:600">{{ (it.price_cents/100).toFixed(2) }} 元</div>
          <button @click="add(it.id)" style="margin-top:8px;">加入购物车</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api';
export default {
  data() {
    return { items: [] };
  },
  async mounted() {
    const r = await api.get('/items');
    this.items = r.data.items;
  },
  methods: {
    async add(itemId) {
      const token = localStorage.getItem('token');
      if (!token) {
        alert('请先登录');
        return;
      }
      try {
        await api.post('/cart', { item_id: itemId, qty: 1 });
        alert('已加入购物车');
        this.$emit('added');
      } catch (e) {
        alert('加入失败：' + (e.response?.data?.error || e.message));
      }
    }
  }
};
</script>
EOF

echo "写入文件: frontend/src/components/Cart.vue"
cat > frontend/src/components/Cart.vue <<'EOF'
<template>
  <div>
    <h3>购物车</h3>
    <div v-if="!user">请先登录以使用购物车</div>
    <div v-else>
      <div v-if="cart.length === 0">购物车为空</div>
      <div v-for="c in cart" :key="c.cart_id" style="border-bottom:1px dashed #ddd;padding:6px 0;">
        <div style="display:flex;justify-content:space-between;">
          <div>{{ c.name }} x {{ c.qty }}</div>
          <div>{{ (c.price_cents/100 * c.qty).toFixed(2) }} 元</div>
        </div>
      </div>
      <div style="margin-top:8px;">
        <button @click="checkout" :disabled="cart.length===0">去结算（模拟支付）</button>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api';
export default {
  props: ['user'],
  data() {
    return { cart: [] };
  },
  watch: {
    user: { immediate: true, handler() { this.load(); } }
  },
  methods: {
    async load() {
      if (!this.user) { this.cart = []; return; }
      const r = await api.get('/cart');
      this.cart = r.data.cart;
    },
    async checkout() {
      if (!confirm('模拟支付并创建订单？')) return;
      try {
        await api.post('/orders/checkout');
        alert('下单并标记为已支付（模拟）');
        this.load();
        this.$emit('checked');
      } catch (e) {
        alert('结算失败：' + (e.response?.data?.error || e.message));
      }
    }
  }
};
</script>
EOF

echo "写入文件: frontend/src/components/Orders.vue"
cat > frontend/src/components/Orders.vue <<'EOF'
<template>
  <div>
    <div v-if="!user">请先登录查看订单</div>
    <div v-else>
      <div v-if="orders.length===0">暂无订单</div>
      <div v-for="o in orders" :key="o.id" style="border:1px solid #eee;padding:8px;margin-bottom:8px;">
        <div>订单 #{{ o.id }} | 总价：{{ (o.total_cents/100).toFixed(2) }} 元 | 状态：{{ o.status }}</div>
        <div style="color:#666">下单时间：{{ o.created_at }}</div>
      </div>
    </div>
  </div>
</template>

<script>
import api from '../api';
export default {
  props: ['user'],
  data() { return { orders: [] }; },
  watch: {
    user: { immediate: true, handler() { this.load(); } }
  },
  methods: {
    async load() {
      if (!this.user) { this.orders = []; return; }
      const r = await api.get('/orders');
      this.orders = r.data.orders;
    }
  }
};
</script>
EOF

echo "写入文件: .gitignore"
cat > .gitignore <<'EOF'
node_modules
backend/data
order-system.zip
EOF

echo "初始化完成，开始打包 zip ..."
cd ..
if [ -f "$ZIP_NAME" ]; then
  rm -f "$ZIP_NAME"
fi
zip -r "$ZIP_NAME" "$ROOT_DIR" > /dev/null

echo "打包完成：$(pwd)/$ZIP_NAME"
echo "解压并运行："
echo "  unzip $ZIP_NAME"
echo "  cd $ROOT_DIR"
echo "如要使用 Docker，一键运行： docker-compose up --build"
echo "脚本结束。"
EOF

运行脚本后（示例）
- 生成 order-system.zip，把它下载到本地或上传到任何你想要的位置。
- 若需要，我可以把 zip 内容逐文件贴出（但脚本已包含全部文件并会写出），或者我可以把项目推送到你指定的 GitHub 仓库（你需提供仓库地址与权限说明）。

还需要我做什么？
- 帮你把仓库初始化并生成 README 更详尽的开发与部署说明（CI/CD）？
- 将项目改成 Postgres、改用 React、或添加商家后台与权限控制？
请告诉我下一步。# -
