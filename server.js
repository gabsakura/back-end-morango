const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const crypto = require('crypto'); // Para gerar segredo aleatório

const app = express();
const port = 3000;

let SECRET_KEY = generateSecretKey(); // Gera um segredo inicial aleatório

app.use(bodyParser.json());
app.use(cors()); // Permitir todas as origens

// Função para gerar uma chave secreta aleatória
function generateSecretKey() {
  return crypto.randomBytes(64).toString('hex');
}

// Configurar o banco de dados SQLite
const db = new sqlite3.Database('./strawberry-clicker.db');
db.serialize(() => {
  // Criar tabela de usuários
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`, (err) => {
    if (err) {
      console.error('Erro ao criar a tabela users:', err);
    } else {
      console.log('Tabela users criada com sucesso');
    }
  });

  // Criar tabela de morangos (upgrades)
  db.run(`CREATE TABLE IF NOT EXISTS strawberries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    cost INTEGER,
    multiplier INTEGER
  )`, (err) => {
    if (err) {
      console.error('Erro ao criar a tabela strawberries:', err);
    } else {
      console.log('Tabela strawberries criada com sucesso');
    }
  });

  // Criar tabela de progresso do usuário
  db.run(`CREATE TABLE IF NOT EXISTS user_progress (
    user_id INTEGER PRIMARY KEY,
    strawberries INTEGER DEFAULT 0,
    upgrades TEXT DEFAULT '[]',
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`, (err) => {
    if (err) {
      console.error('Erro ao criar a tabela user_progress:', err);
    } else {
      console.log('Tabela user_progress criada com sucesso');
    }
  });

  // Verifica se já há upgrades no banco antes de adicionar
  db.get(`SELECT COUNT(*) as count FROM strawberries`, (err, row) => {
    if (err) {
      console.error('Erro ao verificar a tabela strawberries:', err);
    } else if (row.count === 0) {
      // Se a tabela estiver vazia, insere os upgrades
      const stmt = db.prepare(`INSERT INTO strawberries (name, cost, multiplier) VALUES (?, ?, ?)`);

      stmt.run("Morangos Comuns", 10, 1);
      stmt.run("Morangos Doces", 20, 2);
      stmt.run("Morangos de Ouro", 50, 5);
      stmt.run("Morangos Raros", 100, 10);
      stmt.run("Morangos Lendários", 200, 20);
      stmt.run("Morangos Celestiais", 500, 50);

      stmt.finalize();
      console.log('Upgrades inseridos com sucesso');
    } else {
      console.log('Os upgrades já estão presentes, não é necessário inserir novamente.');
    }
  });
});


// Rota de registro de usuário
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function (err) {
    if (err) {
      console.error("Erro ao registrar usuário:", err.message);
      return res.status(500).send("Erro ao registrar usuário.");
    }

    db.run(`INSERT INTO user_progress (user_id, strawberries, upgrades) VALUES (?, ?, ?)`, [this.lastID, 0, '[]'], function (err) {
      if (err) {
        console.error("Erro ao inicializar progresso do usuário:", err.message);
        return res.status(500).send("Erro ao inicializar progresso do usuário.");
      }
      res.status(201).send({ id: this.lastID });
    });
  });
});

// Rota de login de usuário
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) {
      return res.status(401).send("Login inválido.");
    }

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send("Login inválido.");
    }

    // Gera um novo segredo sempre que o usuário faz login
    SECRET_KEY = generateSecretKey();

    // Gerar o token JWT
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: 86400 }); // 24 horas
    res.status(200).send({ auth: true, token });
  });
});

// Middleware de autenticação JWT
function verifyToken(req, res, next) {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(403).send({ auth: false, message: 'Nenhum token fornecido.' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(500).send({ auth: false, message: 'Falha na autenticação do token.' });
    }

    req.userId = decoded.id;
    next();
  });
}

// Rota para colher morango (equivalente a /morangos/click)
app.post('/harvest', verifyToken, (req, res) => {
  db.get(`SELECT strawberries, upgrades FROM user_progress WHERE user_id = ?`, [req.userId], (err, row) => {
    if (err || !row) {
      return res.status(500).send("Erro ao colher morangos.");
    }

    let upgrades = JSON.parse(row.upgrades || '[]');
    let totalMultiplier = upgrades.reduce((sum, upgrade) => sum + (upgrade.multiplier || 0), 0);
    let increment = totalMultiplier > 0 ? totalMultiplier : 1; // Se não houver upgrades, incrementa em 1

    const newCount = row.strawberries + increment;
    db.run(`UPDATE user_progress SET strawberries = ? WHERE user_id = ?`, [newCount, req.userId], function (err) {
      if (err) {
        return res.status(500).send("Erro ao atualizar morangos.");
      }
      res.status(200).send({ strawberries: newCount });
    });
  });
});
// Rota para comprar upgrades
app.post('/buy', verifyToken, (req, res) => {
  const { id } = req.body;

  // Verifica se o ID do upgrade foi fornecido
  if (!id) {
    return res.status(400).send("ID do upgrade não fornecido.");
  }

  // Busca o upgrade pelo ID
  db.get(`SELECT * FROM strawberries WHERE id = ?`, [id], (err, upgrade) => {
    if (err || !upgrade) {
      return res.status(404).send("Upgrade não encontrado.");
    }

    // Busca o progresso do usuário
    db.get(`SELECT strawberries, upgrades FROM user_progress WHERE user_id = ?`, [req.userId], (err, row) => {
      if (err || !row) {
        return res.status(500).send("Erro ao buscar progresso do usuário.");
      }

      let strawberries = row.strawberries;
      let upgrades = JSON.parse(row.upgrades || '[]');

      // Verifica se o usuário tem morangos suficientes para comprar o upgrade
      if (strawberries < upgrade.cost) {
        return res.status(400).send("Morangos insuficientes para comprar o upgrade.");
      }

      // Atualiza a quantidade de morangos do usuário
      strawberries -= upgrade.cost;

      // Verifica se o upgrade já foi comprado
      const existingUpgrade = upgrades.find(u => u.id === id);
      if (existingUpgrade) {
        existingUpgrade.quantity += 1;
      } else {
        upgrades.push({ ...upgrade, quantity: 1 });
      }

      // Atualiza o banco de dados
      db.run(`UPDATE user_progress SET strawberries = ?, upgrades = ? WHERE user_id = ?`, [strawberries, JSON.stringify(upgrades), req.userId], (err) => {
        if (err) {
          return res.status(500).send("Erro ao atualizar progresso do usuário.");
        }

        res.status(200).send({ strawberries, upgrades: JSON.stringify(upgrades) });
      });
    });
  });
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
