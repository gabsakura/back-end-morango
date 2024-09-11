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

  // Criar tabela de morangos
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
    user_id INTEGER,
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

  // Inserir itens de morango (upgrades)
   const stmt = db.prepare(`INSERT INTO strawberries (name, cost, multiplier) VALUES (?, ?, ?)`);
  
  stmt.run("Morangos Comuns", 10, 1, function (err) {
    if (err) {
      console.error('Erro ao inserir Morangos Comuns:', err);
    } else {
      console.log('Morangos Comuns inserido com ID:', this.lastID);
    }
  });
  
  stmt.run("Morangos Doces", 20, 2, function (err) {
    if (err) {
      console.error('Erro ao inserir Morangos Doces:', err);
    } else {
      console.log('Morangos Doces inserido com ID:', this.lastID);
    }
  });
  
  stmt.run("Morangos de Ouro", 50, 5, function (err) {
    if (err) {
      console.error('Erro ao inserir Morangos de Ouro:', err);
    } else {
      console.log('Morangos de Ouro inserido com ID:', this.lastID);
    }
  });
  
  stmt.run("Morangos Raros", 100, 10, function (err) {
    if (err) {
      console.error('Erro ao inserir Morangos Raros:', err);
    } else {
      console.log('Morangos Raros inserido com ID:', this.lastID);
    }
  });
  
  stmt.run("Morangos Lendários", 200, 20, function (err) {
    if (err) {
      console.error('Erro ao inserir Morangos Lendários:', err);
    } else {
      console.log('Morangos Lendários inserido com ID:', this.lastID);
    }
  });
  
  stmt.run("Morangos Celestiais", 500, 50, function (err) {
    if (err) {
      console.error('Erro ao inserir Morangos Celestiais:', err);
    } else {
      console.log('Morangos Celestiais inserido com ID:', this.lastID);
    }
  });
  
  stmt.finalize();
});

// Rota de registro de usuário
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  console.log("Dados de registro:", username, password);

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function (err) {
    if (err) {
      console.error("Erro ao registrar usuário:", err.message);
      return res.status(500).send("Erro ao registrar usuário.");
    }

    console.log("Usuário registrado com sucesso, ID:", this.lastID);

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

  if (!username || !password) {
    return res.status(400).send("Username e password são necessários.");
  }

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
    console.log("Nenhum token fornecido.");
    return res.status(403).send({ auth: false, message: 'Nenhum token fornecido.' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.log("Erro na verificação do token:", err);
      return res.status(500).send({ auth: false, message: 'Falha na autenticação do token.' });
    }

    req.userId = decoded.id;
    next();
  });
}

// Rota para obter informações do usuário
app.get('/profile', verifyToken, (req, res) => {
  db.get(`SELECT username FROM users WHERE id = ?`, [req.userId], (err, user) => {
    if (err || !user) {
      return res.status(500).send("Erro ao buscar informações do usuário.");
    }
    res.status(200).send({ username: user.username });
  });
});

// Rota para colher morango (equivalente a /morangos/click)
app.post('/harvest', verifyToken, (req, res) => {
  db.get(`SELECT strawberries, upgrades FROM user_progress WHERE user_id = ?`, [req.userId], (err, row) => {
    if (err || !row) {
      return res.status(500).send("Erro ao colher morangos.");
    }

    let upgrades = JSON.parse(row.upgrades);
    let totalMultiplier = upgrades.reduce((sum, upgrade) => sum + upgrade.multiplier, 0);
    let increment = totalMultiplier || 1; // Se não tiver upgrades, incrementa em 1

    const newCount = row.strawberries + increment;
    db.run(`UPDATE user_progress SET strawberries = ? WHERE user_id = ?`, [newCount, req.userId], function (err) {
      if (err) {
        return res.status(500).send("Erro ao atualizar morangos.");
      }
      res.status(200).send({ strawberries: newCount });
    });
  });
});

// Rota para comprar upgrade
app.post('/buy', verifyToken, (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(400).send("ID do upgrade é necessário.");
  }

  db.get(`SELECT * FROM strawberries WHERE id = ?`, [id], (err, strawberry) => {
    if (err || !strawberry) {
      return res.status(400).send("Upgrade não encontrado.");
    }

    db.get(`SELECT strawberries, upgrades FROM user_progress WHERE user_id = ?`, [req.userId], (err, progress) => {
      if (err || !progress) {
        return res.status(500).send("Erro ao buscar progresso do jogador.");
      }

      if (progress.strawberries < strawberry.cost) {
        return res.status(400).send("Morango insuficiente para comprar esse upgrade.");
      }

      const newStrawberries = progress.strawberries - strawberry.cost;
      let upgrades = JSON.parse(progress.upgrades);
      upgrades.push(strawberry);

      db.run(`UPDATE user_progress SET strawberries = ?, upgrades = ? WHERE user_id = ?`,
        [newStrawberries, JSON.stringify(upgrades), req.userId], function (err) {
          if (err) {
            return res.status(500).send("Erro ao atualizar progresso.");
          }
          res.status(200).send({ strawberries: newStrawberries, upgrades });
        });
    });
  });
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
