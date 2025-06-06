const express = require('express');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Utils para claves
function getPublicKey(base64PublicKey) {
  return crypto.createPublicKey({
    key: Buffer.from(base64PublicKey, 'base64'),
    format: 'der',
    type: 'spki',
  });
}

function getPrivateKey(base64PrivateKey) {
  return crypto.createPrivateKey({
    key: Buffer.from(base64PrivateKey, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
}

// Utils para acceder/modificar propiedades anidadas
function getValue(obj, path) {
  return path.split('.').reduce((acc, key) => acc?.[key], obj);
}

function setValue(obj, path, value) {
  const keys = path.split('.');
  const lastKey = keys.pop();
  const target = keys.reduce((acc, key) => {
    if (!acc[key]) acc[key] = {};
    return acc[key];
  }, obj);
  target[lastKey] = value;
}

// 🔐 POST /encrypt → { payload, llavePublica, campos }
app.post('/encrypt', (req, res) => {
  const { payload, llavePublica, campos } = req.body;
  if (!payload || !llavePublica || !Array.isArray(campos)) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }

  try {
    const publicKey = getPublicKey(llavePublica);
    const resultado = JSON.parse(JSON.stringify(payload)); // Clonar

    for (const campo of campos) {
      const valor = getValue(resultado, campo);
      if (valor == null || (typeof valor !== 'string' && typeof valor !== 'number')) continue;

      const encrypted = crypto.publicEncrypt(
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(String(valor))
      );
      setValue(resultado, campo, encrypted.toString('base64'));
    }

    res.json({ encryptedPayload: resultado });
  } catch (err) {
    res.status(500).json({ error: 'Error encriptando', detalle: err.message });
  }
});

// 🔓 POST /decrypt → { payload, llavePrivada, campos }
app.post('/decrypt', (req, res) => {
  const { payload, llavePrivada, campos } = req.body;
  if (!payload || !llavePrivada || !Array.isArray(campos)) {
    return res.status(400).json({ error: 'Faltan campos requeridos' });
  }

  try {
    const privateKey = getPrivateKey(llavePrivada);
    const resultado = JSON.parse(JSON.stringify(payload)); // Clonar

    for (const campo of campos) {
      const valor = getValue(resultado, campo);
      if (typeof valor !== 'string') continue;

      const decrypted = crypto.privateDecrypt(
        { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(valor, 'base64')
      );
      setValue(resultado, campo, decrypted.toString());
    }

    res.json({ decryptedPayload: resultado });
  } catch (err) {
    res.status(500).json({ error: 'Error desencriptando', detalle: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🔐 Servidor RSA listo en http://localhost:${PORT}`);
});