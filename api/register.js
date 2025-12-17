import bcrypt from 'bcryptjs';
import { db } from './db.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const hash = await bcrypt.hash(req.body.password, 10);

  await db.user.create({
    data: {
      username: req.body.username,
      password: hash,
      acier: 100,
      beton: 100,
      personnel: 10,
      essence: 50,
      energie: 100
    }
  });

  res.json({ ok: true });
}
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { db } from './db.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const user = await db.user.findUnique({
    where: { username: req.body.username }
  });

  if (!user) return res.status(401).json({ error: 'Utilisateur inconnu' });

  const valid = await bcrypt.compare(req.body.password, user.password);
  if (!valid) return res.status(401).json({ error: 'Mot de passe incorrect' });

  const token = jwt.sign(
    { id: user.id },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({ token });
}
import jwt from 'jsonwebtoken';

export function auth(req) {
  const header = req.headers.authorization;
  if (!header) throw new Error('Non autorisé');

  const token = header.split(' ')[1];
  return jwt.verify(token, process.env.JWT_SECRET);
}
import { auth } from './auth.js';
import { db } from './db.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const user = auth(req);
  const player = await db.user.findUnique({ where: { id: user.id } });

  if (player.personnel < 2 || player.essence < 10) {
    return res.status(400).json({ error: 'Ressources insuffisantes' });
  }

  await db.city.update({
    where: { name: req.body.city },
    data: { ownerId: user.id }
  });

  await db.user.update({
    where: { id: user.id },
    data: {
      personnel: player.personnel - 2,
      essence: player.essence - 10
    }
  });

  res.json({ ok: true });
}
import { auth } from './auth.js';
import { db } from './db.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const user = auth(req);
  const player = await db.user.findUnique({ where: { id: user.id } });

  if (player.personnel < 2 || player.essence < 10) {
    return res.status(400).json({ error: 'Ressources insuffisantes' });
  }

  await db.city.update({
    where: { name: req.body.city },
    data: { ownerId: user.id }
  });

  await db.user.update({
    where: { id: user.id },
    data: {
      personnel: player.personnel - 2,
      essence: player.essence - 10
    }
  });

  res.json({ ok: true });
}
import { PrismaClient } from '@prisma/client';
export const db = new PrismaClient();
