
import { createHash, randomInt, randomBytes, timingSafeEqual } from "node:crypto";
import nodemailer from "nodemailer";
import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getDatabase } from "firebase-admin/database";

const OTP_TTL_MS = 5 * 60 * 1000;
const RESEND_WAIT_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;

function getServices() {
  if (!process.env.GMAIL_USER ||
      !process.env.GMAIL_APP_PASSWORD ||
      !process.env.FIREBASE_DATABASE_URL ||
      !process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    throw new Error("Backend environment variables are incomplete");
  }

  if (!getApps().length) {
    const serviceAccount = JSON.parse(
      process.env.FIREBASE_SERVICE_ACCOUNT_JSON
    );

    initializeApp({
      credential: cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DATABASE_URL
    });
  }

  return {
    db: getDatabase(),
    mailer: nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
      }
    })
  };
}

function emailKey(email) {
  return createHash("sha256")
    .update(email.toLowerCase())
    .digest("hex");
}

function otpHash(email, code, salt) {
  return createHash("sha256")
    .update(`${email.toLowerCase()}|${code}|${salt}`)
    .digest("hex");
}

function sameHash(a, b) {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  return left.length === right.length &&
    timingSafeEqual(left, right);
}

function reply(res, status, body) {
  return res.status(status).json(body);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return reply(res, 405, { error: "Method not allowed" });
  }

  try {
    const { db, mailer } = getServices();
    const action = req.body?.action;
    const email = String(req.body?.email || "")
      .trim()
      .toLowerCase();

    if (email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return reply(res, 400, { error: "Alamat email tidak valid" });
    }

    const key = emailKey(email);
    const ref = db.ref(`privateOtpChallenges/${key}`);

    if (action === "send") {
      const purpose = req.body?.purpose;

      if (purpose !== "register") {
        return reply(res, 400, { error: "Tujuan OTP tidak valid" });
      }

      const snapshot = await ref.get();
      const old = snapshot.val();

      if (old?.lastSentAt &&
          Date.now() - old.lastSentAt < RESEND_WAIT_MS) {
        return reply(res, 429, {
          error: "Tunggu sebentar sebelum meminta OTP baru"
        });
      }

      const code = String(randomInt(0, 1000000)).padStart(6, "0");
      const salt = randomBytes(16).toString("hex");

      await ref.set({
        purpose: "register",
        codeHash: otpHash(email, code, salt),
        salt,
        expiresAt: Date.now() + OTP_TTL_MS,
        lastSentAt: Date.now(),
        attempts: 0,
        verified: false
      });

      try {
        await mailer.sendMail({
          from: `"FOCUS" <${process.env.GMAIL_USER}>`,
          to: email,
          subject: "Kode OTP Pendaftaran FOCUS",
          text:
            `Kode OTP pendaftaran FOCUS kamu adalah ${code}.\n\n` +
            "Kode berlaku selama 5 menit dan hanya dapat digunakan sekali. " +
            "Jangan berikan kode ini kepada siapa pun."
        });
      } catch (error) {
        await ref.remove();
        throw error;
      }

      return reply(res, 200, {
        success: true,
        message: "Jika pengiriman berhasil, OTP akan tiba di email tujuan."
      });
    }

    if (action === "verify") {
      const code = String(req.body?.code || "").trim();

      if (!/^\d{6}$/.test(code)) {
        return reply(res, 400, { error: "Kode OTP harus 6 digit" });
      }

      const snapshot = await ref.get();
      const challenge = snapshot.val();

      if (!challenge ||
          challenge.purpose !== "register" ||
          challenge.verified ||
          Date.now() > challenge.expiresAt) {
        return reply(res, 400, {
          error: "OTP tidak valid atau sudah kedaluwarsa"
        });
      }

      if (challenge.attempts >= MAX_ATTEMPTS) {
        await ref.remove();
        return reply(res, 429, {
          error: "Batas percobaan OTP tercapai. Minta kode baru."
        });
      }

      const valid = sameHash(
        challenge.codeHash,
        otpHash(email, code, challenge.salt)
      );

      if (!valid) {
        await ref.update({
          attempts: challenge.attempts + 1
        });

        return reply(res, 400, { error: "Kode OTP salah" });
      }

      const registrationToken = randomBytes(32).toString("hex");

      await ref.update({
        verified: true,
        codeHash: null,
        salt: null,
        registrationTokenHash: createHash("sha256")
          .update(registrationToken)
          .digest("hex"),
        tokenExpiresAt: Date.now() + 10 * 60 * 1000
      });

      return reply(res, 200, {
        success: true,
        registrationToken
      });
    }

    return reply(res, 400, { error: "Action tidak dikenal" });
  } catch (error) {
    console.error("OTP backend error:", error.message);
    return reply(res, 500, {
      error: "Layanan OTP sedang mengalami kendala"
    });
  }
}
