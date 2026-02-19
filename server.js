import "dotenv/config";
import express from "express";
import cors from "cors";
import { promises as fs } from "node:fs";
import path from "node:path";
import { google } from "googleapis";

const app = express();
const port = Number(process.env.PORT || 8787);
const minDurationMinutes = Number(process.env.MIN_DURATION_MINUTES || 8);

const SECTION_WEIGHTS = {
  Numerical: 0.3,
  Verbal: 0.3,
  Logical: 0.4
};

const COMPETENCY_META = {
  fb: { label: "F&B Knowledge", weight: 0.25, minRatio: 0.5 },
  systems: { label: "Systems Design", weight: 0.45, minRatio: 0.6 },
  execution: { label: "Execution Ownership", weight: 0.3, minRatio: 0.5 }
};

const PASS_MODEL = {
  label: "Management (F&B Systems)",
  rawPass: 15,
  weightedPass: 70
};

const QUESTION_KEY = [
  { id: 1, section: "Numerical", competency: "fb", answer: "C" },
  { id: 2, section: "Numerical", competency: "fb", answer: "B" },
  { id: 3, section: "Numerical", competency: "systems", answer: "C" },
  { id: 4, section: "Numerical", competency: "fb", answer: "B" },
  { id: 5, section: "Numerical", competency: "execution", answer: "C" },
  { id: 6, section: "Numerical", competency: "fb", answer: "B" },
  { id: 7, section: "Numerical", competency: "execution", answer: "B" },
  { id: 8, section: "Numerical", competency: "fb", answer: "D" },

  { id: 9, section: "Verbal", competency: "execution", answer: "B" },
  { id: 10, section: "Verbal", competency: "fb", answer: "B" },
  { id: 11, section: "Verbal", competency: "systems", answer: "B" },
  { id: 12, section: "Verbal", competency: "systems", answer: "A" },
  { id: 13, section: "Verbal", competency: "execution", answer: "B" },
  { id: 14, section: "Verbal", competency: "systems", answer: "C" },
  { id: 15, section: "Verbal", competency: "fb", answer: "C" },
  { id: 16, section: "Verbal", competency: "execution", answer: "A" },

  { id: 17, section: "Logical", competency: "systems", answer: "B" },
  { id: 18, section: "Logical", competency: "execution", answer: "B" },
  { id: 19, section: "Logical", competency: "systems", answer: "D" },
  { id: 20, section: "Logical", competency: "execution", answer: "B" },
  { id: 21, section: "Logical", competency: "fb", answer: "B" },
  { id: 22, section: "Logical", competency: "systems", answer: "B" },
  { id: 23, section: "Logical", competency: "systems", answer: "C" },
  { id: 24, section: "Logical", competency: "execution", answer: "B" }
];

app.use(
  cors({
    origin: (origin, cb) => {
      const allowed = allowedOrigins();
      if (!origin || allowed.length === 0 || allowed.includes(origin)) {
        cb(null, true);
        return;
      }
      cb(new Error("Origin not allowed"));
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "x-api-key"]
  })
);

app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "restaurant-gma-backend" });
});

app.post("/api/submissions", async (req, res) => {
  try {
    enforceSubmissionAccess(req);
    const submission = validateSubmission(req.body);
    const scored = scoreAnswers(submission.answers, submission.durationMinutes);

    const record = {
      submissionId: createSubmissionId(),
      receivedAt: new Date().toISOString(),
      ...submission,
      scored
    };

    await appendSubmission(record);

    const emailed = await trySendSubmissionEmail(record);

    res.json({
      ok: true,
      submissionId: record.submissionId,
      emailed,
      scored
    });
  } catch (error) {
    const status = error?.statusCode || 500;
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(status).json({ ok: false, error: message });
  }
});

app.get("/api/submissions", async (req, res) => {
  try {
    requireApiKey(req);
    const limit = Math.min(Number(req.query.limit || 50), 200);
    const rows = await readSubmissions(limit);
    res.json({ ok: true, count: rows.length, rows });
  } catch (error) {
    const status = error?.statusCode || 500;
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(status).json({ ok: false, error: message });
  }
});

app.post("/api/feedback/email", async (req, res) => {
  try {
    enforceSubmissionAccess(req);
    const feedback = validateFeedback(req.body);

    if (!canSendEmail()) {
      return res.status(400).json({ ok: false, error: "Email settings are not configured." });
    }

    const subject = `GMA Feedback - ${feedback.candidateName}`;
    const body = [
      `Candidate: ${feedback.candidateName}`,
      `Candidate Email: ${feedback.candidateEmail || "N/A"}`,
      `Role: ${feedback.roleLabel || PASS_MODEL.label}`,
      `Submitted At: ${feedback.submittedAt || "N/A"}`,
      "",
      "Feedback:",
      feedback.feedback
    ].join("\n");

    const messageId = await sendViaGmailApi({
      from: required("EMAIL_FROM"),
      to: required("EMAIL_TO"),
      cc: String(process.env.EMAIL_CC || "").trim(),
      subject,
      body
    });

    res.json({ ok: true, messageId });
  } catch (error) {
    const status = error?.statusCode || 500;
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(status).json({ ok: false, error: message });
  }
});

function allowedOrigins() {
  return String(process.env.ALLOWED_ORIGIN || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function enforceSubmissionAccess(req) {
  const expected = String(process.env.API_KEY || "").trim();
  const received = String(req.headers["x-api-key"] || "").trim();

  if (expected && received === expected) return;

  const origin = String(req.headers.origin || "").trim();
  const allowed = allowedOrigins();
  if (allowed.length && origin && allowed.includes(origin)) return;

  if (!expected && allowed.length === 0) return;

  const err = new Error("Unauthorized submission origin or API key.");
  err.statusCode = 401;
  throw err;
}

function requireApiKey(req) {
  const expected = String(process.env.API_KEY || "").trim();
  if (!expected) {
    const err = new Error("API_KEY is required for this endpoint.");
    err.statusCode = 401;
    throw err;
  }

  const received = String(req.headers["x-api-key"] || "").trim();
  if (received !== expected) {
    const err = new Error("Unauthorized API key.");
    err.statusCode = 401;
    throw err;
  }
}

function validateSubmission(input) {
  const body = input || {};
  const candidateName = String(body.candidateName || "").trim();
  const candidateEmail = String(body.candidateEmail || "").trim();
  const submittedAt = String(body.submittedAt || "").trim() || new Date().toISOString();
  const durationMinutes = Number(body.durationMinutes || 0);
  const autoSubmitted = Boolean(body.autoSubmitted);
  const testVersion = String(body.testVersion || "mgmt-sys-v1").trim();

  if (!candidateName) throw new Error("Missing candidateName");
  if (!candidateEmail || !candidateEmail.includes("@")) throw new Error("Missing or invalid candidateEmail");

  const rawAnswers = body.answers || {};
  const answers = {};

  QUESTION_KEY.forEach((q) => {
    const candidate = String(rawAnswers[q.id] || rawAnswers[String(q.id)] || "").trim().toUpperCase();
    answers[q.id] = ["A", "B", "C", "D"].includes(candidate) ? candidate : "";
  });

  return {
    candidateName,
    candidateEmail,
    submittedAt,
    durationMinutes,
    autoSubmitted,
    testVersion,
    answers,
    roleLabel: PASS_MODEL.label
  };
}

function validateFeedback(input) {
  const body = input || {};
  const safe = {
    candidateName: String(body.candidateName || "").trim(),
    candidateEmail: String(body.candidateEmail || "").trim(),
    roleLabel: String(body.roleLabel || "").trim(),
    submittedAt: String(body.submittedAt || "").trim(),
    feedback: String(body.feedback || "").trim()
  };

  if (!safe.candidateName) throw new Error("Missing candidateName");
  if (!safe.feedback) throw new Error("Missing feedback");
  return safe;
}

function scoreAnswers(answers, durationMinutes) {
  let rawScore = 0;
  let answeredCount = 0;

  const sectionTotals = {
    Numerical: { correct: 0, total: 0 },
    Verbal: { correct: 0, total: 0 },
    Logical: { correct: 0, total: 0 }
  };

  const competencyTotals = {
    fb: { label: COMPETENCY_META.fb.label, correct: 0, total: 0 },
    systems: { label: COMPETENCY_META.systems.label, correct: 0, total: 0 },
    execution: { label: COMPETENCY_META.execution.label, correct: 0, total: 0 }
  };

  QUESTION_KEY.forEach((q) => {
    const picked = String(answers[q.id] || "").trim().toUpperCase();
    if (picked) answeredCount += 1;

    sectionTotals[q.section].total += 1;
    competencyTotals[q.competency].total += 1;

    if (picked && picked === q.answer) {
      rawScore += 1;
      sectionTotals[q.section].correct += 1;
      competencyTotals[q.competency].correct += 1;
    }
  });

  let sectionWeightedScore = 0;
  Object.keys(sectionTotals).forEach((section) => {
    const ratio = sectionTotals[section].correct / sectionTotals[section].total;
    sectionWeightedScore += ratio * SECTION_WEIGHTS[section] * 100;
  });

  let competencyWeightedScore = 0;
  Object.keys(competencyTotals).forEach((key) => {
    const ratio = competencyTotals[key].correct / competencyTotals[key].total;
    competencyWeightedScore += ratio * COMPETENCY_META[key].weight * 100;
  });

  const competencyPass = Object.keys(competencyTotals).every((key) => {
    const ratio = competencyTotals[key].correct / competencyTotals[key].total;
    return ratio >= COMPETENCY_META[key].minRatio;
  });

  const weightedScore = Math.round((sectionWeightedScore * 0.4) + (competencyWeightedScore * 0.6));
  const rapidFlag = Number(durationMinutes || 0) < minDurationMinutes;
  const pass = rawScore >= PASS_MODEL.rawPass && weightedScore >= PASS_MODEL.weightedPass && competencyPass;

  const recommendation = pass
    ? rapidFlag
      ? "Manual review (rapid completion)"
      : "Advance to structured interview"
    : "Do not advance";

  return {
    rawScore,
    answeredCount,
    weightedScore,
    sectionWeightedScore: Math.round(sectionWeightedScore),
    competencyWeightedScore: Math.round(competencyWeightedScore),
    sectionTotals,
    competencyTotals,
    competencyPass,
    rapidFlag,
    pass,
    recommendation
  };
}

function createSubmissionId() {
  return `gma_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

function storePath() {
  const configured = String(process.env.STORE_PATH || "").trim();
  if (configured) {
    return path.isAbsolute(configured) ? configured : path.join(process.cwd(), configured);
  }
  return path.join(process.cwd(), "data", "submissions.ndjson");
}

async function appendSubmission(record) {
  const target = storePath();
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.appendFile(target, `${JSON.stringify(record)}\n`, "utf8");
}

async function readSubmissions(limit) {
  const target = storePath();
  const raw = await fs.readFile(target, "utf8").catch(() => "");
  if (!raw.trim()) return [];

  const rows = raw
    .trim()
    .split("\n")
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  return rows.slice(-limit).reverse();
}

async function trySendSubmissionEmail(record) {
  if (!canSendEmail()) return false;

  const subject = `GMA Submission - ${record.candidateName} - ${record.scored.weightedScore}/100`;
  const body = formatSubmissionEmail(record);

  await sendViaGmailApi({
    from: required("EMAIL_FROM"),
    to: required("EMAIL_TO"),
    cc: String(process.env.EMAIL_CC || "").trim(),
    subject,
    body
  });

  return true;
}

function formatSubmissionEmail(record) {
  const s = record.scored;
  return [
    `Submission ID: ${record.submissionId}`,
    `Candidate: ${record.candidateName}`,
    `Candidate Email: ${record.candidateEmail}`,
    `Track: ${record.roleLabel}`,
    `Submitted At: ${record.submittedAt}`,
    `Duration Minutes: ${record.durationMinutes}`,
    `Answered Questions: ${s.answeredCount}/24`,
    `Raw Score: ${s.rawScore}/24`,
    `Weighted Score: ${s.weightedScore}/100`,
    `Recommendation: ${s.recommendation}`,
    `Competency Gate: ${s.competencyPass ? "Met" : "Missed"}`,
    `Rapid Completion Flag: ${s.rapidFlag ? "Yes" : "No"}`,
    "",
    `Section Scores: Numerical ${s.sectionTotals.Numerical.correct}/8, Verbal ${s.sectionTotals.Verbal.correct}/8, Logical ${s.sectionTotals.Logical.correct}/8`,
    `Competency Scores: F&B ${s.competencyTotals.fb.correct}/8, Systems ${s.competencyTotals.systems.correct}/8, Execution ${s.competencyTotals.execution.correct}/8`
  ].join("\n");
}

function canSendEmail() {
  return [
    "EMAIL_FROM",
    "EMAIL_TO",
    "GOOGLE_CLIENT_EMAIL",
    "GOOGLE_PRIVATE_KEY",
    "GOOGLE_IMPERSONATED_USER"
  ].every((key) => String(process.env[key] || "").trim());
}

async function sendViaGmailApi({ from, to, cc, subject, body }) {
  const auth = new google.auth.JWT({
    email: required("GOOGLE_CLIENT_EMAIL"),
    key: normalizePrivateKey(required("GOOGLE_PRIVATE_KEY")),
    scopes: ["https://www.googleapis.com/auth/gmail.send"],
    subject: required("GOOGLE_IMPERSONATED_USER")
  });

  const gmail = google.gmail({ version: "v1", auth });

  const rawMessage = [
    `From: ${from}`,
    `To: ${to}`,
    cc ? `Cc: ${cc}` : "",
    `Subject: ${subject}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    body
  ]
    .filter(Boolean)
    .join("\r\n");

  const encoded = Buffer.from(rawMessage)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  const response = await gmail.users.messages.send({
    userId: "me",
    requestBody: { raw: encoded }
  });

  return response.data.id;
}

function required(name) {
  const value = String(process.env[name] || "").trim();
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
}

function normalizePrivateKey(key) {
  return key.replace(/\\n/g, "\n");
}

app.use((err, _req, res, _next) => {
  const status = err?.statusCode || 500;
  const message = err instanceof Error ? err.message : "Unexpected error";
  res.status(status).json({ ok: false, error: message });
});

app.listen(port, () => {
  console.log(`Backend listening on http://localhost:${port}`);
});
