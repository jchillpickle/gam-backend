import "dotenv/config";
import express from "express";
import cors from "cors";
import { promises as fs } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { google } from "googleapis";

const app = express();
const port = Number(process.env.PORT || 8787);
const minDurationMinutes = Number(process.env.MIN_DURATION_MINUTES || 15);

const SECTION_ORDER = ["Numerical", "Verbal", "Logical"];

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
  rawPassRatio: 15 / 24,
  weightedPass: 70
};

const QUESTION_KEY = [
  { id: 1, section: "Numerical", competency: "fb", answer: "C" },
  { id: 2, section: "Numerical", competency: "fb", answer: "B" },
  { id: 3, section: "Numerical", competency: "systems", answer: "C" },
  { id: 4, section: "Numerical", competency: "execution", answer: "B" },
  { id: 5, section: "Numerical", competency: "fb", answer: "C" },
  { id: 6, section: "Numerical", competency: "systems", answer: "D" },
  { id: 7, section: "Numerical", competency: "execution", answer: "B" },
  { id: 8, section: "Numerical", competency: "fb", answer: "C" },
  { id: 9, section: "Numerical", competency: "systems", answer: "D" },
  { id: 10, section: "Numerical", competency: "execution", answer: "C" },
  { id: 11, section: "Numerical", competency: "fb", answer: "C" },
  { id: 12, section: "Numerical", competency: "systems", answer: "B" },
  { id: 13, section: "Numerical", competency: "execution", answer: "C" },
  { id: 14, section: "Numerical", competency: "fb", answer: "B" },
  { id: 15, section: "Numerical", competency: "systems", answer: "C" },
  { id: 16, section: "Numerical", competency: "execution", answer: "D" },
  { id: 17, section: "Numerical", competency: "systems", answer: "D" },

  { id: 18, section: "Verbal", competency: "execution", answer: "B" },
  { id: 19, section: "Verbal", competency: "fb", answer: "A" },
  { id: 20, section: "Verbal", competency: "systems", answer: "B" },
  { id: 21, section: "Verbal", competency: "execution", answer: "B" },
  { id: 22, section: "Verbal", competency: "fb", answer: "C" },
  { id: 23, section: "Verbal", competency: "systems", answer: "B" },
  { id: 24, section: "Verbal", competency: "execution", answer: "A" },
  { id: 25, section: "Verbal", competency: "fb", answer: "B" },
  { id: 26, section: "Verbal", competency: "systems", answer: "B" },
  { id: 27, section: "Verbal", competency: "execution", answer: "B" },
  { id: 28, section: "Verbal", competency: "fb", answer: "B" },
  { id: 29, section: "Verbal", competency: "systems", answer: "B" },
  { id: 30, section: "Verbal", competency: "execution", answer: "B" },
  { id: 31, section: "Verbal", competency: "fb", answer: "C" },
  { id: 32, section: "Verbal", competency: "fb", answer: "A" },
  { id: 33, section: "Verbal", competency: "systems", answer: "C" },
  { id: 34, section: "Verbal", competency: "execution", answer: "C" },

  { id: 35, section: "Logical", competency: "systems", answer: "B" },
  { id: 36, section: "Logical", competency: "execution", answer: "B" },
  { id: 37, section: "Logical", competency: "fb", answer: "B" },
  { id: 38, section: "Logical", competency: "systems", answer: "A" },
  { id: 39, section: "Logical", competency: "execution", answer: "B" },
  { id: 40, section: "Logical", competency: "systems", answer: "D" },
  { id: 41, section: "Logical", competency: "fb", answer: "B" },
  { id: 42, section: "Logical", competency: "systems", answer: "B" },
  { id: 43, section: "Logical", competency: "execution", answer: "B" },
  { id: 44, section: "Logical", competency: "systems", answer: "C" },
  { id: 45, section: "Logical", competency: "fb", answer: "B" },
  { id: 46, section: "Logical", competency: "systems", answer: "A" },
  { id: 47, section: "Logical", competency: "execution", answer: "B" },
  { id: 48, section: "Logical", competency: "systems", answer: "B" },
  { id: 49, section: "Logical", competency: "fb", answer: "A" },
  { id: 50, section: "Logical", competency: "execution", answer: "B" }
];

const TOTAL_QUESTIONS = QUESTION_KEY.length;
const RAW_PASS_MIN = Math.ceil(TOTAL_QUESTIONS * PASS_MODEL.rawPassRatio);
const MAX_LIMIT = 5000;
const MAX_NAME_LEN = 120;
const MAX_ROLE_LABEL_LEN = 120;
const MAX_TEST_VERSION_LEN = 40;
const MAX_FEEDBACK_LEN = 4000;
const MAX_DURATION_MINUTES = Number(process.env.MAX_DURATION_MINUTES || 240);
const REQUIRE_SUBMISSION_API_KEY = parseBoolEnv("REQUIRE_SUBMISSION_API_KEY", false);
const RATE_WINDOW_MS = Number(process.env.RATE_WINDOW_MS || 10 * 60 * 1000);
const RATE_MAX_SUBMISSIONS = Number(process.env.RATE_MAX_SUBMISSIONS || 30);
const RATE_MAX_FEEDBACK = Number(process.env.RATE_MAX_FEEDBACK || 20);
const RATE_MAX_ADMIN = Number(process.env.RATE_MAX_ADMIN || 120);
const RATE_BUCKETS = new Map();

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i;
const EMAIL_TYPO_MAP = {
  "gmial.com": "gmail.com",
  "gmil.com": "gmail.com",
  "gmail.co": "gmail.com",
  "yaho.com": "yahoo.com",
  "yahoo.co": "yahoo.com",
  "hotnail.com": "hotmail.com",
  "hotmial.com": "hotmail.com",
  "outlok.com": "outlook.com",
  "outlook.co": "outlook.com",
  "iclod.com": "icloud.com",
  "icloud.co": "icloud.com"
};
const COMMON_EMAIL_DOMAINS = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "icloud.com",
  "aol.com",
  "protonmail.com",
  "live.com",
  "msn.com",
  "larkinsrestaurants.com"
];

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

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
    enforceJsonRequest(req);
    enforceRateLimit(req, "submit", RATE_MAX_SUBMISSIONS, RATE_WINDOW_MS);
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
    enforceRateLimit(req, "admin-list", RATE_MAX_ADMIN, RATE_WINDOW_MS);
    requireApiKey(req);
    const limit = parseLimit(req.query.limit, 50);
    const testVersion = String(req.query.testVersion || "").trim();

    const rows = await readSubmissions(limit);
    const filtered = filterByTestVersion(rows, testVersion);

    res.json({ ok: true, count: filtered.length, rows: filtered });
  } catch (error) {
    const status = error?.statusCode || 500;
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(status).json({ ok: false, error: message });
  }
});

app.get("/api/admin/submissions/download", async (req, res) => {
  try {
    enforceRateLimit(req, "admin-download", RATE_MAX_ADMIN, RATE_WINDOW_MS);
    requireApiKey(req);
    const limit = parseLimit(req.query.limit, 500);
    const format = String(req.query.format || "csv").trim().toLowerCase();
    const testVersion = String(req.query.testVersion || "").trim();

    const rows = await readSubmissions(limit);
    const filtered = filterByTestVersion(rows, testVersion);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");

    if (format === "json") {
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="gma-submissions-${stamp}.json"`);
      res.send(JSON.stringify(filtered, null, 2));
      return;
    }

    const csv = buildSubmissionCsv(filtered);
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="gma-submissions-${stamp}.csv"`);
    res.send(csv);
  } catch (error) {
    const status = error?.statusCode || 500;
    const message = error instanceof Error ? error.message : "Unknown error";
    res.status(status).json({ ok: false, error: message });
  }
});

app.post("/api/feedback/email", async (req, res) => {
  try {
    enforceJsonRequest(req);
    enforceRateLimit(req, "feedback", RATE_MAX_FEEDBACK, RATE_WINDOW_MS);
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

  if (expected && timingSafeEqual(expected, received)) return;

  if (REQUIRE_SUBMISSION_API_KEY && expected) {
    fail(401, "Submission API key required.");
  }

  const origin = String(req.headers.origin || "").trim();
  const allowed = allowedOrigins();
  if (allowed.length && origin && allowed.includes(origin)) return;

  if (!expected && allowed.length === 0) return;

  fail(401, "Unauthorized submission origin or API key.");
}

function requireApiKey(req) {
  const expected = String(process.env.API_KEY || "").trim();
  if (!expected) {
    fail(401, "API_KEY is required for this endpoint.");
  }

  const received = String(req.headers["x-api-key"] || "").trim();
  if (!timingSafeEqual(expected, received)) {
    fail(401, "Unauthorized API key.");
  }
}

function validateSubmission(input) {
  const body = input || {};
  const candidateName = String(body.candidateName || "").trim();
  const candidateEmail = String(body.candidateEmail || "").trim().toLowerCase();
  const submittedAt = String(body.submittedAt || "").trim() || new Date().toISOString();
  const durationMinutes = Number(body.durationMinutes || 0);
  const autoSubmitted = Boolean(body.autoSubmitted);
  const testVersion = normalizeTestVersion(String(body.testVersion || "mgmt-sys-v2-50q").trim());

  if (!candidateName) fail(400, "Missing candidateName");
  if (candidateName.length > MAX_NAME_LEN) fail(400, "candidateName is too long");
  if (!isValidEmailFormat(candidateEmail)) fail(400, "Missing or invalid candidateEmail");
  if (candidateEmail.length > 254) fail(400, "candidateEmail is too long");
  if (!isFinite(durationMinutes) || durationMinutes < 0 || durationMinutes > MAX_DURATION_MINUTES) {
    fail(400, "Invalid durationMinutes");
  }
  if (!Number.isFinite(Date.parse(submittedAt))) fail(400, "Invalid submittedAt");

  const suggestion = suggestEmailCorrection(candidateEmail);
  if (suggestion) {
    fail(400, `Possible candidateEmail typo. Did you mean ${suggestion}?`);
  }

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

  if (!safe.candidateName) fail(400, "Missing candidateName");
  if (safe.candidateName.length > MAX_NAME_LEN) fail(400, "candidateName is too long");
  if (safe.candidateEmail && !isValidEmailFormat(safe.candidateEmail)) fail(400, "Invalid candidateEmail");
  if (safe.roleLabel.length > MAX_ROLE_LABEL_LEN) fail(400, "roleLabel is too long");
  if (!safe.feedback) fail(400, "Missing feedback");
  if (safe.feedback.length > MAX_FEEDBACK_LEN) fail(400, "feedback is too long");
  if (safe.submittedAt && !Number.isFinite(Date.parse(safe.submittedAt))) fail(400, "Invalid submittedAt");
  return safe;
}

function scoreAnswers(answers, durationMinutes) {
  let rawScore = 0;
  let answeredCount = 0;

  const sectionTotals = buildSectionTotals();
  const competencyTotals = buildCompetencyTotals();

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
    const ratio = sectionTotals[section].total > 0 ? sectionTotals[section].correct / sectionTotals[section].total : 0;
    sectionWeightedScore += ratio * SECTION_WEIGHTS[section] * 100;
  });

  let competencyWeightedScore = 0;
  Object.keys(competencyTotals).forEach((key) => {
    const ratio = competencyTotals[key].total > 0 ? competencyTotals[key].correct / competencyTotals[key].total : 0;
    competencyWeightedScore += ratio * COMPETENCY_META[key].weight * 100;
  });

  const competencyPass = Object.keys(competencyTotals).every((key) => {
    const ratio = competencyTotals[key].total > 0 ? competencyTotals[key].correct / competencyTotals[key].total : 0;
    return ratio >= COMPETENCY_META[key].minRatio;
  });

  const weightedScore = Math.round((sectionWeightedScore * 0.4) + (competencyWeightedScore * 0.6));
  const rapidFlag = Number(durationMinutes || 0) < minDurationMinutes;
  const pass = rawScore >= RAW_PASS_MIN && weightedScore >= PASS_MODEL.weightedPass && competencyPass;

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

function buildSectionTotals() {
  const totals = {};
  SECTION_ORDER.forEach((section) => {
    totals[section] = { correct: 0, total: 0 };
  });
  return totals;
}

function buildCompetencyTotals() {
  const totals = {};
  Object.keys(COMPETENCY_META).forEach((key) => {
    totals[key] = { label: COMPETENCY_META[key].label, correct: 0, total: 0 };
  });
  return totals;
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

function filterByTestVersion(rows, testVersion) {
  if (!testVersion) return rows;
  return rows.filter((row) => String(row.testVersion || "").trim() === testVersion);
}

async function trySendSubmissionEmail(record) {
  if (!canSendEmail()) return false;

  const subject = `GMA Submission [${record.testVersion}] - ${record.candidateName} - ${record.scored.weightedScore}/100`;
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
  const sectionSummary = SECTION_ORDER.map((section) => {
    const row = s.sectionTotals[section] || { correct: 0, total: 0 };
    return `${section} ${row.correct}/${row.total}`;
  }).join(", ");

  const competencySummary = Object.keys(COMPETENCY_META).map((key) => {
    const row = s.competencyTotals[key] || { correct: 0, total: 0 };
    return `${COMPETENCY_META[key].label} ${row.correct}/${row.total}`;
  }).join(", ");

  return [
    `Submission ID: ${record.submissionId}`,
    `Candidate: ${record.candidateName}`,
    `Candidate Email: ${record.candidateEmail}`,
    `Track: ${record.roleLabel}`,
    `Test Version: ${record.testVersion}`,
    `Submitted At: ${record.submittedAt}`,
    `Duration Minutes: ${record.durationMinutes}`,
    `Answered Questions: ${s.answeredCount}/${TOTAL_QUESTIONS}`,
    `Raw Score: ${s.rawScore}/${TOTAL_QUESTIONS}`,
    `Raw Pass Minimum: ${RAW_PASS_MIN}/${TOTAL_QUESTIONS}`,
    `Weighted Score: ${s.weightedScore}/100`,
    `Recommendation: ${s.recommendation}`,
    `Competency Gate: ${s.competencyPass ? "Met" : "Missed"}`,
    `Rapid Completion Flag: ${s.rapidFlag ? "Yes" : "No"}`,
    "",
    `Section Scores: ${sectionSummary}`,
    `Competency Scores: ${competencySummary}`
  ].join("\n");
}

function buildSubmissionCsv(rows) {
  const headers = [
    "submissionId",
    "receivedAt",
    "submittedAt",
    "testVersion",
    "candidateName",
    "candidateEmail",
    "durationMinutes",
    "answeredCount",
    "rawScore",
    "totalQuestions",
    "rawPassMinimum",
    "weightedScore",
    "recommendation",
    "pass",
    "competencyPass",
    "rapidFlag",
    "numericalCorrect",
    "numericalTotal",
    "verbalCorrect",
    "verbalTotal",
    "logicalCorrect",
    "logicalTotal",
    "fbCorrect",
    "fbTotal",
    "systemsCorrect",
    "systemsTotal",
    "executionCorrect",
    "executionTotal"
  ];

  const lines = [headers.join(",")];

  rows.forEach((record) => {
    const s = record.scored || {};
    const sectionTotals = s.sectionTotals || {};
    const competencyTotals = s.competencyTotals || {};

    const row = [
      record.submissionId,
      record.receivedAt,
      record.submittedAt,
      record.testVersion,
      record.candidateName,
      record.candidateEmail,
      record.durationMinutes,
      s.answeredCount,
      s.rawScore,
      TOTAL_QUESTIONS,
      RAW_PASS_MIN,
      s.weightedScore,
      s.recommendation,
      s.pass,
      s.competencyPass,
      s.rapidFlag,
      sectionTotals.Numerical?.correct,
      sectionTotals.Numerical?.total,
      sectionTotals.Verbal?.correct,
      sectionTotals.Verbal?.total,
      sectionTotals.Logical?.correct,
      sectionTotals.Logical?.total,
      competencyTotals.fb?.correct,
      competencyTotals.fb?.total,
      competencyTotals.systems?.correct,
      competencyTotals.systems?.total,
      competencyTotals.execution?.correct,
      competencyTotals.execution?.total
    ];

    lines.push(row.map(csvEscape).join(","));
  });

  return lines.join("\n");
}

function csvEscape(value) {
  if (value === null || value === undefined) return "";
  let text = String(value);
  if (/^[=+\-@]/.test(text)) {
    text = `'${text}`;
  }
  if (/[",\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function parseLimit(value, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), MAX_LIMIT);
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
  if (!value) fail(500, `Missing required env var: ${name}`);
  return value;
}

function normalizePrivateKey(key) {
  return key.replace(/\\n/g, "\n");
}

function isValidEmailFormat(email) {
  return EMAIL_REGEX.test(String(email || "").trim().toLowerCase());
}

function suggestEmailCorrection(email) {
  const parts = String(email || "").trim().toLowerCase().split("@");
  if (parts.length !== 2) return "";

  const [local, domainRaw] = parts;
  const domain = domainRaw.toLowerCase();

  if (EMAIL_TYPO_MAP[domain]) {
    return `${local}@${EMAIL_TYPO_MAP[domain]}`;
  }

  if (COMMON_EMAIL_DOMAINS.includes(domain)) return "";

  const closest = findClosestKnownDomain(domain);
  if (!closest) return "";

  return `${local}@${closest}`;
}

function findClosestKnownDomain(domain) {
  let best = "";
  let bestDistance = Number.POSITIVE_INFINITY;

  COMMON_EMAIL_DOMAINS.forEach((candidate) => {
    const d = levenshtein(domain, candidate);
    if (d < bestDistance) {
      bestDistance = d;
      best = candidate;
    }
  });

  if (bestDistance <= 1) return best;
  if (bestDistance === 2 && Math.abs(domain.length - best.length) <= 1) return best;
  return "";
}

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i += 1) dp[i][0] = i;
  for (let j = 0; j <= n; j += 1) dp[0][j] = j;

  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }

  return dp[m][n];
}

function normalizeTestVersion(raw) {
  const safe = String(raw || "").trim().slice(0, MAX_TEST_VERSION_LEN);
  if (!safe) return "mgmt-sys-v2-50q";
  if (!/^[a-zA-Z0-9._-]+$/.test(safe)) {
    fail(400, "Invalid testVersion format");
  }
  return safe;
}

function enforceJsonRequest(req) {
  if (!req.is("application/json")) {
    fail(415, "Content-Type must be application/json");
  }
}

function parseBoolEnv(name, fallback) {
  const raw = String(process.env[name] || "").trim().toLowerCase();
  if (!raw) return fallback;
  if (["1", "true", "yes", "on"].includes(raw)) return true;
  if (["0", "false", "no", "off"].includes(raw)) return false;
  return fallback;
}

function timingSafeEqual(a, b) {
  const x = Buffer.from(String(a || ""), "utf8");
  const y = Buffer.from(String(b || ""), "utf8");
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

function getClientIp(req) {
  const fwd = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  if (fwd) return fwd;
  return String(req.ip || req.socket?.remoteAddress || "unknown");
}

function enforceRateLimit(req, bucket, maxRequests, windowMs) {
  const now = Date.now();
  const key = `${bucket}:${getClientIp(req)}`;
  const entry = RATE_BUCKETS.get(key);

  if (!entry || now - entry.windowStart >= windowMs) {
    RATE_BUCKETS.set(key, { windowStart: now, count: 1 });
    purgeOldRateBuckets(now, windowMs);
    return;
  }

  if (entry.count >= maxRequests) {
    fail(429, "Too many requests. Please try again later.");
  }

  entry.count += 1;
}

function purgeOldRateBuckets(now, windowMs) {
  for (const [key, entry] of RATE_BUCKETS.entries()) {
    if (now - entry.windowStart >= windowMs * 2) {
      RATE_BUCKETS.delete(key);
    }
  }
}

function fail(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  throw err;
}

app.use((err, _req, res, _next) => {
  const status = err?.statusCode || 500;
  const message = err instanceof Error ? err.message : "Unexpected error";
  res.status(status).json({ ok: false, error: message });
});

app.listen(port, () => {
  console.log(`Backend listening on http://localhost:${port}`);
});
