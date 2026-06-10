import { useEffect, useMemo, useState } from 'react'
import './App.css'

type Section = 'reading' | 'listening'

// answers["reading"] = { "1": "A", "2": "B" } — only filled entries are kept
type Answers = Record<Section, Record<string, string>>

type ScoreRow = {
  q: number
  key: string // correct answer
  yours: string // your answer ('' if blank)
  ok: boolean
}
type ScoreResult = {
  total: number // number of scored questions (key non-null)
  correct: number
  rows: ScoreRow[]
}

const STORAGE_KEY = 'test-answers'
const DEFAULT_COUNT = 100
const SECTIONS: Section[] = ['reading', 'listening']
// first question number per section (Reading is numbered 101+)
const START: Record<Section, number> = { reading: 101, listening: 1 }

// Shift reading answers saved under old 1-based numbers up to the new start
// (101+). Keys already >= START.reading are left untouched, so it's safe to
// run repeatedly.
function migrateReading(reading: Record<string, string>): Record<string, string> {
  const offset = START.reading - 1
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(reading)) {
    const n = Number(k)
    out[String(Number.isFinite(n) && n < START.reading ? n + offset : n || k)] = v
  }
  return out
}

function loadAnswers(): Answers {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const p = JSON.parse(raw)
      return {
        reading: migrateReading(p.reading ?? {}),
        // old data was saved under "speaking" before the rename
        listening: p.listening ?? p.speaking ?? {},
      }
    }
  } catch {
    // ignore corrupt storage
  }
  return { reading: {}, listening: {} }
}

// normalize for comparison: trim + lowercase
const norm = (v: unknown) => String(v ?? '').trim().toLowerCase()

function App() {
  const [answers, setAnswers] = useState<Answers>(loadAnswers)
  const [counts, setCounts] = useState<Record<Section, number>>({
    reading: DEFAULT_COUNT,
    listening: DEFAULT_COUNT,
  })
  const [saved, setSaved] = useState(false)

  // answer-key text pasted per section + computed result / parse error
  const [keyText, setKeyText] = useState<Record<Section, string>>({
    reading: '',
    listening: '',
  })
  const [results, setResults] = useState<Record<Section, ScoreResult | null>>({
    reading: null,
    listening: null,
  })
  const [errors, setErrors] = useState<Record<Section, string>>({
    reading: '',
    listening: '',
  })

  // Auto-save answers on every change (debounced) -> browser localStorage
  useEffect(() => {
    const id = setTimeout(() => {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(answers))
      setSaved(true)
      setTimeout(() => setSaved(false), 1200)
    }, 300)
    return () => clearTimeout(id)
  }, [answers])

  function setAnswer(section: Section, num: number, value: string) {
    setAnswers((prev) => {
      const next = { ...prev, [section]: { ...prev[section] } }
      const v = value.trim()
      if (v) next[section][String(num)] = v
      else delete next[section][String(num)] // empty = not stored
      return next
    })
  }

  // JSON output keeps only filled answers, sorted by question number
  const output = useMemo(() => {
    const sortNumeric = (obj: Record<string, string>) =>
      Object.fromEntries(
        Object.entries(obj).sort((a, b) => Number(a[0]) - Number(b[0])),
      )
    return {
      reading: sortNumeric(answers.reading),
      listening: sortNumeric(answers.listening),
    }
  }, [answers])

  const json = JSON.stringify(output, null, 2)

  function copyJson() {
    navigator.clipboard.writeText(json)
  }

  function downloadJson() {
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'answers.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  function clearAll() {
    if (!confirm('Clear all saved answers?')) return
    setAnswers({ reading: {}, listening: {} })
  }

  // Score one section against a pasted answer key (JSON: { "1": "a", "2": "B" })
  // Only questions whose key value is non-null/non-empty are scored.
  function scoreSection(section: Section) {
    setErrors((e) => ({ ...e, [section]: '' }))
    let key: Record<string, unknown>
    try {
      key = JSON.parse(keyText[section])
      if (typeof key !== 'object' || key === null || Array.isArray(key))
        throw new Error('not an object')
    } catch {
      setResults((r) => ({ ...r, [section]: null }))
      setErrors((e) => ({
        ...e,
        [section]: 'Invalid JSON. Use quotes, e.g. {"1": "a", "2": "B"}',
      }))
      return
    }

    const rows: ScoreRow[] = []
    let correct = 0
    for (const [q, raw] of Object.entries(key)) {
      // skip questions with no key answer (null / empty)
      if (raw === null || raw === undefined || norm(raw) === '') continue
      const yours = answers[section][q] ?? ''
      const ok = norm(raw) === norm(yours)
      if (ok) correct++
      rows.push({ q: Number(q), key: String(raw), yours, ok })
    }
    rows.sort((a, b) => a.q - b.q)
    setResults((r) => ({
      ...r,
      [section]: { total: rows.length, correct, rows },
    }))
  }

  return (
    <div className="app">
      <header>
        <h1>Test Answer Sheet</h1>
        <span className={`save-badge ${saved ? 'show' : ''}`}>✓ Saved</span>
      </header>

      <div className="sections">
        {SECTIONS.map((section) => (
          <section key={section} className="panel">
            <div className="panel-head">
              <h2>{section === 'reading' ? 'Reading' : 'Listening'}</h2>
              <div className="count-ctrl">
                <button
                  onClick={() =>
                    setCounts((c) => ({
                      ...c,
                      [section]: Math.max(1, c[section] - 1),
                    }))
                  }
                >
                  −
                </button>
                <span>{counts[section]} questions</span>
                <button
                  onClick={() =>
                    setCounts((c) => ({ ...c, [section]: c[section] + 1 }))
                  }
                >
                  +
                </button>
              </div>
            </div>

            <div className="grid">
              {Array.from({ length: counts[section] }, (_, i) => {
                const num = START[section] + i
                return (
                  <label key={num} className="qrow">
                    <span className="qnum">{num}.</span>
                    <input
                      id={`${section}-${num}`}
                      type="text"
                      value={answers[section][String(num)] ?? ''}
                      onChange={(e) => setAnswer(section, num, e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault()
                          const next = document.getElementById(
                            `${section}-${num + 1}`,
                          )
                          ;(next as HTMLInputElement | null)?.focus()
                        }
                      }}
                      placeholder="—"
                    />
                  </label>
                )
              })}
            </div>

            {/* Scoring */}
            <div className="score-box">
              <h3>Score {section === 'reading' ? 'Reading' : 'Listening'}</h3>
              <textarea
                value={keyText[section]}
                onChange={(e) =>
                  setKeyText((k) => ({ ...k, [section]: e.target.value }))
                }
                placeholder={'Paste answer key JSON, e.g.\n{"1": "a", "2": "B", "3": "C"}'}
                rows={4}
              />
              {errors[section] && (
                <p className="score-error">{errors[section]}</p>
              )}
              <button onClick={() => scoreSection(section)}>Score</button>

              {results[section] && (
                <div className="score-result">
                  <p className="score-headline">
                    {results[section]!.correct} / {results[section]!.total}
                    {results[section]!.total > 0 && (
                      <span className="pct">
                        {' '}
                        (
                        {Math.round(
                          (results[section]!.correct /
                            results[section]!.total) *
                            100,
                        )}
                        %)
                      </span>
                    )}
                  </p>
                  <ul className="score-rows">
                    {results[section]!.rows.map((r) => (
                      <li key={r.q} className={r.ok ? 'ok' : 'bad'}>
                        <span>{r.ok ? '✓' : '✗'}</span> Q{r.q}: you=
                        <b>{r.yours || '—'}</b> key=<b>{r.key}</b>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </section>
        ))}
      </div>

      <section className="output">
        <div className="output-head">
          <h2>Your Answers (JSON)</h2>
          <div className="actions">
            <button onClick={copyJson}>Copy</button>
            <button onClick={downloadJson}>Download</button>
            <button className="danger" onClick={clearAll}>
              Clear
            </button>
          </div>
        </div>
        <pre>{json}</pre>
      </section>
    </div>
  )
}

export default App
