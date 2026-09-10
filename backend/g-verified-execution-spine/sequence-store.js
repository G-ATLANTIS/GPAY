'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { sha256 } = require('../g-bank-live-v1/canonical');

// Monotonic per-stream sequence guard. A "stream" is an (actor, capability)
// pair. A request carries `expected_sequence`; the spine accepts it only if it
// is strictly greater than the last committed sequence for that stream. This
// rejects stale / out-of-order / rolled-back state (STALE_STATE_REJECTED) and
// makes replays of an old, lower-numbered request non-viable.
//
// The committed sequence advances ONLY after a verified success commit.

class SequenceStore {
  constructor(rootDir) {
    this.rootDir = path.resolve(rootDir);
    fs.mkdirSync(this.rootDir, { recursive: true, mode: 0o700 });
  }

  _file(stream) {
    return path.join(this.rootDir, `${sha256(stream)}.seq.json`);
  }

  current(stream) {
    try {
      const rec = JSON.parse(fs.readFileSync(this._file(stream), 'utf8'));
      return Number.isSafeInteger(rec.sequence) ? rec.sequence : 0;
    } catch (err) {
      if (err.code === 'ENOENT') return 0;
      throw err;
    }
  }

  // Returns { ok, current, reason }. Does not mutate.
  check(stream, expectedSequence) {
    const cur = this.current(stream);
    if (!Number.isSafeInteger(expectedSequence) || expectedSequence <= 0) {
      return { ok: false, current: cur, reason: 'sequence_not_positive_integer' };
    }
    if (expectedSequence <= cur) {
      return { ok: false, current: cur, reason: 'sequence_not_monotonic' };
    }
    return { ok: true, current: cur, reason: null };
  }

  // Advance the committed sequence. Refuses to move backwards.
  commit(stream, sequence) {
    const cur = this.current(stream);
    if (sequence <= cur) throw new Error('sequence_commit_not_monotonic');
    const file = this._file(stream);
    const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
    fs.writeFileSync(
      tmp,
      JSON.stringify({ stream_sha256: sha256(stream), sequence, updated_at: new Date().toISOString() }, null, 2) + '\n',
      { flag: 'w', mode: 0o600 },
    );
    fs.renameSync(tmp, file);
    return sequence;
  }
}

module.exports = { SequenceStore };
