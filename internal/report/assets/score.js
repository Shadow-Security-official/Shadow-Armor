/*
 * Shadow-Armor scoring formula: JavaScript twin of internal/score/score.go.
 * The Go test TestParityWithJavaScript runs both on the same vectors.
 *
 *   weight(severity)  critical 10, high 5, medium 3, low 1, info 0
 *   evaluated         pass, fail, error (skip and waived excluded; error = failure)
 *   score             100 * sum(weight of passes) / sum(weight of evaluated), 1 decimal
 *   raw grade         A >= 90, B >= 80, C >= 65, D >= 50, else E
 *   caps              critical control failing or in error      -> at most D
 *                     an A that rests on runtime-only passes     -> B
 *                     (it rests on them when it would not stay A if every
 *                     runtime-only pass failed after a reboot)
 *   grade             worse of raw grade and caps; nothing evaluated -> "N/A"
 */
(function (root) {
  "use strict";
  var GRADES = ["A", "B", "C", "D", "E"];
  var THRESHOLDS = [["A", 90], ["B", 80], ["C", 65], ["D", 50], ["E", 0]];
  var DEFAULT_WEIGHTS = { critical: 10, high: 5, medium: 3, low: 1, info: 0 };

  function rank(g) {
    var i = GRADES.indexOf(g);
    return i < 0 ? GRADES.length : i;
  }
  function worse(a, b) { return rank(b) > rank(a) ? b : a; }
  function rawGrade(s) {
    for (var i = 0; i < THRESHOLDS.length; i++) if (s >= THRESHOLDS[i][1]) return THRESHOLDS[i][0];
    return "E";
  }
  function refs(map, std) {
    map = map || {};
    switch (std) {
      case "cis": return (map.cis || []).concat(map.cis_benchmark ? [map.cis_benchmark] : []);
      case "anssi": return map.anssi || [];
      case "nist": return map.nist || [];
      case "nist171": return map.nist171 || [];
      case "pci": return map.pci || [];
      case "stig": return map.stig || [];
    }
    return [];
  }
  function inLens(c, lens) {
    if (!lens || lens === "all") return true;
    return refs(c.map, lens).length > 0;
  }
  function one(controls, weights) {
    var s = { score: null, grade: "N/A", raw_grade: "N/A", caps: [], runtime_qualified: false, qualified_passes: 0,
      counts: { pass: 0, fail: 0, error: 0, skip: 0, waived: 0, runtime_only: 0, pending: 0, reboot_proven: 0, total: 0 } };
    var earned = 0, possible = 0, unproven = 0, critical = [], runtimeOnly = [], criticalUnproven = false;
    controls.forEach(function (c) {
      s.counts.total++;
      var w = weights[c.severity] || 0;
      switch (c.status) {
        case "pass":
          s.counts.pass++; earned += w; possible += w;
          if (c.qualifier === "runtime-only") {
            s.counts.runtime_only++; runtimeOnly.push(c.id); unproven += w;
            if (c.severity === "critical") criticalUnproven = true;
          }
          if (c.proof && c.proof.reboot === "proven") s.counts.reboot_proven++;
          break;
        case "fail":
        case "error":
          if (c.status === "fail") s.counts.fail++; else s.counts.error++;
          if (c.qualifier === "pending") s.counts.pending++;
          possible += w;
          if (c.severity === "critical") critical.push(c.id);
          break;
        case "skip": s.counts.skip++; break;
        case "waived": s.counts.waived++; break;
      }
    });
    s.qualified_passes = runtimeOnly.length;
    if (possible === 0) return s;
    // Scores are never negative, so Math.round matches Go's math.Round here.
    var v = Math.round((1000 * earned) / possible) / 10;
    s.score = v;
    s.raw_grade = rawGrade(v);
    s.grade = s.raw_grade;
    if (critical.length) { s.caps.push({ grade: "D", reason: "critical control failing", ids: critical }); s.grade = worse(s.grade, "D"); }
    if (s.grade === "A" && runtimeOnly.length) {
      // Worst case after a reboot: every runtime-only pass fails.
      var worst = rawGrade(Math.round((1000 * (earned - unproven)) / possible) / 10);
      if (critical.length || criticalUnproven) worst = worse(worst, "D");
      if (worst !== "A") {
        s.caps.push({ grade: "B", reason: "the A rests on passes whose persistence is not proven (runtime-only)", ids: runtimeOnly });
        s.grade = "B";
        s.runtime_qualified = true;
      }
    }
    return s;
  }

  function compute(controls, weights, lens) {
    weights = weights || DEFAULT_WEIGHTS;
    lens = lens || "all";
    var inl = controls.filter(function (c) { return inLens(c, lens); });
    var sum = one(inl, weights);
    sum.lens = lens;
    sum.pillars = [];
    for (var id = 1; id <= 12; id++) {
      var sub = inl.filter(function (c) { return c.pillar === id; });
      if (!sub.length) continue;
      var ps = one(sub, weights);
      sum.pillars.push({ id: id, score: ps.score, grade: ps.grade, counts: ps.counts });
    }
    return sum;
  }

  var api = { compute: compute, inLens: inLens, refs: refs, rawGrade: rawGrade, rank: rank, GRADES: GRADES, DEFAULT_WEIGHTS: DEFAULT_WEIGHTS };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ShadowArmorScore = api;
})(this);
