import { useState } from "react";

const FRAMEWORKS = [
  { id: "nist-800-171-r2", name: "NIST 800-171", controls: 110, enforced: 94, partial: 11, gap: 5, score: 88.5 },
  { id: "hipaa", name: "HIPAA", controls: 54, enforced: 48, partial: 4, gap: 2, score: 92.1 },
  { id: "ferpa", name: "FERPA", controls: 28, enforced: 26, partial: 2, gap: 0, score: 96.4 },
];
const CONTROLS = [
  { id: "3.1.1", fam: "Access Control", title: "Limit system access to authorized users", st: "enforced", scps: 1, cedar: 1, config: 1 },
  { id: "3.1.2", fam: "Access Control", title: "Limit access to authorized transactions", st: "enforced", scps: 1, cedar: 1, config: 1 },
  { id: "3.1.3", fam: "Access Control", title: "Control flow of CUI", st: "enforced", scps: 2, cedar: 1, config: 2 },
  { id: "3.1.5", fam: "Access Control", title: "Employ least privilege", st: "enforced", scps: 2, cedar: 1, config: 1 },
  { id: "3.1.12", fam: "Access Control", title: "Monitor remote access", st: "waived", scps: 0, cedar: 1, config: 1, waiver: "W-2025-003" },
  { id: "3.4.1", fam: "Config Mgmt", title: "Baseline configurations", st: "enforced", scps: 1, cedar: 0, config: 1 },
  { id: "3.4.5", fam: "Config Mgmt", title: "Physical/logical access restrictions", st: "partial", scps: 1, cedar: 1, config: 0 },
  { id: "3.5.3", fam: "ID & Auth", title: "MFA for privileged accounts", st: "enforced", scps: 1, cedar: 1, config: 1 },
  { id: "3.13.1", fam: "Sys & Comms", title: "Protect communications at boundaries", st: "enforced", scps: 1, cedar: 1, config: 2 },
  { id: "3.13.11", fam: "Sys & Comms", title: "FIPS-validated cryptography", st: "enforced", scps: 2, cedar: 1, config: 2 },
  { id: "3.14.1", fam: "Integrity", title: "Identify/correct system flaws", st: "gap", scps: 0, cedar: 0, config: 1 },
  { id: "3.14.6", fam: "Integrity", title: "Monitor org systems", st: "partial", scps: 0, cedar: 1, config: 1 },
];
const ENVS = [
  { name: "genomics-hipaa-lab1", ou: "Enclave/HIPAA", owner: "Dr. Chen", dc: ["PHI","CUI"], evals: 4821, deny: 0 },
  { name: "nlp-research-gpu", ou: "Enclave/CUI", owner: "Dr. Patel", dc: ["CUI"], evals: 2134, deny: 2 },
  { name: "undergrad-teaching", ou: "General/FERPA", owner: "CS Dept", dc: ["FERPA"], evals: 892, deny: 0 },
  { name: "materials-science", ou: "Enclave/CUI", owner: "Dr. Williams", dc: ["CUI","ITAR"], evals: 1567, deny: 1 },
  { name: "clinical-trials-02", ou: "Enclave/HIPAA", owner: "Dr. Rodriguez", dc: ["PHI"], evals: 3241, deny: 0 },
];
const DECISIONS = [
  { t: "14:32:08", act: "s3:PutObject", prin: "role/genomics-pipeline", res: "s3://hipaa-data-lab1/chr7.vcf.gz", eff: "ALLOW", ctrl: "3.1.3", acct: "genomics-hipaa-lab1" },
  { t: "14:31:42", act: "s3:PutObject", prin: "role/data-export", res: "s3://external-collab/dataset.tar.gz", eff: "DENY", ctrl: "3.1.3", acct: "nlp-research-gpu", reason: "Destination not in CUI enclave" },
  { t: "14:31:30", act: "iam:AttachRolePolicy", prin: "user/grad-student-kim", res: "role/admin-access", eff: "DENY", ctrl: "3.1.5", acct: "nlp-research-gpu", reason: "Not in admin OU path" },
  { t: "14:31:18", act: "s3:GetObject", prin: "role/clinical-etl", res: "s3://hipaa-clinical/batch-1042.json", eff: "ALLOW", ctrl: "3.1.1", acct: "clinical-trials-02" },
  { t: "14:30:59", act: "kms:Decrypt", prin: "role/genomics-pipeline", res: "key/cui-enclave-master", eff: "ALLOW", ctrl: "3.13.11", acct: "genomics-hipaa-lab1" },
  { t: "14:30:22", act: "s3:PutBucketPolicy", prin: "user/intern-jones", res: "s3://teaching-assets", eff: "DENY", ctrl: "3.1.2", acct: "undergrad-teaching", reason: "Lacks bucket-admin scope" },
];
const WAIVERS = [
  { id: "W-2025-003", ctrl: "3.1.12", title: "Clean room USB transfer", scope: "materials-science", by: "CISO Dr. Park", exp: "2027-06-15", st: "active", comp: ["Physical access log","Weekly USB audit","Air-gap monitor"] },
  { id: "W-2025-007", ctrl: "3.4.5", title: "Legacy SCADA interface", scope: "materials-science", by: "CISO Dr. Park", exp: "2025-12-31", st: "expiring", comp: ["VLAN isolation","IDS monitoring"] },
];
const INCIDENTS = [
  { id: "INC-2025-012", title: "Unusual S3 pattern in NLP account", sev: "medium", det: "2025-03-28", res: "2025-03-30", st: "closed", ctrls: ["3.1.3","3.14.6"], rem: "Pipeline misconfigured; Cedar policy extended to CopyObject" },
  { id: "INC-2025-008", title: "Credential anomaly (GuardDuty)", sev: "high", det: "2025-02-14", res: "2025-02-14", st: "closed", ctrls: ["3.1.1","3.5.3"], rem: "Access key rotated in 4h, MFA verified" },
];
const TREND = [
  { m: "Oct", s: 72, g: 18 },{ m: "Nov", s: 78, g: 14 },{ m: "Dec", s: 81, g: 11 },
  { m: "Jan", s: 83, g: 9 },{ m: "Feb", s: 85, g: 7 },{ m: "Mar", s: 87, g: 6 },{ m: "Apr", s: 89, g: 5 },
];
const TESTS = [
  { suite: "cui-data-movement", cases: 24, pass: 24, fail: 0 },
  { suite: "least-privilege", cases: 18, pass: 18, fail: 0 },
  { suite: "boundary-control", cases: 12, pass: 11, fail: 1 },
  { suite: "fips-crypto", cases: 8, pass: 8, fail: 0 },
  { suite: "mfa-enforcement", cases: 6, pass: 6, fail: 0 },
];
const PROPOSED = [
  { name: "cedar-chen-genomics-irb.cedar", type: "cedar", src: "ai translate", age: "1h", ctrl: "3.1.3" },
  { name: "cedar-copyobject-cui.cedar", type: "cedar", src: "ai remediate", age: "3h", ctrl: "3.1.3" },
  { name: "cfn-inspector-org.yaml", type: "cfn", src: "ai remediate 3.14.1", age: "3h", ctrl: "3.14.1" },
];

const SC = { enforced: { bg: "var(--color-background-success)", tx: "var(--color-text-success)", bd: "var(--color-border-success)" }, partial: { bg: "var(--color-background-warning)", tx: "var(--color-text-warning)", bd: "var(--color-border-warning)" }, gap: { bg: "var(--color-background-danger)", tx: "var(--color-text-danger)", bd: "var(--color-border-danger)" }, waived: { bg: "var(--color-background-info)", tx: "var(--color-text-info)", bd: "var(--color-border-info)" }, expiring: { bg: "var(--color-background-warning)", tx: "var(--color-text-warning)", bd: "var(--color-border-warning)" } };
const Badge = ({ s }) => { const c = SC[s] || SC.gap; return <span style={{ fontSize: 10, fontWeight: 500, padding: "1px 6px", borderRadius: "var(--border-radius-md)", background: c.bg, color: c.tx, border: `0.5px solid ${c.bd}`, textTransform: "uppercase", letterSpacing: ".03em" }}>{s}</span>; };
const M = ({ l, v, sub, a }) => <div style={{ background: "var(--color-background-secondary)", borderRadius: "var(--border-radius-md)", padding: "10px 14px" }}><div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 3 }}>{l}</div><div style={{ fontSize: 20, fontWeight: 500, color: a || "var(--color-text-primary)" }}>{v}</div>{sub && <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginTop: 2 }}>{sub}</div>}</div>;
const Ring = ({ e, p, g, t, sz = 110 }) => { const r = sz * .4, cx = sz / 2, cy = sz / 2, sw = sz * .08, C = 2 * Math.PI * r; return <svg viewBox={`0 0 ${sz} ${sz}`} style={{ width: sz, height: sz }}><circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--color-border-tertiary)" strokeWidth={sw}/><circle cx={cx} cy={cy} r={r} fill="none" stroke="#1D9E75" strokeWidth={sw} strokeDasharray={`${(e/t)*C} ${C}`} strokeDashoffset={C*.25} strokeLinecap="round"/><circle cx={cx} cy={cy} r={r} fill="none" stroke="#EF9F27" strokeWidth={sw} strokeDasharray={`${(p/t)*C} ${C}`} strokeDashoffset={C*.25-(e/t)*C}/><circle cx={cx} cy={cy} r={r} fill="none" stroke="#E24B4A" strokeWidth={sw} strokeDasharray={`${(g/t)*C} ${C}`} strokeDashoffset={C*.25-(e/t)*C-(p/t)*C}/><text x={cx} y={cy-2} textAnchor="middle" style={{ fontSize: sz*.17, fontWeight: 500, fill: "var(--color-text-primary)" }}>{Math.round(e/t*100)}%</text><text x={cx} y={cy+sz*.1} textAnchor="middle" style={{ fontSize: sz*.08, fill: "var(--color-text-secondary)" }}>enforced</text></svg>; };

function Posture() {
  const tot = CONTROLS.length, enf = CONTROLS.filter(c => c.st === "enforced").length, par = CONTROLS.filter(c => c.st === "partial").length, gap = CONTROLS.filter(c => c.st === "gap").length, wv = CONTROLS.filter(c => c.st === "waived").length;
  const fams = [...new Set(CONTROLS.map(c => c.fam))];
  return <div>
    <div style={{ display: "flex", alignItems: "center", gap: 24, marginBottom: 20 }}>
      <Ring e={enf} p={par} g={gap} t={tot}/>
      <div style={{ flex: 1 }}><div style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>SRE compliance posture</div><div style={{ fontSize: 24, fontWeight: 500 }}>{Math.round(enf/tot*100)}% enforced</div><div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginTop: 2 }}>{enf} enforced · {par} partial · {gap} gap · {wv} waived · {FRAMEWORKS.length} frameworks</div></div>
      <div style={{ textAlign: "right" }}><div style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>CMMC 2.0 L2</div><div style={{ fontSize: 24, fontWeight: 500 }}>487<span style={{ fontSize: 13, color: "var(--color-text-secondary)" }}>/550</span></div><div style={{ fontSize: 10, color: "var(--color-text-success)" }}>Assessment ready</div></div>
    </div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8, marginBottom: 16 }}>
      <M l="Structural (SCPs)" v="24" sub="Org-level"/><M l="Operational (Cedar)" v="31" sub="Context-dependent"/><M l="Monitoring (Config)" v="18" sub="Drift detection"/><M l="Active waivers" v={WAIVERS.length} sub={WAIVERS.some(w=>w.st==="expiring")?"1 expiring soon":""} a={WAIVERS.some(w=>w.st==="expiring")?"var(--color-text-warning)":undefined}/>
    </div>
    <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 8 }}>Posture trend</div>
    <div style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 56, marginBottom: 16 }}>
      {TREND.map((d, i) => <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 3 }}><div style={{ fontSize: 9, fontWeight: 500, color: i===TREND.length-1?"var(--color-text-primary)":"var(--color-text-secondary)" }}>{d.s}%</div><div style={{ width: "100%", background: i===TREND.length-1?"#1D9E75":"var(--color-border-secondary)", borderRadius: 2, height: d.s*.5 }}/><div style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>{d.m}</div></div>)}
    </div>
    {fams.map(f => { const fc = CONTROLS.filter(c=>c.fam===f); return <div key={f} style={{ marginBottom: 12 }}><div style={{ fontSize: 11, fontWeight: 500, marginBottom: 4 }}>{f}</div><div style={{ display: "flex", gap: 3, flexWrap: "wrap" }}>{fc.map(c => { const col = c.st==="enforced"?"#1D9E75":c.st==="partial"?"#EF9F27":c.st==="waived"?"#378ADD":"#E24B4A"; return <div key={c.id} title={`${c.id}: ${c.title} (${c.st})`} style={{ width: 26, height: 26, borderRadius: "var(--border-radius-md)", background: col, fontSize: 8, fontWeight: 500, color: "#fff", display: "flex", alignItems: "center", justifyContent: "center" }}/>; })}</div></div>; })}
    <div style={{ display: "flex", gap: 10, fontSize: 10, color: "var(--color-text-secondary)", marginTop: 4 }}>{[["#1D9E75","Enforced"],["#EF9F27","Partial"],["#E24B4A","Gap"],["#378ADD","Waived"]].map(([c,l])=><span key={l} style={{ display: "flex", alignItems: "center", gap: 3 }}><span style={{ width: 7, height: 7, borderRadius: 2, background: c }}/>{l}</span>)}</div>
  </div>;
}

function Fw() {
  const [sel, setSel] = useState(null);
  return <div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 16 }}>
      {FRAMEWORKS.map(f => <div key={f.id} onClick={() => setSel(f.id===sel?null:f.id)} style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: sel===f.id?"2px solid var(--color-border-info)":"0.5px solid var(--color-border-tertiary)", padding: "12px", cursor: "pointer" }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}><span style={{ fontSize: 13, fontWeight: 500 }}>{f.name}</span><span style={{ fontSize: 16, fontWeight: 500 }}>{f.score}%</span></div>
        <div style={{ display: "flex", height: 5, borderRadius: 2, overflow: "hidden", background: "var(--color-border-tertiary)" }}><div style={{ width: `${f.enforced/f.controls*100}%`, background: "#1D9E75" }}/><div style={{ width: `${f.partial/f.controls*100}%`, background: "#EF9F27" }}/><div style={{ width: `${f.gap/f.controls*100}%`, background: "#E24B4A" }}/></div>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--color-text-secondary)", marginTop: 4 }}><span>{f.enforced} enforced</span><span>{f.partial} partial</span><span>{f.gap} gap</span></div>
      </div>)}
    </div>
    {sel && <div style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", overflow: "hidden" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}><thead><tr style={{ borderBottom: "0.5px solid var(--color-border-tertiary)" }}>{["Ctrl","Title","Status","SCPs","Cedar","Config"].map(h=><th key={h} style={{ padding: "6px 10px", textAlign: "left", fontWeight: 500, color: "var(--color-text-secondary)", fontSize: 10 }}>{h}</th>)}</tr></thead>
        <tbody>{CONTROLS.map(c=><tr key={c.id} style={{ borderBottom: "0.5px solid var(--color-border-tertiary)" }}><td style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontWeight: 500, fontSize: 11 }}>{c.id}</td><td style={{ padding: "7px 10px", maxWidth: 200 }}>{c.title}</td><td style={{ padding: "7px 10px" }}><Badge s={c.st}/></td><td style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>{c.scps||"—"}</td><td style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>{c.cedar||"—"}</td><td style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>{c.config||"—"}</td></tr>)}</tbody></table>
    </div>}
  </div>;
}

function Ops() {
  const [flt, setFlt] = useState("all");
  const ds = flt === "all" ? DECISIONS : DECISIONS.filter(d => d.eff === flt.toUpperCase());
  return <div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8, marginBottom: 12 }}><M l="Evaluations (24h)" v="12,655" sub="+8%"/><M l="Permits" v="12,652"/><M l="Denials" v="3" sub="0.02%"/><M l="Principals" v="47"/></div>
    <div style={{ display: "flex", gap: 4, marginBottom: 10 }}>{["all","allow","deny"].map(f=><button key={f} onClick={()=>setFlt(f)} style={{ background: flt===f?"var(--color-background-secondary)":"transparent", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: "2px 8px", fontSize: 10, cursor: "pointer", color: flt===f?"var(--color-text-primary)":"var(--color-text-secondary)", fontWeight: flt===f?500:400 }}>{f==="all"?"All":f==="allow"?"Permits":"Denials"}</button>)}</div>
    <div style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", overflow: "hidden" }}>
      <div style={{ padding: "7px 12px", borderBottom: "0.5px solid var(--color-border-tertiary)", display: "flex", alignItems: "center", gap: 5 }}><div style={{ width: 5, height: 5, borderRadius: "50%", background: "#1D9E75", animation: "pulse 2s infinite" }}/><span style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>Live — Cedar PDP</span><span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--color-text-secondary)" }}>EventBridge → PDP → S3 + SecurityHub</span></div>
      {ds.map((d, i) => <div key={i} style={{ padding: "7px 12px", borderBottom: "0.5px solid var(--color-border-tertiary)", display: "grid", gridTemplateColumns: "48px 36px minmax(0,1fr) minmax(0,1fr) 50px", gap: 8, alignItems: "center", background: d.eff==="DENY"?"var(--color-background-danger)":"transparent" }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--color-text-secondary)" }}>{d.t}</span>
        <span style={{ fontSize: 8, fontWeight: 500, padding: "1px 4px", borderRadius: "var(--border-radius-md)", textAlign: "center", background: d.eff==="ALLOW"?"var(--color-background-success)":"var(--color-background-danger)", color: d.eff==="ALLOW"?"var(--color-text-success)":"var(--color-text-danger)" }}>{d.eff}</span>
        <div style={{ overflow: "hidden" }}><div style={{ fontSize: 10, fontFamily: "var(--font-mono)" }}>{d.act}</div><div style={{ fontSize: 9, color: "var(--color-text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.res}</div>{d.reason && <div style={{ fontSize: 9, color: "var(--color-text-danger)", marginTop: 1 }}>{d.reason}</div>}</div>
        <div style={{ fontSize: 9, color: "var(--color-text-secondary)" }}><div>{d.prin}</div><div>{d.acct}</div></div>
        <div style={{ fontSize: 9, fontFamily: "var(--font-mono)", color: "var(--color-text-secondary)", textAlign: "right" }}>{d.ctrl}</div>
      </div>)}
    </div>
  </div>;
}

function Env() {
  return <div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 12 }}><M l="Environments" v={ENVS.length}/><M l="Evaluations (24h)" v="12,655"/><M l="Data classes" v="4" sub="PHI, CUI, FERPA, ITAR"/></div>
    <div style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", overflow: "hidden" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}><thead><tr style={{ borderBottom: "0.5px solid var(--color-border-tertiary)" }}>{["Name","OU","Owner","Data classes","Evals","Deny"].map(h=><th key={h} style={{ padding: "6px 10px", textAlign: "left", fontWeight: 500, color: "var(--color-text-secondary)", fontSize: 10 }}>{h}</th>)}</tr></thead>
        <tbody>{ENVS.map(e=><tr key={e.name} style={{ borderBottom: "0.5px solid var(--color-border-tertiary)" }}><td style={{ padding: "7px 10px", fontWeight: 500 }}>{e.name}</td><td style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--color-text-secondary)" }}>{e.ou}</td><td style={{ padding: "7px 10px" }}>{e.owner}</td><td style={{ padding: "7px 10px" }}><div style={{ display: "flex", gap: 2, flexWrap: "wrap" }}>{e.dc.map(d=><span key={d} style={{ fontSize: 8, padding: "1px 4px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-info)", color: "var(--color-text-info)", fontWeight: 500 }}>{d}</span>)}</div></td><td style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 10 }}>{e.evals.toLocaleString()}</td><td style={{ padding: "7px 10px", fontFamily: "var(--font-mono)", fontSize: 10, color: e.deny>0?"var(--color-text-danger)":"var(--color-text-success)", fontWeight: 500 }}>{e.deny}</td></tr>)}</tbody></table>
    </div>
  </div>;
}

function Waiv() {
  return <div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 12 }}><M l="Active" v={WAIVERS.length}/><M l="Expiring 90d" v={WAIVERS.filter(w=>w.st==="expiring").length} a="var(--color-text-warning)"/><M l="Controls affected" v={new Set(WAIVERS.map(w=>w.ctrl)).size}/></div>
    {WAIVERS.map(w=><div key={w.id} style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", padding: "12px 16px", marginBottom: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}><div style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 500 }}>{w.id}</span><span style={{ fontSize: 12, fontWeight: 500 }}>{w.title}</span></div><Badge s={w.st==="expiring"?"expiring":"waived"}/></div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, fontSize: 11, color: "var(--color-text-secondary)", marginBottom: 4 }}><div>Control: <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-text-primary)" }}>{w.ctrl}</span></div><div>Scope: {w.scope}</div><div>Expires: <span style={{ color: w.st==="expiring"?"var(--color-text-warning)":"var(--color-text-primary)", fontWeight: w.st==="expiring"?500:400 }}>{w.exp}</span></div></div>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>Approved: {w.by} · Compensating: {w.comp.join(" · ")}</div>
    </div>)}
  </div>;
}

function Inc() {
  return <div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 12 }}><M l="Open" v={0}/><M l="Closed (period)" v={INCIDENTS.length}/><M l="MTTR" v="5h" sub="Below 24h SLA"/></div>
    {INCIDENTS.map(i=><div key={i.id} style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", padding: "12px 16px", marginBottom: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}><div style={{ display: "flex", alignItems: "center", gap: 6 }}><span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)" }}>{i.id}</span><span style={{ fontSize: 12, fontWeight: 500 }}>{i.title}</span></div><div style={{ display: "flex", gap: 4 }}><Badge s={i.sev==="high"?"gap":"partial"}/><span style={{ fontSize: 9, padding: "1px 5px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-success)", color: "var(--color-text-success)", fontWeight: 500 }}>{i.st}</span></div></div>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)", marginBottom: 3 }}>Detected: {i.det} · Resolved: {i.res} · Controls: {i.ctrls.join(", ")}</div>
      <div style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>{i.rem}</div>
    </div>)}
    <div style={{ fontSize: 11, color: "var(--color-text-secondary)", marginTop: 6, padding: "6px 0", borderTop: "0.5px solid var(--color-border-tertiary)", fontStyle: "italic" }}>SSP: {INCIDENTS.length} incidents during assessment period. All remediated. Cedar logs confirm no CUI exposure.</div>
  </div>;
}

function Tests() {
  return <div>
    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 8, marginBottom: 12 }}><M l="Suites" v={TESTS.length}/><M l="Cases" v={TESTS.reduce((a,t)=>a+t.cases,0)}/><M l="Passing" v={TESTS.reduce((a,t)=>a+t.pass,0)} a="var(--color-text-success)"/><M l="Failing" v={TESTS.reduce((a,t)=>a+t.fail,0)} a={TESTS.some(t=>t.fail>0)?"var(--color-text-danger)":"var(--color-text-success)"}/></div>
    <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 8 }}>Proposed artifacts</div>
    {PROPOSED.map(p=><div key={p.name} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 12px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
      <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: "var(--border-radius-md)", background: "var(--color-background-info)", color: "var(--color-text-info)", fontWeight: 500 }}>{p.type}</span>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 500, flex: 1 }}>{p.name}</span>
      <span style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>{p.src} · {p.age}</span>
      <button style={{ background: "transparent", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", padding: "2px 8px", fontSize: 10, cursor: "pointer", color: "var(--color-text-success)", fontWeight: 500 }}>Accept</button>
      <button style={{ background: "transparent", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: "2px 8px", fontSize: 10, cursor: "pointer", color: "var(--color-text-secondary)" }}>Reject</button>
    </div>)}
    <div style={{ fontSize: 12, fontWeight: 500, margin: "14px 0 8px" }}>Test suites</div>
    <div style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", overflow: "hidden" }}>
      {TESTS.map(t=><div key={t.suite} style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
        <span style={{ width: 7, height: 7, borderRadius: "50%", background: t.fail>0?"#E24B4A":"#1D9E75" }}/>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 500, flex: 1 }}>{t.suite}</span>
        <span style={{ fontSize: 10, color: "var(--color-text-success)" }}>{t.pass} pass</span>
        {t.fail>0&&<span style={{ fontSize: 10, color: "var(--color-text-danger)" }}>{t.fail} fail</span>}
      </div>)}
    </div>
    <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
      <div style={{ flex: 1, background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", padding: "12px" }}>
        <div style={{ fontSize: 11, fontWeight: 500, marginBottom: 4 }}>Git store</div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>HEAD: <span style={{ color: "var(--color-text-primary)" }}>a3f7c21</span> compile: update Cedar 3.1.3<br/>TAG: <span style={{ color: "var(--color-text-info)" }}>assessment-2025-q1</span><br/>+3 Cedar, +1 Config since tag</div>
      </div>
      <div style={{ flex: 1, background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", padding: "12px" }}>
        <div style={{ fontSize: 11, fontWeight: 500, marginBottom: 4 }}>IaC output</div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-text-secondary)", lineHeight: 1.7 }}>Terraform: <span style={{ color: "var(--color-text-success)" }}>synced</span><br/>Modules: scps, config, eventbridge, security<br/>Last apply: 6h ago via CI/CD</div>
      </div>
    </div>
  </div>;
}

function Gen() {
  const [g, setG] = useState(null);
  const docs = [
    { id: "ssp", l: "System security plan", d: "From crosswalk + eval logs", c: "attest generate ssp" },
    { id: "assess", l: "Self-assessment", d: "CMMC 2.0 L2 scoring", c: "attest generate assess" },
    { id: "poam", l: "Plan of action & milestones", d: "From gaps + estimates", c: "attest generate poam" },
    { id: "oscal", l: "Full OSCAL export", d: "SSP + AR + POA&M bundle", c: "attest generate oscal" },
    { id: "trend", l: "Trend report", d: "90-day posture change", c: "attest report --window 90d" },
    { id: "cross", l: "Crosswalk manifest", d: "Control → artifact mapping", c: "attest compile" },
  ];
  return <div>{docs.map(d=><div key={d.id} style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", padding: "12px 16px", marginBottom: 6, display: "flex", alignItems: "center", gap: 12 }}>
    <div style={{ flex: 1 }}><div style={{ fontSize: 12, fontWeight: 500, marginBottom: 1 }}>{d.l}</div><div style={{ fontSize: 10, color: "var(--color-text-secondary)" }}>{d.d} · <span style={{ fontFamily: "var(--font-mono)" }}>{d.c}</span></div></div>
    <button onClick={()=>{setG(d.id);setTimeout(()=>setG(null),1200)}} style={{ background: g===d.id?"var(--color-background-success)":"transparent", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", padding: "5px 12px", fontSize: 11, cursor: "pointer", color: g===d.id?"var(--color-text-success)":"var(--color-text-primary)", fontWeight: 500 }}>{g===d.id?"Done":"Generate"}</button>
  </div>)}</div>;
}

function AI() {
  const [inp, setInp] = useState("");
  const [msgs, setMsgs] = useState([{ r: "a", t: "I have access to your full compliance state — posture, crosswalk, Cedar decision logs, Security Hub findings, framework definitions. Every claim cites a specific artifact. How can I help?" }]);
  const ask = (q) => { const txt = q || inp; if (!txt.trim()) return; setMsgs(m => [...m, { r: "u", t: txt }, { r: "a", t: "Querying posture... Checking crosswalk... Searching Cedar log...\n\nYour current posture is 88.5% (crosswalk: 110 controls). 2 gaps remain: 3.14.1 (Inspector not enabled in 2 accounts) and 3.14.6 (partial monitoring). 1 waiver active (W-2025-003, 3.1.12). The waiver for 3.4.5 expires Dec 2025.\n\nFor CMMC readiness, your score is 487/550. The 2 major findings an assessor would flag: 3.14.1 (no vulnerability scanning) and the boundary-control test failure.\n\nRecommend: `attest ai remediate 3.14.1` then `attest test` to verify.\n\n[posture-2025-04-09, crosswalk 3.14.1, W-2025-003, W-2025-007, test-suite boundary-control]" }]); setInp(""); };
  return <div>
    <div style={{ display: "flex", gap: 4, marginBottom: 10, flexWrap: "wrap" }}>{["Are we ready for CMMC?","What if we add ITAR to materials-science?","Explain the March GuardDuty incident impact"].map((q,i)=><button key={i} onClick={()=>ask(q)} style={{ background: "var(--color-background-primary)", border: "0.5px solid var(--color-border-tertiary)", borderRadius: "var(--border-radius-md)", padding: "5px 10px", fontSize: 10, cursor: "pointer", color: "var(--color-text-primary)", textAlign: "left" }}>{q}</button>)}</div>
    <div style={{ background: "var(--color-background-primary)", borderRadius: "var(--border-radius-lg)", border: "0.5px solid var(--color-border-tertiary)", minHeight: 280, display: "flex", flexDirection: "column" }}>
      <div style={{ flex: 1, padding: "12px", overflow: "auto" }}>{msgs.map((m, i) => <div key={i} style={{ marginBottom: 10, display: "flex", gap: 6 }}>
        <div style={{ width: 20, height: 20, borderRadius: "50%", background: m.r==="u"?"var(--color-background-info)":"var(--color-background-secondary)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 500, color: m.r==="u"?"var(--color-text-info)":"var(--color-text-secondary)", flexShrink: 0, marginTop: 1 }}>{m.r==="u"?"U":"A"}</div>
        <div style={{ fontSize: 11, lineHeight: 1.6, whiteSpace: "pre-wrap" }}>{m.t}</div>
      </div>)}</div>
      <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", padding: "8px 12px", display: "flex", gap: 6 }}>
        <input value={inp} onChange={e=>setInp(e.target.value)} onKeyDown={e=>e.key==="Enter"&&ask()} placeholder="Ask the compliance analyst..." style={{ flex: 1, fontSize: 11 }}/>
        <button onClick={()=>ask()} style={{ background: "transparent", border: "0.5px solid var(--color-border-secondary)", borderRadius: "var(--border-radius-md)", padding: "3px 10px", fontSize: 11, cursor: "pointer", fontWeight: 500 }}>Ask</button>
      </div>
    </div>
    <div style={{ display: "flex", gap: 4, marginTop: 8, flexWrap: "wrap" }}>{["attest ai audit-sim","attest ai analyze --window 30d","attest ai translate","attest ai impact","attest ai remediate"].map(c=><span key={c} style={{ fontFamily: "var(--font-mono)", fontSize: 9, background: "var(--color-background-secondary)", padding: "2px 6px", borderRadius: "var(--border-radius-md)", color: "var(--color-text-secondary)" }}>{c}</span>)}</div>
  </div>;
}

const NAV = {
  posture: { l: "Posture", i: "\u25C9", C: Posture, t: "SRE posture" },
  frameworks: { l: "Frameworks", i: "\u2630", C: Fw, t: "Framework compliance", n: 3 },
  operations: { l: "Operations", i: "\u25B6", C: Ops, t: "Operational monitoring" },
  environments: { l: "Environments", i: "\u2302", C: Env, t: "Research environments", n: 5 },
  waivers: { l: "Waivers", i: "\u2696", C: Waiv, t: "Exception management", a: true },
  incidents: { l: "Incidents", i: "\u26A0", C: Inc, t: "Incident lifecycle" },
  tests: { l: "Tests & deploy", i: "\u2713", C: Tests, t: "Policy testing & deployment" },
  generate: { l: "Generate", i: "\u2193", C: Gen, t: "Generate documents" },
  analyst: { l: "AI analyst", i: "\u2606", C: AI, t: "Compliance analyst" },
};
const GROUPS = [["Compliance", ["posture","frameworks","operations","environments"]], ["Governance", ["waivers","incidents"]], ["Engineering", ["tests","generate"]], ["AI", ["analyst"]]];

export default function App() {
  const [v, setV] = useState("posture");
  const V = NAV[v];
  return <div style={{ display: "flex", minHeight: 600 }}>
    <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}`}</style>
    <div style={{ width: 176, borderRight: "0.5px solid var(--color-border-tertiary)", padding: "10px 6px", flexShrink: 0, display: "flex", flexDirection: "column" }}>
      <div style={{ fontSize: 15, fontWeight: 500, padding: "4px 10px", marginBottom: 8 }}>attest</div>
      {GROUPS.map(([g, ks]) => <div key={g}><div style={{ fontSize: 9, fontWeight: 500, color: "var(--color-text-secondary)", textTransform: "uppercase", letterSpacing: ".05em", padding: "8px 10px 3px" }}>{g}</div>
        {ks.map(k => { const n = NAV[k]; return <button key={k} onClick={()=>setV(k)} style={{ background: v===k?"var(--color-background-secondary)":"transparent", border: "none", borderRadius: "var(--border-radius-md)", padding: "5px 10px", cursor: "pointer", display: "flex", alignItems: "center", gap: 6, color: v===k?"var(--color-text-primary)":"var(--color-text-secondary)", fontWeight: v===k?500:400, fontSize: 12, width: "100%", textAlign: "left" }}>
          <span style={{ fontSize: 12, width: 16, textAlign: "center", opacity: .65 }}>{n.i}</span>{n.l}
          {n.n!==undefined&&<span style={{ marginLeft: "auto", fontSize: 9, background: "var(--color-background-tertiary)", borderRadius: "var(--border-radius-md)", padding: "0 5px", color: "var(--color-text-secondary)" }}>{n.n}</span>}
          {n.a&&<span style={{ marginLeft: n.n!==undefined?0:"auto", width: 5, height: 5, borderRadius: "50%", background: "#E24B4A" }}/>}
        </button>; })}
      </div>)}
      <div style={{ marginTop: "auto", borderTop: "0.5px solid var(--color-border-tertiary)", paddingTop: 8 }}>
        <div style={{ fontSize: 10, color: "var(--color-text-secondary)", padding: "0 10px" }}>SRE</div>
        <div style={{ fontSize: 11, fontWeight: 500, padding: "0 10px" }}>research-university</div>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--color-text-secondary)", padding: "0 10px" }}>o-abc123def456</div>
        <div style={{ display: "flex", alignItems: "center", gap: 3, padding: "4px 10px 0", fontSize: 9 }}><div style={{ width: 5, height: 5, borderRadius: "50%", background: "#1D9E75", animation: "pulse 2s infinite" }}/><span style={{ color: "var(--color-text-success)" }}>Cedar PDP active</span></div>
        <div style={{ borderTop: "0.5px solid var(--color-border-tertiary)", marginTop: 6, padding: "6px 10px 0" }}><div style={{ fontSize: 10, fontWeight: 500 }}>Dr. Park</div><div style={{ fontSize: 9, color: "var(--color-text-secondary)" }}>compliance_officer · passkey</div></div>
      </div>
    </div>
    <div style={{ flex: 1, padding: "14px 18px", minWidth: 0, overflow: "auto" }}>
      <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 14 }}>{V.t}</div>
      <V.C/>
    </div>
  </div>;
}
