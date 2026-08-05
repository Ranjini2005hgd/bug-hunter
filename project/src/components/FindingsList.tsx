import { useState, useMemo, useCallback } from 'react';
import { ChevronDown, ExternalLink, Code2, Wrench, ListChecks, FileWarning, ShieldAlert, FileText, Clock, Activity, Camera, Video, Download, X, Trash2, Cpu, Film } from 'lucide-react';
import type { Category, Finding, Severity, ScreenshotEvidence, VideoEvidence, Assessment } from '@/lib/types';
import { SeverityBadge, CATEGORY_META } from './ScanVisuals';
import { generateSingleFindingReport } from '@/lib/reportGenerator';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORIES: Category[] = ['security', 'accessibility', 'seo', 'performance', 'best-practices', 'pwa', 'code'];

interface FindingsListProps {
  findings: Finding[];
  assessment?: Assessment;
  onFindingsChange?: (findings: Finding[]) => void;
  onRecordEvidence?: (finding: Finding) => void;
}

export function FindingsList({ findings, assessment, onFindingsChange, onRecordEvidence }: FindingsListProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [catFilter, setCatFilter] = useState<Set<Category>>(new Set());

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSev = (s: Severity) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const toggleCat = (c: Category) => {
    setCatFilter((prev) => {
      const next = new Set(prev);
      if (next.has(c)) next.delete(c);
      else next.add(c);
      return next;
    });
  };

  const updateFinding = useCallback((id: string, updates: Partial<Finding>) => {
    if (!onFindingsChange) return;
    onFindingsChange(findings.map((f) => (f.id === id ? { ...f, ...updates } : f)));
  }, [findings, onFindingsChange]);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (sevFilter.size > 0 && !sevFilter.has(f.severity)) return false;
      if (catFilter.size > 0 && !catFilter.has(f.category)) return false;
      return true;
    });
  }, [findings, sevFilter, catFilter]);

  if (findings.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500">
        <ListChecks className="w-12 h-12 mx-auto mb-4 text-emerald-400/60" />
        <p className="text-lg">No issues were detected during this scan.</p>
        <p className="text-sm mt-1">This page passes all checks. Nice work!</p>
      </div>
    );
  }

  return (
    <div>
      {/* Filters */}
      <div className="mb-6 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500 uppercase tracking-wide mr-1">Severity:</span>
          {SEVERITIES.map((s) => {
            const active = sevFilter.has(s);
            return (
              <button
                key={s}
                onClick={() => toggleSev(s)}
                className={`transition ${active ? 'ring-2 ring-offset-2 ring-offset-slate-900' : 'opacity-60 hover:opacity-100'}`}
              >
                <SeverityBadge severity={s} size="sm" />
              </button>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500 uppercase tracking-wide mr-1">Category:</span>
          {CATEGORIES.map((c) => {
            const meta = CATEGORY_META[c];
            const active = catFilter.has(c);
            return (
              <button
                key={c}
                onClick={() => toggleCat(c)}
                className={`text-xs px-2.5 py-1 rounded-full border transition ${active ? `${meta.bg} ${meta.color} ${meta.border}` : 'bg-slate-800/40 text-slate-500 border-slate-700/40 hover:text-slate-300'}`}
              >
                {meta.label}
              </button>
            );
          })}
        </div>
        <div className="text-xs text-slate-500">
          Showing {filtered.length} of {findings.length} findings
        </div>
      </div>

      {/* Findings */}
      <div className="space-y-3">
        {filtered.map((f, i) => {
          const originalIndex = findings.indexOf(f) + 1;
          return (
            <FindingCard
              key={f.id}
              finding={f}
              index={originalIndex}
              expanded={expanded.has(f.id)}
              onToggle={() => toggle(f.id)}
              assessment={assessment}
              onRecordEvidence={onRecordEvidence}
              onAddScreenshot={(ss) => {
                const existing = f.mediaEvidence?.screenshots || [];
                updateFinding(f.id, {
                  mediaEvidence: {
                    ...f.mediaEvidence,
                    screenshots: [...existing, ss],
                  },
                });
              }}
              onRemoveScreenshot={(ssId) => {
                const existing = f.mediaEvidence?.screenshots || [];
                updateFinding(f.id, {
                  mediaEvidence: {
                    ...f.mediaEvidence,
                    screenshots: existing.filter((s) => s.id !== ssId),
                  },
                });
              }}
              onAddVideo={(vid) => {
                updateFinding(f.id, {
                  mediaEvidence: {
                    ...f.mediaEvidence,
                    screenshots: f.mediaEvidence?.screenshots || [],
                    videoRecording: vid,
                  },
                });
              }}
              onRemoveVideo={() => {
                updateFinding(f.id, {
                  mediaEvidence: {
                    ...f.mediaEvidence,
                    screenshots: f.mediaEvidence?.screenshots || [],
                    videoRecording: undefined,
                  },
                });
              }}
            />
          );
        })}
      </div>
    </div>
  );
}

interface FindingCardProps {
  finding: Finding;
  index: number;
  expanded: boolean;
  onToggle: () => void;
  assessment?: Assessment;
  onAddScreenshot?: (ss: ScreenshotEvidence) => void;
  onRemoveScreenshot?: (id: string) => void;
  onAddVideo?: (vid: VideoEvidence) => void;
  onRemoveVideo?: () => void;
  onRecordEvidence?: (finding: Finding) => void;
}

function FindingCard({ finding, index, expanded, onToggle, assessment, onAddScreenshot, onRemoveScreenshot, onAddVideo, onRemoveVideo, onRecordEvidence }: FindingCardProps) {
  const meta = CATEGORY_META[finding.category];
  const Icon = meta.icon;
  const [showEvidence, setShowEvidence] = useState(false);

  const handleScreenshotUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || !onAddScreenshot) return;
    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = () => {
        onAddScreenshot({
          id: crypto.randomUUID(),
          dataUrl: reader.result as string,
          filename: file.name,
          caption: `Screenshot: ${file.name}`,
          timestamp: new Date().toISOString(),
        });
      };
      reader.readAsDataURL(file);
    });
    e.target.value = '';
  };

  const handleVideoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !onAddVideo) return;
    const reader = new FileReader();
    reader.onload = () => {
      onAddVideo({
        id: crypto.randomUUID(),
        dataUrl: reader.result as string,
        filename: file.name,
        duration: 0,
        timestamp: new Date().toISOString(),
      });
    };
    reader.readAsDataURL(file);
    e.target.value = '';
  };

  const hasMedia = (finding.mediaEvidence?.screenshots.length || 0) > 0 || !!finding.mediaEvidence?.videoRecording;

  return (
    <div className={`bg-slate-800/30 border rounded-xl overflow-hidden transition-all duration-200 ${expanded ? 'border-cyan-500/40' : 'border-slate-700/40 hover:border-slate-600/60'}`}>
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 p-4 text-left"
      >
        <div className={`w-9 h-9 rounded-lg ${meta.bg} flex items-center justify-center ${meta.color} flex-shrink-0 mt-0.5`}>
          <Icon className="w-4.5 h-4.5" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-xs text-slate-600 font-mono">#{index}</span>
            <SeverityBadge severity={finding.severity} size="sm" />
            <span className={`text-xs ${meta.color}`}>{meta.label}</span>
            {finding.cvss && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-cyan-900/40">
                CVSS {finding.cvss.score.toFixed(1)}
              </span>
            )}
            {finding.owaspCategory && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-orange-400 border border-orange-900/40">
                {finding.owaspCategory.split(':')[0]}
              </span>
            )}
            {finding.cweId && <span className="text-[10px] text-slate-600 font-mono">{finding.cweId}</span>}
            {finding.vulnerabilityClass && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-900/40">
                {finding.vulnerabilityClass.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
              </span>
            )}
            {hasMedia && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-900/40">
                <Camera className="w-2.5 h-2.5 inline mr-0.5" />Evidence
              </span>
            )}
          </div>
          <h3 className="text-sm font-semibold text-slate-200 leading-snug">{finding.title}</h3>
          {!expanded && <p className="text-xs text-slate-500 mt-1 line-clamp-1">{finding.description}</p>}
        </div>
        <ChevronDown className={`w-5 h-5 text-slate-500 flex-shrink-0 transition-transform ${expanded ? 'rotate-180' : ''}`} />
      </button>

      {expanded && (
        <div className="px-4 pb-4 pt-1 space-y-4 animate-slide-down">
          {/* Per-finding download button */}
          <div className="flex flex-wrap gap-2">
            {assessment && (
              <button
                onClick={() => generateSingleFindingReport(assessment, finding, index)}
                className="inline-flex items-center gap-2 px-3 py-1.5 bg-violet-500/10 hover:bg-violet-500/20 text-violet-300 text-xs font-medium rounded-lg border border-violet-500/20 transition"
              >
                <Download className="w-3.5 h-3.5" />
                Download This Finding
              </button>
            )}
            {onRecordEvidence && (
              <button
                onClick={() => onRecordEvidence(finding)}
                className="inline-flex items-center gap-2 px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-300 text-xs font-medium rounded-lg border border-red-500/20 transition"
              >
                <Film className="w-3.5 h-3.5" />
                Record Video Evidence
              </button>
            )}
          </div>

          {/* Description */}
          <Section icon={<FileWarning className="w-3.5 h-3.5" />} title="Description">
            <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>
          </Section>

          {/* Evidence */}
          {finding.evidence && (
            <Section icon={<Code2 className="w-3.5 h-3.5" />} title="Evidence">
              <pre className="text-xs text-slate-400 bg-slate-950/60 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap border border-slate-800">{finding.evidence}</pre>
            </Section>
          )}

          {/* Impact */}
          <Section title="Impact">
            <p className="text-sm text-slate-300 leading-relaxed">{finding.impact}</p>
          </Section>

          {/* Recommendation */}
          <Section icon={<Wrench className="w-3.5 h-3.5" />} title="Recommended Fix">
            <p className="text-sm text-cyan-300/90 leading-relaxed">{finding.recommendation}</p>
          </Section>

          {/* Fix steps */}
          <Section icon={<ListChecks className="w-3.5 h-3.5" />} title="Step-by-Step">
            <ol className="space-y-1.5">
              {finding.fixSteps.map((step, idx) => (
                <li key={idx} className="text-sm text-slate-300 flex gap-2.5">
                  <span className="text-cyan-400 font-mono text-xs mt-0.5">{idx + 1}.</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </Section>

          {/* Before / After code */}
          {(finding.codeBefore || finding.codeAfter) && (
            <Section icon={<Code2 className="w-3.5 h-3.5" />} title="Code Example">
              <div className="grid sm:grid-cols-2 gap-3">
                {finding.codeBefore && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-red-400/70 mb-1 font-semibold">Before</div>
                    <pre className="text-xs text-red-300/80 bg-red-950/30 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap border border-red-900/30">{finding.codeBefore}</pre>
                  </div>
                )}
                {finding.codeAfter && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-emerald-400/70 mb-1 font-semibold">After</div>
                    <pre className="text-xs text-emerald-300/80 bg-emerald-950/30 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap border border-emerald-900/30">{finding.codeAfter}</pre>
                  </div>
                )}
              </div>
            </Section>
          )}

          {/* References */}
          {finding.references.length > 0 && (
            <Section title="References">
              <div className="space-y-1.5">
                {finding.references.map((ref, idx) => (
                  <a
                    key={idx}
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition"
                  >
                    <ExternalLink className="w-3 h-3" />
                    {ref.label}
                  </a>
                ))}
              </div>
            </Section>
          )}

          {/* PoC */}
          {finding.evidencePackage?.proofOfConcept && (
            <Section icon={<ShieldAlert className="w-3.5 h-3.5" />} title="Proof of Concept">
              <div className="text-sm text-slate-300 leading-relaxed bg-slate-950/40 border-l-2 border-cyan-500/40 rounded-r-lg p-3 whitespace-pre-wrap">{finding.evidencePackage.proofOfConcept}</div>
            </Section>
          )}

          {/* Reproduction steps */}
          {finding.evidencePackage?.reproductionSteps?.length ? (
            <Section icon={<ListChecks className="w-3.5 h-3.5" />} title="Reproduction Steps">
              <ol className="space-y-1.5">
                {finding.evidencePackage.reproductionSteps.map((step, idx) => (
                  <li key={idx} className="text-sm text-slate-300 flex gap-2.5">
                    <span className="text-cyan-400 font-mono text-xs mt-0.5">{idx + 1}.</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </Section>
          ) : null}

          {/* HTTP Request/Response */}
          {finding.evidencePackage?.httpRequests?.length ? (
            <Section icon={<FileText className="w-3.5 h-3.5" />} title="HTTP Request">
              <pre className="text-xs text-slate-400 bg-slate-950/60 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap border border-slate-800">{finding.evidencePackage.httpRequests[0].content}</pre>
            </Section>
          ) : null}

          {finding.evidencePackage?.httpResponses?.length ? (
            <Section icon={<FileText className="w-3.5 h-3.5" />} title="HTTP Response">
              <pre className="text-xs text-slate-400 bg-slate-950/60 rounded-lg p-3 overflow-x-auto font-mono whitespace-pre-wrap border border-slate-800">{finding.evidencePackage.httpResponses[0].content}</pre>
            </Section>
          ) : null}

          {/* Media Evidence Upload */}
          {onAddScreenshot && (
            <Section icon={<Camera className="w-3.5 h-3.5" />} title="Evidence — Screenshots & Video">
              <div className="space-y-3">
                {/* Uploaded screenshots */}
                {finding.mediaEvidence?.screenshots.map((ss) => (
                  <div key={ss.id} className="relative group">
                    <img src={ss.dataUrl} alt={ss.caption} className="rounded-lg border border-slate-700 max-h-48 object-contain" />
                    <button
                      onClick={() => onRemoveScreenshot?.(ss.id)}
                      className="absolute top-2 right-2 p-1 bg-red-500/80 hover:bg-red-500 text-white rounded opacity-0 group-hover:opacity-100 transition"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                    <p className="text-xs text-slate-500 mt-1">{ss.caption}</p>
                  </div>
                ))}

                {/* Uploaded video */}
                {finding.mediaEvidence?.videoRecording && (
                  <div className="flex items-center gap-3 bg-slate-900/40 border border-slate-700 rounded-lg p-3">
                    <Video className="w-5 h-5 text-cyan-400" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-slate-300 truncate">{finding.mediaEvidence.videoRecording.filename}</p>
                      <p className="text-[10px] text-slate-500">Video evidence attached</p>
                    </div>
                    <button
                      onClick={() => onRemoveVideo?.()}
                      className="p-1 text-slate-500 hover:text-red-400 transition"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                )}

                {/* Upload buttons */}
                {!showEvidence ? (
                  <div className="flex gap-2">
                    <button
                      onClick={() => setShowEvidence(true)}
                      className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-xs rounded-lg border border-slate-700/50 transition"
                    >
                      <Camera className="w-3.5 h-3.5" />
                      Add Screenshot
                    </button>
                    <button
                      onClick={() => setShowEvidence(true)}
                      className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 text-xs rounded-lg border border-slate-700/50 transition"
                    >
                      <Video className="w-3.5 h-3.5" />
                      Add Video
                    </button>
                  </div>
                ) : (
                  <div className="flex gap-2">
                    <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs rounded-lg border border-cyan-500/20 transition">
                      <Camera className="w-3.5 h-3.5" />
                      Upload Screenshot
                      <input type="file" accept="image/*" multiple onChange={handleScreenshotUpload} className="hidden" />
                    </label>
                    <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs rounded-lg border border-cyan-500/20 transition">
                      <Video className="w-3.5 h-3.5" />
                      Upload Video
                      <input type="file" accept="video/*" onChange={handleVideoUpload} className="hidden" />
                    </label>
                    <button
                      onClick={() => setShowEvidence(false)}
                      className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-800 text-slate-500 text-xs rounded-lg border border-slate-700/50 transition"
                    >
                      <X className="w-3.5 h-3.5" />
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            </Section>
          )}

          {finding.timeline?.length ? (
            <Section icon={<Clock className="w-3.5 h-3.5" />} title="Timeline">
              <div className="space-y-1.5">
                {finding.timeline.map((t, idx) => (
                  <div key={idx} className="text-xs text-slate-400 flex gap-2">
                    <Activity className="w-3 h-3 text-slate-600 mt-0.5 flex-shrink-0" />
                    <span><span className="text-slate-500">{new Date(t.timestamp).toLocaleTimeString()}</span> — <span className="text-slate-300">{t.event}</span>{t.detail ? <span className="text-slate-500">: {t.detail}</span> : null}</span>
                  </div>
                ))}
              </div>
            </Section>
          ) : null}

          {finding.aiExplanation && (
            <Section icon={<Cpu className="w-3.5 h-3.5" />} title="AI Vulnerability Analysis">
              <div className="space-y-3">
                <div className="text-sm text-slate-300 leading-relaxed bg-slate-950/40 rounded-lg p-3 border-l-2 border-cyan-500/40">
                  <span className="text-cyan-400 text-xs font-semibold uppercase tracking-wide block mb-1">Summary</span>
                  {finding.aiExplanation.summary}
                </div>
                <div className="text-sm text-slate-300 leading-relaxed bg-slate-950/40 rounded-lg p-3 border-l-2 border-red-500/40">
                  <span className="text-red-400 text-xs font-semibold uppercase tracking-wide block mb-1">Attack Scenario</span>
                  {finding.aiExplanation.attackScenario}
                </div>
                <div className="text-sm text-slate-300 leading-relaxed bg-slate-950/40 rounded-lg p-3 border-l-2 border-amber-500/40">
                  <span className="text-amber-400 text-xs font-semibold uppercase tracking-wide block mb-1">Business Risk</span>
                  {finding.aiExplanation.businessRisk}
                </div>
                <div className="text-sm text-slate-300 leading-relaxed bg-slate-950/40 rounded-lg p-3 border-l-2 border-emerald-500/40">
                  <span className="text-emerald-400 text-xs font-semibold uppercase tracking-wide block mb-1">Remediation Priority</span>
                  {finding.aiExplanation.remediationPriority}
                </div>
                <div className="text-sm text-slate-300 leading-relaxed bg-slate-950/40 rounded-lg p-3 border-l-2 border-violet-500/40">
                  <span className="text-violet-400 text-xs font-semibold uppercase tracking-wide block mb-1">Testing Advice</span>
                  {finding.aiExplanation.testingAdvice}
                </div>
              </div>
            </Section>
          )}

          <div className="flex items-center gap-3 text-[10px] text-slate-600 pt-1 border-t border-slate-800 flex-wrap">
            <span className="font-mono">Rule: {finding.ruleId}</span>
            <span>Confidence: {finding.confidence}</span>
            {finding.likelihood && <span>Likelihood: {finding.likelihood}</span>}
            {finding.cvss && <span className="font-mono text-slate-500">{finding.cvss.vector}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ title, icon, children }: { title: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-slate-500 font-semibold mb-1.5 flex items-center gap-1.5">
        {icon}
        {title}
      </div>
      {children}
    </div>
  );
}
