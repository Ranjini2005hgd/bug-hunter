// ============================================================
// BugHunter Pro — Type System
// Full security assessment platform types
// ============================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Category = 'security' | 'accessibility' | 'seo' | 'performance' | 'best-practices' | 'pwa' | 'code';
export type Confidence = 'confirmed' | 'certain' | 'high' | 'medium' | 'low';
export type FindingStatus = 'potential' | 'confirmed' | 'false-positive' | 'needs-verification' | 'certain';

// --- Workflow ---
export type WorkflowStep =
  | 'scope-validation'
  | 'reconnaissance'
  | 'asset-discovery'
  | 'endpoint-mapping'
  | 'vulnerability-testing'
  | 'ai-analysis'
  | 'evidence-collection'
  | 'severity-assessment'
  | 'report-generation'
  | 'human-review';

export interface WorkflowState {
  currentStep: WorkflowStep;
  completedSteps: WorkflowStep[];
  stepStatus: Record<WorkflowStep, 'pending' | 'in-progress' | 'completed' | 'skipped'>;
  startedAt: string;
  stepTimings: Record<string, number>;
}

// --- Scope ---
export interface AssessmentScope {
  programName: string;
  targetDomains: string[];
  inScopeAssets: string[];
  outOfScopeAssets: string[];
  authAvailable: boolean;
  programRules: string;
  rateLimit: string;
  testingRestrictions: string;
}

// --- Reconnaissance ---
export interface TechnologyFingerprint {
  name: string;
  category: string;
  version?: string;
  confidence: 'certain' | 'high' | 'medium';
  evidence: string;
}

export interface DiscoveredAsset {
  id: string;
  type: 'subdomain' | 'webapp' | 'api' | 'javascript' | 'endpoint' | 'dns';
  url: string;
  method?: string;
  status?: number;
  contentType?: string;
  authRequired: boolean;
  parameters?: string[];
  relatedEndpoints?: string[];
}

export interface EndpointInfo {
  id: string;
  url: string;
  method: string;
  parameters: string[];
  headers: Record<string, string>;
  cookies: string[];
  authRequired: boolean;
  responseCode: number;
  contentType: string;
  relatedEndpoints: string[];
}

export interface ReconResult {
  technologies: TechnologyFingerprint[];
  assets: DiscoveredAsset[];
  endpoints: EndpointInfo[];
  dnsInfo: DnsInfo;
  javascriptResources: string[];
  publicEndpoints: string[];
  subdomains?: SubdomainResult[];
  secrets?: SecretFinding[];
  jsAnalysis?: JsAnalysisResult;
  directoryScan?: DirectoryScanResult[];
}

export interface SubdomainResult {
  id: string;
  hostname: string;
  source: string;
  ip?: string;
  status?: number;
  title?: string;
  open: boolean;
}

export interface SecretFinding {
  id: string;
  type: string;
  value: string;
  file: string;
  line: number;
  severity: Severity;
  description: string;
}

export interface JsAnalysisResult {
  files: JsFileAnalysis[];
  totalFiles: number;
  totalSize: number;
  endpoints: string[];
  secrets: SecretFinding[];
}

export interface JsFileAnalysis {
  url: string;
  size: number;
  hasSourceMap: boolean;
  frameworks: string[];
  endpoints: string[];
  secrets: SecretFinding[];
}

export interface DirectoryScanResult {
  path: string;
  url: string;
  status: number;
  size: number;
  redirect: boolean;
  redirectUrl?: string;
  contentType?: string;
  interesting: boolean;
}

export interface DnsInfo {
  hostname: string;
  ips: string[];
  nameservers: string[];
  txtRecords: string[];
}

// --- CVSS 3.1 ---
export interface CvssVector {
  attackVector: 'network' | 'adjacent' | 'local' | 'physical';
  attackComplexity: 'low' | 'high';
  privilegesRequired: 'none' | 'low' | 'high';
  userInteraction: 'none' | 'required';
  scope: 'unchanged' | 'changed';
  confidentiality: 'none' | 'low' | 'high';
  integrity: 'none' | 'low' | 'high';
  availability: 'none' | 'low' | 'high';
}

export interface CvssResult {
  score: number;
  severity: Severity;
  vector: string;
}

// --- Evidence ---
export interface EvidencePackage {
  findingId: string;
  screenshots: EvidenceArtifact[];
  httpRequests: EvidenceArtifact[];
  httpResponses: EvidenceArtifact[];
  proofOfConcept: string;
  reproductionSteps: string[];
  metadata: EvidenceMetadata;
}

export interface EvidenceArtifact {
  id: string;
  type: 'screenshot' | 'request' | 'response' | 'poc' | 'log' | 'video';
  filename: string;
  content: string;
  mimeType: string;
  timestamp: string;
  dataUrl?: string;
}

export type VulnerabilityClass =
  | 'remote-code-execution'
  | 'sql-injection'
  | 'xss-stored'
  | 'xss-reflected'
  | 'account-takeover'
  | 'idor'
  | 'payment-bypass'
  | 'security-misconfiguration'
  | 'information-disclosure'
  | 'cryptographic-failure'
  | 'access-control'
  | 'injection'
  | 'other';

export interface EvidenceMetadata {
  timestamp: string;
  affectedEndpoint: string;
  httpMethod: string;
  parameters: string[];
  authState: string;
  evidenceIds: string[];
}

// --- Finding (upgraded) ---
export interface Reference {
  label: string;
  url: string;
}

export interface MediaEvidence {
  screenshots: ScreenshotEvidence[];
  videoRecording?: VideoEvidence;
}

export interface ScreenshotEvidence {
  id: string;
  dataUrl: string;
  filename: string;
  caption: string;
  timestamp: string;
}

export interface VideoEvidence {
  id: string;
  dataUrl: string;
  filename: string;
  duration: number;
  timestamp: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  category: Category;
  severity: Severity;
  status?: FindingStatus;
  confidence: Confidence;
  title: string;
  description: string;
  evidence?: string;
  location?: string;
  impact: string;
  recommendation: string;
  fixSteps: string[];
  codeBefore?: string;
  codeAfter?: string;
  references: Reference[];
  cweId?: string;
  wcagLevel?: string;
  owaspCategory?: string;
  vulnerabilityClass?: VulnerabilityClass;
  mediaEvidence?: MediaEvidence;
  cvss?: CvssResult;
  affectedAsset?: string;
  affectedEndpoint?: string;
  prerequisites?: string;
  likelihood?: 'low' | 'medium' | 'high';
  evidencePackage?: Partial<EvidencePackage>;
  timeline?: TimelineEntry[];
  aiExplanation?: AiExplanation;
}

export interface TimelineEntry {
  timestamp: string;
  event: string;
  detail?: string;
}

// --- Assessment (top-level) ---
export interface CategoryCount {
  security: number;
  accessibility: number;
  seo: number;
  performance: number;
  'best-practices': number;
  pwa: number;
  code: number;
}

export interface SeverityCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface PageStats {
  htmlSizeBytes: number;
  loadTimeMs: number;
  numScripts: number;
  numStylesheets: number;
  numImages: number;
  numLinks: number;
  numForms: number;
  redirectCount: number;
  hasRobotsTxt: boolean;
  hasSitemapXml: boolean;
  hasHttps: boolean;
  protocol: string;
}

export interface Assessment {
  id: string;
  scope: AssessmentScope;
  workflow: WorkflowState;
  recon: ReconResult;
  url: string;
  finalUrl: string;
  status: number;
  statusText: string;
  score: number;
  grade: string;
  totalIssues: number;
  severityCounts: SeverityCount;
  categoryCounts: CategoryCount;
  findings: Finding[];
  pageStats: PageStats;
  scannedAt: string;
  compliance: ComplianceReport;
}

export interface ComplianceReport {
  gdpr: ComplianceItem[];
  pciDss: ComplianceItem[];
  hipaa: ComplianceItem[];
  iso27001: ComplianceItem[];
}

export interface ComplianceItem {
  control: string;
  status: 'pass' | 'fail' | 'warning' | 'n/a';
  finding?: string;
  description: string;
}

// --- Legacy compat (ScanResult maps to Assessment for existing code) ---
export type ScanResult = Assessment;

// --- Fetch ---
export interface FetchResult {
  url: string;
  finalUrl: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  html: string;
  timingMs: number;
  redirectChain: string[];
  robots: { status: number; content: string } | null;
  sitemap: { status: number; content: string } | null;
  securityTxt?: { status: number; content: string } | null;
  dns?: { hostname: string; ips: string[]; txtRecords: string[] };
  fetchedAt: string;
  error?: string;
}

export interface ScanContext {
  document: Document;
  html: string;
  headers: Record<string, string>;
  url: string;
  finalUrl: string;
  robots: { status: number; content: string } | null;
  sitemap: { status: number; content: string } | null;
  isHttps: boolean;
}

export type Checker = (ctx: ScanContext) => Finding[];

// --- Code Analysis ---
export type CodeLanguage = 'javascript' | 'typescript' | 'python' | 'java' | 'php' | 'go' | 'ruby' | 'csharp' | 'generic';

export interface CodeFinding {
  id: string;
  ruleId: string;
  language: CodeLanguage;
  severity: Severity;
  title: string;
  description: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  impact: string;
  recommendation: string;
  fixSteps: string[];
  codeBefore?: string;
  codeAfter?: string;
  references: Reference[];
  cweId?: string;
  owaspCategory?: string;
  confidence: Confidence;
}

export interface CodeAnalysisResult {
  findings: CodeFinding[];
  language: CodeLanguage;
  totalLines: number;
  linesScanned: number;
  scanDuration: number;
}

export type ScanMode = 'website' | 'code';

// --- Formal Submission Report ---
export interface FormalSubmissionReport {
  reportId: string;
  programName: string;
  researcherName: string;
  researcherEmail: string;
  submissionDate: string;
  targetUrl: string;
  scope: AssessmentScope;
  findings: Finding[];
  executiveSummary: string;
  riskRating: Severity;
  cvssMax: number;
  disclaimer: string;
  confidentialityNotice: string;
}

// --- Monitoring ---
export interface SystemHealth {
  status: 'operational' | 'degraded' | 'down';
  edgeFunctionLatency: number;
  databaseLatency: number;
  activeScans: number;
  totalScansCompleted: number;
  uptime: string;
}

// --- Bug Recorder ---
export type BugStatus = 'open' | 'triaged' | 'fixed' | 'duplicate';

export type RecordingAction =
  | 'navigate'
  | 'click'
  | 'input'
  | 'scroll'
  | 'screenshot'
  | 'http-request'
  | 'note';

export interface RecordingStep {
  id: string;
  timestamp: string;
  relativeTime: number;
  action: RecordingAction;
  url: string;
  description: string;
  screenshotDataUrl?: string;
  httpEntryId?: string;
}

export interface HttpEntry {
  id: string;
  timestamp: string;
  url: string;
  method: string;
  status: number;
  statusText: string;
  duration: number;
  initiatorType: string;
  transferSize: number;
  encodedBodySize: number;
  decodedBodySize: number;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
}

export interface BugRecord {
  id: string;
  bugId: string;
  title: string;
  severity: Severity;
  status: BugStatus;
  targetUrl: string;
  notes: string;
  vulnerabilityClass?: string;
  steps: RecordingStep[];
  httpEntries: HttpEntry[];
  recordingDuration: number;
  screenshotCount: number;
  videoBlobUrl?: string;
  screenshots: ScreenshotEvidence[];
  reportMarkdown: string;
  createdAt: string;
  updatedAt: string;
}

export interface AiExplanation {
  summary: string;
  attackScenario: string;
  remediationPriority: string;
  businessRisk: string;
  testingAdvice: string;
}
