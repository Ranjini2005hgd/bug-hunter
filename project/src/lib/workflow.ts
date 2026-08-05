import type { WorkflowStep, WorkflowState } from './types';

export const WORKFLOW_STEPS: { step: WorkflowStep; label: string; description: string }[] = [
  { step: 'scope-validation', label: 'Scope Validation', description: 'Verify the target is within authorized scope' },
  { step: 'reconnaissance', label: 'Reconnaissance', description: 'Build inventory of authorized assets and technologies' },
  { step: 'asset-discovery', label: 'Asset Discovery', description: 'Discover subdomains, APIs, and JavaScript resources' },
  { step: 'endpoint-mapping', label: 'Endpoint Mapping', description: 'Map URLs, parameters, and response metadata' },
  { step: 'vulnerability-testing', label: 'Vulnerability Testing', description: 'Test endpoints against vulnerability classes' },
  { step: 'ai-analysis', label: 'AI Analysis', description: 'Classify findings by confidence and impact' },
  { step: 'evidence-collection', label: 'Evidence Collection', description: 'Capture HTTP requests, responses, and PoC' },
  { step: 'severity-assessment', label: 'Severity Assessment', description: 'Assign CVSS scores and OWASP categories' },
  { step: 'report-generation', label: 'Report Generation', description: 'Generate professional reports and evidence packages' },
  { step: 'human-review', label: 'Human Review', description: 'Final review before submission' },
];

export function createInitialWorkflowState(): WorkflowState {
  const stepStatus = {} as Record<WorkflowStep, 'pending' | 'in-progress' | 'completed' | 'skipped'>;
  for (const item of WORKFLOW_STEPS) {
    stepStatus[item.step] = 'pending';
  }
  return {
    currentStep: 'scope-validation',
    completedSteps: [],
    stepStatus,
    startedAt: new Date().toISOString(),
    stepTimings: {},
  };
}

export function advanceWorkflow(state: WorkflowState, to: WorkflowStep): WorkflowState {
  const completedSteps = [...state.completedSteps];
  if (!completedSteps.includes(state.currentStep)) {
    completedSteps.push(state.currentStep);
  }
  const stepStatus = { ...state.stepStatus, [state.currentStep]: 'completed' as const, [to]: 'in-progress' as const };
  return {
    ...state,
    currentStep: to,
    completedSteps,
    stepStatus,
  };
}

export function completeWorkflow(state: WorkflowState): WorkflowState {
  const completedSteps = state.completedSteps.includes(state.currentStep) ? state.completedSteps : [...state.completedSteps, state.currentStep];
  const stepStatus = { ...state.stepStatus, [state.currentStep]: 'completed' as const };
  return {
    ...state,
    completedSteps,
    stepStatus,
  };
}

export function getStepIndex(step: WorkflowStep): number {
  return WORKFLOW_STEPS.findIndex((s) => s.step === step);
}

export function getProgressPercent(state: WorkflowState): number {
  const total = WORKFLOW_STEPS.length;
  const completed = state.completedSteps.length;
  return Math.round((completed / total) * 100);
}
