export interface BreachDetail {
  name: string;
  domain: string;
  date: string;
  description: string;
  logo: string;
  passwordRisk: string;
  dataExposed: string[];
  records: number;
  verified: boolean;
}

export interface EmailBreachReport {
  ok: true;
  email: string;
  clean: boolean;
  breachCount: number;
  breachNames: string[];
  breaches: BreachDetail[];
  dataTypesLeaked: string[];
  passwordExposedCount: number;
  firstBreachYear: number | null;
  riskLabel: string | null;
  riskScore: number | null;
  passwordStrength: {
    EasyToCrack: number;
    PlainText: number;
    StrongHash: number;
    Unknown: number;
  } | null;
  pastesCount: number;
}

export interface EmailBreachError {
  ok: false;
  error: string;
  rateLimited?: boolean;
}

export type EmailBreachResult = EmailBreachReport | EmailBreachError;

export interface DomainProbeResult {
  email: string;
  result: EmailBreachResult;
}

export interface DomainBreachReport {
  mode: "domain";
  domain: string;
  probes: DomainProbeResult[];
  hitCount: number;
  totalProbed: number;
  combinedBreaches: BreachDetail[];
  dataTypesLeaked: string[];
  firstBreachYear: number | null;
}

export type ScanMode = "email" | "domain";

export interface BreachLogEntry {
  id: string;
  createdAt: number;
  mode: ScanMode;
  query: string;
  clean: boolean;
  breachCount: number;
  label: string;
}
