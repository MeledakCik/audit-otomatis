export type OsintType = "domain" | "email" | "username" | "name";

export interface OsintLink {
  label: string;
  url: string;
  group?: string;
}

export type PlatformStatus = "found" | "not_found" | "unknown" | "manual";

export interface PlatformResult {
  platform: string;
  url: string;
  status: PlatformStatus;
  note?: string;
}

export interface DomainOsint {
  type: "domain";
  domain: string;
  dns: { a: string[]; aaaa: string[]; mx: string[]; ns: string[]; txt: string[] };
  rdap: {
    registrar?: string;
    created?: string;
    updated?: string;
    expires?: string;
    status?: string[];
  } | null;
  subdomains: string[];
  links: OsintLink[];
}

export interface EmailOsint {
  type: "email";
  email: string;
  validSyntax: boolean;
  domain: string;
  mx: string[];
  disposable: boolean;
  gravatar: { exists: boolean; url: string };
  links: OsintLink[];
}

export interface UsernameOsint {
  type: "username";
  username: string;
  platforms: PlatformResult[];
}

export interface NameOsint {
  type: "name";
  name: string;
  usernameGuesses: string[];
  links: OsintLink[];
}

export type OsintResult = DomainOsint | EmailOsint | UsernameOsint | NameOsint;
