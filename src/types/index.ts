export interface PackageDependency {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  peer?: boolean;
  peerOptional?: boolean;
  dependencies?: Record<string, string>;
  trace?: string[];
}

export interface LockfileData {
  name: string;
  version: string;
  lockfileVersion: number;
  dependencies: Map<string, PackageDependency>;
  rootDependencies?: Record<string, string>;
}

export type AntiPatternCategory =
  | 'Injection & Dynamic Execution'
  | 'Data Exposure'
  | 'Transport & Communication'
  | 'React Native Mobile Risks'
  | 'Supply Chain Risk';

export interface Finding {
  category: AntiPatternCategory;
  id: string;
  severity: string;
  isoControl: string;
  packageName?: string;
  packageVersion?: string;
  summary?: string;
  details?: string;
  weakage?: any;
  location?: string;
  traces?: string[][];
  cvss?: {
    score: number;
    vectorString: string;
  };
  cwe?: string[];
  aliases?: string[];
  isDirect?: boolean;
  fixAvailable: boolean;
  fixedVersions?: string[];
  url?: string;
}

export interface ReportMetadata {
  vulnerabilities: {
    info: number;
    low: number;
    moderate: number;
    high: number;
    critical: number;
    total: number;
  };
  dependencies: {
    prod: number;
    dev: number;
    optional?: number;
    peer?: number;
    peerOptional?: number;
    total: number;
  };
}

export interface SecurityReport {
  timestamp: string;
  scannedDirectory: string;
  totalDependencies: number;
  directDependenciesCount: number;
  transitiveDependenciesCount: number;
  metadata?: ReportMetadata;
  vulnerabilities: Finding[];
  abandonedPackages: Finding[];
  codeAntiPatterns: Finding[];
}
