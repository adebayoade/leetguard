export interface PackageDependency {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  dependencies?: Record<string, string>;
}

export interface LockfileData {
  name: string;
  version: string;
  lockfileVersion: number;
  dependencies: Map<string, PackageDependency>;
}

export type AntiPatternCategory =
  | 'Injection & Dynamic Execution'
  | 'Data Exposure'
  | 'Transport & Communication'
  | 'React Native Mobile Risks'
  | 'Supply Chain Risk';

export interface Finding {
  category: AntiPatternCategory;
  patternName: string;
  severity: 'High' | 'Medium' | 'Low';
  description: string;
  isoControl: string;
  location?: string;
}

export interface SecurityReport {
  timestamp: string;
  scannedDirectory: string;
  totalDependencies: number;
  vulnerabilities: Finding[];
  abandonedPackages: Finding[];
  codeAntiPatterns: Finding[];
}
