import type { ScannedProject } from '@snyk/cli-interface/legacy/common';

import { buildDepGraph } from './dep-graph';
import { ParseContext, FingerprintData, MavenGraph } from './types';

export function buildScannedProjects(
  mavenGraphs: MavenGraph[],
  includeTestScope = false,
  verboseEnabled = false,
  fingerprintMap = new Map<string, FingerprintData>(),
  includePurl = false,
  sbomMavenScopeProperties = false,
): { scannedProjects: ScannedProject[] } {
  // When sbomMavenScopeProperties is enabled, we need to include test scope
  // dependencies to properly analyze and label all Maven scopes for SBOM purposes
  const effectiveIncludeTestScope = includeTestScope || sbomMavenScopeProperties;
  
  const context: ParseContext = {
    includeTestScope: effectiveIncludeTestScope,
    verboseEnabled,
    fingerprintMap,
    includePurl,
    sbomMavenScopeProperties,
  };

  const scannedProjects: ScannedProject[] = [];
  for (const mavenGraph of mavenGraphs) {
    const depGraph = buildDepGraph(mavenGraph, context);
    scannedProjects.push({ depGraph });
  }

  return { scannedProjects };
}
