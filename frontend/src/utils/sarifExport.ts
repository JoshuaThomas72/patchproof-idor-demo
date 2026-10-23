import { SecurityFinding, RecentScan } from '../types';

export function generateSarifReport(scan: RecentScan, findings: SecurityFinding[]) {
  const sarifData = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'PatchProof Security Engine',
            version: '2.4.0-apple',
            informationUri: 'https://patchproof.dev',
            rules: findings.map((f) => ({
              id: f.ruleId,
              name: f.title,
              shortDescription: {
                text: f.title,
              },
              fullDescription: {
                text: f.description,
              },
              helpUri: `https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html`,
              properties: {
                category: f.category,
                cwe: f.cwe,
                severity: f.severity,
                verifiedByPytest: f.verificationStatus === 'Verified Fixed',
              },
            })),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: new Date(scan.scanDate).toISOString(),
            toolExecutionNotifications: [],
          },
        ],
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: f.severity === 'Critical' || f.severity === 'High' ? 'error' : 'warning',
          message: {
            text: `${f.title}: ${f.aiExplanation.summary}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.filePath,
                },
                region: {
                  startLine: f.lineNumber,
                  endLine: f.endLineNumber || f.lineNumber,
                },
              },
            },
          ],
          properties: {
            confidence: f.confidence,
            verificationStatus: f.verificationStatus,
            aiReasoningEngine: f.aiExplanation.suggestedByModel,
            remediationDiff: f.patchDiff,
          },
        })),
      },
    ],
  };

  return sarifData;
}

export function downloadJsonFile(filename: string, data: unknown) {
  const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(
    JSON.stringify(data, null, 2)
  )}`;
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', jsonString);
  downloadAnchor.setAttribute('download', filename);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

export function downloadDiffFile(filename: string, diffText: string) {
  const blob = new Blob([diffText], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', url);
  downloadAnchor.setAttribute('download', filename);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
  URL.revokeObjectURL(url);
}
