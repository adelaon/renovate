/*
 * Detects if any CI status check names appear to be test-related
*/
export function hasTestChecks(checkNames: string[]): boolean {
  if (!checkNames || checkNames.length === 0) {
    return false;
  }

  // Exclude patterns which are not test-related
  const excludePatterns = [
    'renovate/',
    'dependabot',
    'codecov/',
    'coveralls',
    'vercel',
    'netlify',
    'chromatic',
    'percy',
    'snyk',
    'fossa',
    'mergify',
    'bors',
  ];

  const relevantChecks = checkNames.filter(name => {
    const lowerName = name.toLowerCase();
    return !excludePatterns.some(pattern => lowerName.includes(pattern));
  });

  return relevantChecks.length > 0;
}
