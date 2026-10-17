// Build-time brand fallback for the shell.
//
// The live brand is operator-editable (settings → Application name) and
// arrives per request from /api/v1/config; this is the value the shell falls
// back to before that response, and the one it must show when the response
// cannot be read at all (#2178). Kept in one place because it was previously
// spelled as a bare 'APIARY' literal in four spots in __root.tsx, which is
// four chances for a rebrand to miss one.
export const APP_CONFIG = {
  name: 'APIARY',
  meta: {
    title: 'APIARY',
    description:
      'Defensive security operations dashboard — honeypot, sensor and campaign telemetry in one view.',
  },
}
