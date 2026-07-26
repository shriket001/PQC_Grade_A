/** Generic key icon for "Sign in with SSO" — SAML/enterprise SSO has no
 * single universal brand mark the way Google does, so this is a plain,
 * neutral stand-in rather than any specific provider's logo. */
export function SsoIcon(): JSX.Element {
  return (
    <svg
      className="btn-icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      aria-hidden="true"
    >
      <circle cx="8" cy="15" r="4" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M10.8 12.2 20 3M15.5 7.5l3 3M12.7 10.3l2 2" />
    </svg>
  );
}
