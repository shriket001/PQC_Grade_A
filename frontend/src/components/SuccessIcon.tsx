/** Small circular check mark used above "you're done" success states. */
export function SuccessIcon(): JSX.Element {
  return (
    <span className="success-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 12.5 10 17.5 19 7" />
      </svg>
    </span>
  );
}
