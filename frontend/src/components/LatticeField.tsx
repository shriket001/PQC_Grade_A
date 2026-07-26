/**
 * LatticeField — the signature element of the VAYUNX Grade A identity.
 *
 * Grade A's cryptography is *lattice*-based: ML-KEM-768 (key exchange) and
 * ML-DSA-65 (signatures) both reduce to the Shortest Vector / Learning With
 * Errors problems over a lattice. So the brand's defining visual is a lattice —
 * a regular point grid with a basis, not decoration.
 *
 * The component renders that grid and traces a single "key-handshake" path
 * across it: the visual analogue of the ML-KEM key exchange establishing a
 * shared secret. The trace is the only motion on the auth surface; it is paused
 * entirely when the viewer asks for reduced motion.
 */

interface LatticeFieldProps {
  /** Visually quieten the lattice for use as a background behind the form. */
  variant?: "feature" | "bg";
}

const CELL = 44;
const COLS = 7;
const ROWS = 9;

/** Deterministic handshake path — node indices walked left-to-right with
 *  deliberate rises and falls, encoding a real exchange rather than a doodle. */
const TRACE_NODES: ReadonlyArray<[number, number]> = [
  [0, 6],
  [1, 3],
  [2, 5],
  [3, 1],
  [4, 4],
  [5, 2],
  [6, 5],
];

function point([col, row]: [number, number]): [number, number] {
  return [col * CELL + CELL / 2, row * CELL + CELL / 2];
}

export function LatticeField({ variant = "feature" }: LatticeFieldProps): JSX.Element {
  const width = COLS * CELL;
  const height = ROWS * CELL;
  const dots: JSX.Element[] = [];
  for (let c = 0; c < COLS; c++) {
    for (let r = 0; r < ROWS; r++) {
      dots.push(
        <circle
          key={`${c}-${r}`}
          cx={c * CELL + CELL / 2}
          cy={r * CELL + CELL / 2}
          r={variant === "feature" ? 1.6 : 1.2}
          fill="var(--grid)"
        />,
      );
    }
  }

  const tracePoints = TRACE_NODES.map(point);
  const tracePath = tracePoints
    .map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`)
    .join(" ");

  return (
    <svg
      className={`lattice ${variant === "bg" ? "lattice--bg" : ""}`}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      focusable="false"
    >
      {dots}
      {/* Basis vectors drawn faintly from the origin — the lattice's defining
          structure, not decoration. */}
      <g stroke="var(--grid)" strokeWidth={1}>
        <line x1={CELL / 2} y1={CELL / 2} x2={CELL / 2 + CELL} y2={CELL / 2} />
        <line x1={CELL / 2} y1={CELL / 2} x2={CELL / 2} y2={CELL / 2 + CELL} />
      </g>
      <path
        d={tracePath}
        fill="none"
        stroke="var(--signal)"
        strokeWidth={variant === "feature" ? 2 : 1.4}
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeDasharray="360"
        strokeDashoffset={0}
        className="lattice__trace"
        opacity={variant === "feature" ? 0.85 : 0.55}
      />
      <circle r={variant === "feature" ? 4 : 3} fill="var(--signal)" className="lattice__head">
        <animateMotion dur="5.4s" repeatCount="indefinite" path={tracePath} />
      </circle>
    </svg>
  );
}
