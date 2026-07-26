import type { InputHTMLAttributes, ReactNode } from "react";

interface FormFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: ReactNode;
  /** When true, renders the input in monospace (tokens, codes). */
  mono?: boolean;
  /** When true, sets aria-invalid and the error styling. */
  invalid?: boolean;
}

export function FormField({
  label,
  hint,
  mono = false,
  invalid = false,
  id,
  className,
  ...rest
}: FormFieldProps): JSX.Element {
  const inputId = id ?? rest.name;
  return (
    <div className="field">
      <label className="field__label" htmlFor={inputId}>
        {label}
      </label>
      <input
        {...rest}
        id={inputId}
        className={["input", mono ? "input--mono" : "", className ?? ""].filter(Boolean).join(" ")}
        aria-invalid={invalid || undefined}
      />
      {hint ? <span className="field__hint">{hint}</span> : null}
    </div>
  );
}
