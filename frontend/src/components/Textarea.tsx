import { useLayoutEffect, useRef } from "react";
import type { ReactNode, TextareaHTMLAttributes } from "react";

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: ReactNode;
  invalid?: boolean;
}

/** Auto-resizing textarea, grows with content up to a CSS max-height clamp. */
export function Textarea({
  label,
  hint,
  invalid = false,
  id,
  className,
  value,
  onChange,
  ...rest
}: TextareaProps): JSX.Element {
  const ref = useRef<HTMLTextAreaElement>(null);
  const inputId = id ?? rest.name;

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, [value]);

  const textarea = (
    <textarea
      {...rest}
      ref={ref}
      id={inputId}
      value={value}
      onChange={onChange}
      rows={1}
      className={["input", "textarea", className ?? ""].filter(Boolean).join(" ")}
      aria-invalid={invalid || undefined}
    />
  );

  if (!label) return textarea;

  return (
    <div className="field">
      <label className="field__label" htmlFor={inputId}>
        {label}
      </label>
      {textarea}
      {hint ? <span className="field__hint">{hint}</span> : null}
    </div>
  );
}
