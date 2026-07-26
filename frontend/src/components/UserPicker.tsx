/**
 * UserPicker — searchable username autocomplete (single or multi-select).
 *
 * Replaces raw manual-entry text fields for "who do I want to message / add"
 * flows (New Conversation, group member selection) with a proper directory
 * picker: type 2+ characters, see a debounced, rate-limit-friendly dropdown of
 * matching registered usernames (FR-053 prefix search), and select with the
 * mouse or keyboard instead of hand-typing an exact handle.
 *
 * Multi-select renders chosen users as removable chips inside the field.
 * Single-select swaps the input for the chosen user's chip once picked.
 */

import { useEffect, useMemo, useRef, useState } from "react";

import { searchUsers } from "@/services/userService";
import type { UserSummaryResponse } from "@/types/user";

const SEARCH_DEBOUNCE_MS = 220;
const MIN_QUERY_LENGTH = 2;

export interface UserPickerProps {
  mode: "single" | "multi";
  label: string;
  placeholder?: string;
  selected: UserSummaryResponse[];
  onChange: (selected: UserSummaryResponse[]) => void;
  /** User ids to never offer (e.g. the signed-in user, or already-a-member ids). */
  excludeIds?: string[];
  disabled?: boolean;
  id?: string;
}

export function UserPicker(props: UserPickerProps): JSX.Element {
  const {
    mode,
    label,
    placeholder,
    selected,
    onChange,
    excludeIds = [],
    disabled = false,
    id,
  } = props;

  const [query, setQuery] = useState("");
  const [results, setResults] = useState<UserSummaryResponse[]>([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [highlighted, setHighlighted] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const requestSeq = useRef(0);

  const selectedIds = useMemo(() => new Set(selected.map((u) => u.id)), [selected]);
  const excludeSet = useMemo(() => new Set(excludeIds), [excludeIds]);

  // Debounced search as the user types; a stale response arriving after a
  // newer one is discarded via a monotonically increasing request sequence.
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    const trimmed = query.trim();
    if (trimmed.length < MIN_QUERY_LENGTH) {
      setResults([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    const seq = ++requestSeq.current;
    debounceRef.current = setTimeout(() => {
      void searchUsers(trimmed)
        .then((hits) => {
          if (requestSeq.current !== seq) return; // superseded by a newer keystroke
          setResults(hits.filter((h) => !selectedIds.has(h.id) && !excludeSet.has(h.id)));
          setHighlighted(0);
        })
        .catch(() => {
          if (requestSeq.current === seq) setResults([]);
        })
        .finally(() => {
          if (requestSeq.current === seq) setLoading(false);
        });
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- selectedIds/excludeSet are derived, re-filtering on them alone would refire the network call unnecessarily
  }, [query]);

  // Close the dropdown on an outside click.
  useEffect(() => {
    function onDocMouseDown(e: MouseEvent): void {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onDocMouseDown);
    return () => document.removeEventListener("mousedown", onDocMouseDown);
  }, []);

  function commitSelection(user: UserSummaryResponse): void {
    if (mode === "single") {
      onChange([user]);
      setQuery("");
      setOpen(false);
    } else {
      onChange([...selected, user]);
      setQuery("");
      setResults((r) => r.filter((u) => u.id !== user.id));
      inputRef.current?.focus();
    }
  }

  function removeSelected(userId: string): void {
    onChange(selected.filter((u) => u.id !== userId));
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>): void {
    if (!open || results.length === 0) {
      if (e.key === "Backspace" && query === "" && mode === "multi" && selected.length) {
        removeSelected(selected[selected.length - 1].id);
      }
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlighted((h) => Math.min(h + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlighted((h) => Math.max(h - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const hit = results[highlighted];
      if (hit) commitSelection(hit);
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  }

  const showSingleChip = mode === "single" && selected.length > 0;
  const inputId = id ?? label.toLowerCase().replace(/\s+/g, "-");

  return (
    <div className="picker" ref={containerRef}>
      <label className="field__label" htmlFor={inputId}>
        {label}
      </label>

      <div className={`picker__control${disabled ? " picker__control--disabled" : ""}`}>
        {mode === "multi" && selected.length > 0 ? (
          <ul className="picker__chips" aria-label={`Selected for ${label}`}>
            {selected.map((u) => (
              <li key={u.id} className="picker__chip">
                <span className="mono">{u.username}</span>
                {!disabled ? (
                  <button
                    type="button"
                    className="picker__chip-remove"
                    onClick={() => removeSelected(u.id)}
                    aria-label={`Remove ${u.username}`}
                  >
                    ×
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}

        {showSingleChip ? (
          <span className="picker__single-chip">
            <span className="mono">{selected[0].username}</span>
            {!disabled ? (
              <button
                type="button"
                className="picker__chip-remove"
                onClick={() => onChange([])}
                aria-label={`Clear ${selected[0].username}`}
              >
                ×
              </button>
            ) : null}
          </span>
        ) : (
          <input
            ref={inputRef}
            id={inputId}
            className="input picker__input"
            type="text"
            role="combobox"
            aria-expanded={open}
            aria-autocomplete="list"
            autoComplete="off"
            placeholder={placeholder}
            value={query}
            disabled={disabled}
            onChange={(e) => {
              setQuery(e.target.value);
              setOpen(true);
            }}
            onFocus={() => setOpen(true)}
            onKeyDown={handleKeyDown}
          />
        )}

        {loading ? <span className="picker__spinner" aria-hidden="true" /> : null}
      </div>

      {open && !showSingleChip ? (
        <ul className="picker__dropdown" role="listbox">
          {query.trim().length < MIN_QUERY_LENGTH ? (
            <li className="picker__dropdown-empty">Type at least 2 characters…</li>
          ) : loading ? (
            <li className="picker__dropdown-empty">Searching…</li>
          ) : results.length === 0 ? (
            <li className="picker__dropdown-empty">No matching users</li>
          ) : (
            results.map((u, i) => (
              <li key={u.id} role="option" aria-selected={i === highlighted}>
                <button
                  type="button"
                  className={`picker__option${i === highlighted ? " picker__option--active" : ""}`}
                  onMouseEnter={() => setHighlighted(i)}
                  onMouseDown={(e) => {
                    // mousedown (not click) so the input's blur doesn't close
                    // the dropdown before the selection registers.
                    e.preventDefault();
                    commitSelection(u);
                  }}
                >
                  <span className="picker__option-username mono">{u.username}</span>
                  {u.display_name && u.display_name !== u.username ? (
                    <span className="picker__option-name">{u.display_name}</span>
                  ) : null}
                </button>
              </li>
            ))
          )}
        </ul>
      ) : null}
    </div>
  );
}
