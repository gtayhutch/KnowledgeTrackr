import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";

/** Primary action. Looks like a printed label, not a marketing button. */
export function Button({
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={`inline-flex h-10 items-center justify-center rounded-md bg-pine px-4 text-sm text-pine-ink hover:bg-pine/90 disabled:opacity-50 ${className}`}
      {...props}
    />
  );
}

/** Secondary action on the paper background. */
export function QuietButton({
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={`inline-flex h-10 items-center justify-center rounded-md border border-rule bg-paper px-4 text-sm hover:bg-white disabled:opacity-50 ${className}`}
      {...props}
    />
  );
}

/** Single-line field. */
export function Input({
  className = "",
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`h-10 w-full rounded-md border border-rule bg-white px-3 text-sm outline-none focus:border-pine ${className}`}
      {...props}
    />
  );
}

/** Article body. */
export function TextArea({
  className = "",
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={`min-h-64 w-full rounded-md border border-rule bg-white px-3 py-2 text-sm outline-none focus:border-pine ${className}`}
      {...props}
    />
  );
}

/** Form label tied to a control. */
export function Label({
  htmlFor,
  children,
}: {
  htmlFor: string;
  children: string;
}) {
  return (
    <label htmlFor={htmlFor} className="mb-1 block text-sm">
      {children}
    </label>
  );
}
