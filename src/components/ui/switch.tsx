import * as React from "react";

import { cn } from "@/lib/utils";

type SwitchProps = Omit<React.InputHTMLAttributes<HTMLInputElement>, "type" | "role" | "children"> & {
  onCheckedChange?: (checked: boolean) => void;
};

// Native checked/defaultChecked state avoids a separately optimized React hook
// dependency while preserving keyboard, label and form behavior.
const Switch = React.forwardRef<HTMLInputElement, SwitchProps>(
  ({ className, onCheckedChange, onChange, ...props }, ref) => (
    <span className={cn("relative inline-flex h-5 w-9 shrink-0", className)}>
      <input
        {...props}
        ref={ref}
        type="checkbox"
        role="switch"
        className="peer absolute inset-0 z-10 m-0 h-full w-full cursor-pointer opacity-0 disabled:cursor-not-allowed"
        onChange={(event) => {
          onChange?.(event);
          onCheckedChange?.(event.currentTarget.checked);
        }}
      />
      <span aria-hidden="true" className="pointer-events-none inline-flex h-5 w-9 items-center rounded-full border-2 border-transparent bg-input shadow-sm transition-colors peer-checked:bg-primary peer-focus-visible:ring-2 peer-focus-visible:ring-ring peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-background peer-disabled:opacity-50 peer-checked:[&>span]:translate-x-4">
        <span className="block h-4 w-4 rounded-full bg-background shadow-lg ring-0 transition-transform motion-reduce:transition-none" />
      </span>
    </span>
  ),
);
Switch.displayName = "Switch";

export { Switch };
