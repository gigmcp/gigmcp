import type { SVGProps } from "react";

/**
 * gigmcp mark: five lines converging to a single point at the right.
 * Drawn on a 1024×1024 grid; viewBox tightly cropped to the painted
 * extents (stroke 26, butt caps) plus a small margin.
 */
export function Logo({ className, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="205 303 612 410"
      fill="none"
      stroke="currentColor"
      strokeWidth={26}
      strokeLinecap="butt"
      aria-hidden="true"
      className={className}
      {...props}
    >
      <line x1={375} y1={325} x2={800} y2={510} />
      <line x1={425} y1={425} x2={800} y2={510} />
      <line x1={215} y1={510} x2={800} y2={510} />
      <line x1={425} y1={597} x2={800} y2={510} />
      <line x1={375} y1={690} x2={800} y2={510} />
    </svg>
  );
}
