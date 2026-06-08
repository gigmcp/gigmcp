"use client";
import { useEffect, useRef, useState } from "react";
import { useFormatter, useTranslations } from "next-intl";
import type { HeatmapDay } from "@/lib/types";
import { cn } from "@/lib/utils";

// Five intensity buckets on a GitHub-style blue ramp. Level 0 = visible empty tile.
const LEVELS = [
  "bg-blue-500/10 dark:bg-blue-400/10 ring-1 ring-inset ring-blue-500/15 dark:ring-blue-400/15",
  "bg-blue-500/30 dark:bg-blue-400/30",
  "bg-blue-500/50 dark:bg-blue-400/50",
  "bg-blue-500/75 dark:bg-blue-400/75",
  "bg-blue-600 dark:bg-blue-400",
] as const;

// Cell metrics: size-3.5 = 14px tile, gap-1 = 4px gap → 18px stride per cell.
const CELL = 14;
const GAP = 4;
const STRIDE = CELL + GAP;

function level(count: number, max: number): number {
  if (count <= 0 || max <= 0) return 0;
  const ratio = count / max;
  if (ratio > 0.75) return 4;
  if (ratio > 0.5) return 3;
  if (ratio > 0.25) return 2;
  return 1;
}

// fitCount: how many whole cells (incl. their gaps) fit in content width w.
// N cells span N*CELL + (N-1)*GAP = N*STRIDE - GAP, so N = floor((w + GAP) / STRIDE).
function fitCount(w: number): number {
  return Math.max(1, Math.floor((w + GAP) / STRIDE));
}

export function ActivityHeatmap({ days }: { days: HeatmapDay[] }) {
  const t = useTranslations("overview");
  const format = useFormatter();
  const rowRef = useRef<HTMLDivElement>(null);
  // Pre-measure: render all days (overflow-hidden clips) to avoid a layout jump,
  // then trim to the measured fitting count.
  const [count, setCount] = useState(days.length);

  useEffect(() => {
    const el = rowRef.current;
    if (!el) return;
    const measure = () => setCount(fitCount(el.clientWidth));
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const visible = days.slice(Math.max(0, days.length - count));
  const max = visible.reduce((m, d) => Math.max(m, d.count), 0);

  return (
    <div>
      <h2 className="mb-3 text-base font-semibold tracking-tight">
        {t("heatmap.title")}
      </h2>
      <div className="rounded-lg border border-border p-4">
        <div ref={rowRef} className="flex justify-end gap-1 overflow-hidden">
          {visible.map((d) => (
            <div
              key={d.date}
              title={t("heatmap.cell", {
                date: format.dateTime(new Date(d.date), { dateStyle: "medium" }),
                count: d.count,
              })}
              className={cn("size-3.5 shrink-0 rounded-sm", LEVELS[level(d.count, max)])}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
