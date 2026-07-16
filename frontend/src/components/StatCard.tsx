interface Props {
  label: string;
  value: number | string;
  tone: "critical" | "high" | "medium" | "low" | "info";
}

const TONES: Record<Props["tone"], string> = {
  critical: "text-red-400 border-red-900/40",
  high: "text-orange-400 border-orange-900/40",
  medium: "text-blue-400 border-blue-900/40",
  low: "text-gray-300 border-gray-700",
  info: "text-accent border-accent/30",
};

export function StatCard({ label, value, tone }: Props) {
  return (
    <div className={`card border ${TONES[tone]}`}>
      <div className="text-2xl font-bold tabular-nums">{value}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-gray-500">{label}</div>
    </div>
  );
}
