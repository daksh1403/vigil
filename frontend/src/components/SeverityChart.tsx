"use client";

import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell } from "recharts";

interface Props {
  data: { critical: number; high: number; medium: number; low: number; info: number };
}

const COLORS = { critical: "#ef4444", high: "#f97316", medium: "#3b82f6", low: "#9ca3af", info: "#4b5563" };

export function SeverityChart({ data }: Props) {
  const rows = [
    { name: "Critical", value: data.critical, fill: COLORS.critical },
    { name: "High", value: data.high, fill: COLORS.high },
    { name: "Medium", value: data.medium, fill: COLORS.medium },
    { name: "Low", value: data.low, fill: COLORS.low },
    { name: "Info", value: data.info, fill: COLORS.info },
  ];
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={rows} layout="vertical" margin={{ left: 10, right: 20 }}>
        <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 12 }} />
        <YAxis type="category" dataKey="name" tick={{ fill: "#9ca3af", fontSize: 12 }} width={70} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]}>
          {rows.map((r, i) => <Cell key={i} fill={r.fill} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
