/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: { DEFAULT: "#0b0f17", soft: "#111827", card: "#0f1623" },
        border: { DEFAULT: "#1f2937" },
        accent: { DEFAULT: "#22d3ee", muted: "#0891b2" },
      },
      fontFamily: {
        sans: ["-apple-system", "system-ui", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
