/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      colors: {
        ink: {
          900: "#070a0f",
          800: "#0b0f17",
          700: "#111722",
          600: "#1a2230",
          500: "#273142",
        },
        acid: {
          DEFAULT: "#39ff8b",
          dim: "#1f7a48",
        },
        amber: { DEFAULT: "#ffb454" },
        danger: { DEFAULT: "#ff5d6c" },
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(57,255,139,0.25), 0 0 24px -6px rgba(57,255,139,0.35)",
      },
      keyframes: {
        blink: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.25" } },
      },
      animation: { blink: "blink 1.1s steps(1) infinite" },
    },
  },
  plugins: [],
};
