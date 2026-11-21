/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: [
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        graphite: {
          950: "#06080B",
          900: "#0B0E14",
          850: "#10141D",
          800: "#161C27",
          700: "#222B3B",
          600: "#344155",
        },
        cyan: {
          400: "#22D3EE",
          500: "#06B6D4",
          neon: "#00F0FF"
        },
        violet: {
          400: "#A78BFA",
          500: "#8B5CF6",
          neon: "#B388FF"
        },
        emerald: {
          400: "#34D399",
          500: "#10B981",
          neon: "#00E676"
        },
        amber: {
          400: "#FBBF24",
          500: "#F59E0B"
        },
        rose: {
          500: "#F43F5E",
          600: "#E11D48",
          neon: "#FF1744"
        }
      },
      fontFamily: {
        mono: ['var(--font-mono)', 'JetBrains Mono', 'Menlo', 'Consolas', 'monospace'],
        sans: ['var(--font-sans)', 'Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'cyan-glow': '0 0 20px -3px rgba(0, 240, 255, 0.35)',
        'violet-glow': '0 0 20px -3px rgba(139, 92, 246, 0.35)',
        'red-glow': '0 0 20px -3px rgba(239, 68, 68, 0.35)',
        'green-glow': '0 0 20px -3px rgba(16, 185, 129, 0.35)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 8s linear infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        }
      }
    },
  },
  plugins: [],
};
