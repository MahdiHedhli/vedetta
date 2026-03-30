/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        display: ['"Instrument Serif"', 'Georgia', 'serif'],
        body: ['"DM Sans"', 'system-ui', 'sans-serif'],
        mono: ['"Space Mono"', '"Courier New"', 'monospace'],
      },
      colors: {
        // Foundation — Navy
        navy: {
          deep: '#070E1A',
          DEFAULT: '#0B1426',
          mid: '#111D33',
        },
        charcoal: {
          DEFAULT: '#1C2840',
          light: '#253350',
        },
        slate: '#3A4A6B',
        // Override gray scale to brand navy palette
        gray: {
          950: '#070E1A',
          900: '#0B1426',
          800: '#111D33',
          700: '#1C2840',
          600: '#253350',
          500: '#3A4A6B',
          400: '#7A879E',
          300: '#C0C8D8',
          200: '#E0E4EC',
          100: '#F0F2F7',
          50: '#F5F7FA',
        },
        // Primary Accent — Beacon Amber
        amber: {
          50: 'rgba(232,160,32,0.08)',
          100: 'rgba(232,160,32,0.15)',
          200: '#F5B731',
          300: '#F5B731',
          400: '#E8A020',
          500: '#E8A020',
          600: '#C4872A',
          700: '#A06B1E',
          800: '#7A5115',
          900: '#543A10',
        },
        // Secondary Accent — Signal Teal
        teal: {
          50: 'rgba(46,196,160,0.08)',
          100: 'rgba(46,196,160,0.12)',
          200: '#3EDDB5',
          300: '#3EDDB5',
          400: '#2EC4A0',
          500: '#2EC4A0',
          600: '#1E9A7A',
          700: '#177A61',
          800: '#115A47',
          900: '#0B3D30',
        },
        // Semantic
        red: {
          400: '#E85454',
          500: '#E85454',
        },
        green: {
          400: '#34D399',
          500: '#34D399',
        },
        blue: {
          400: '#5B8DEF',
          500: '#5B8DEF',
        },
      },
    },
  },
  plugins: [],
};
