/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        vedetta: {
          50: '#f0f7ff',
          100: '#e0effe',
          500: '#3b82f6',
          700: '#1d4ed8',
          900: '#1e3a5f',
        },
      },
    },
  },
  plugins: [],
};
