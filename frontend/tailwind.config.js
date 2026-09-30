/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        severity: {
          critical: '#ef4444', // red-500
          high: '#f59e0b', // amber-500
          medium: '#eab308', // yellow-500
          low: '#3b82f6', // blue-500
        }
      }
    },
  },
  plugins: [],
}
