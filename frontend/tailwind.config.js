/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}"
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        'sans': ['Inter', 'sans-serif'],
        'mono': ['Anonymous Pro', 'monospace']
      },
      colors: {
        // Minimalistic Black & Blue Theme
        bg: {
          primary: '#050505',   // Very dark black
          secondary: '#111111', // Slightly lighter for cards
          tertiary: '#1a1a1a'   // Borders/Separators
        },
        accent: {
          primary: '#2563eb',   // Electric Blue
          secondary: '#0ea5e9', // Cyan/Light Blue
          hover: '#1d4ed8'      // Darker blue for hover
        },
        text: {
          primary: '#f3f4f6',   // Off-white
          secondary: '#9ca3af', // Gray
          muted: '#6b7280'      // Darker gray
        },
        status: {
          success: '#10b981',
          error: '#ef4444',
          warning: '#f59e0b'
        }
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      }
    },
  },
  plugins: [],
}
