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
        'sans': ['Anonymous Pro', 'monospace']
      },
      colors: {
        'custom': {
          'dark-gray': '#222831',
          'gray': '#393E46',
          'light-gray': '#948979',
          'cream': '#DFD0B8',
          'light-bg': '#FBF8EF'
        },
        'retro': {
          'dark-border': '#000000',
          'terminal-green': '#00FF00',
          'terminal-amber': '#FFBF00',
          'crt-bg': '#0a0a0a'
        }
      },
      borderWidth: {
        '3': '3px',
        '4': '4px',
        '5': '5px'
      },
      boxShadow: {
        'retro': '4px 4px 0px 0px rgba(0,0,0,1)',
        'retro-inset': 'inset 2px 2px 4px rgba(0,0,0,0.5)'
      }
    },
  },
  plugins: [],
}
