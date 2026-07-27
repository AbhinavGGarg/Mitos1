import React from 'react'
import { createRoot } from 'react-dom/client'

/* Two voices, two faces. Instrument Serif carries display, Source Serif the prose,
   JetBrains Mono everything a program said or that instructs one. No sans anywhere. */
import '@fontsource/instrument-serif/400.css'
import '@fontsource-variable/source-serif-4'
import '@fontsource-variable/jetbrains-mono'

import App from './App.jsx'
import './styles.css'

createRoot(document.getElementById('root')).render(<App />)
