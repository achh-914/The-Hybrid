<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 240" width="1280" height="240" role="img" aria-labelledby="t">
  <title id="t">Contributing</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#1b0f3d"/><stop offset="0.6" stop-color="#0d0a2b"/><stop offset="1" stop-color="#07061a"/>
    </linearGradient>
    <linearGradient id="ic" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#e9d5ff"/><stop offset="0.55" stop-color="#a855f7"/><stop offset="1" stop-color="#6366f1"/>
    </linearGradient>
    <linearGradient id="line" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#c084fc" stop-opacity="0"/><stop offset="0.3" stop-color="#c084fc"/>
      <stop offset="0.7" stop-color="#38bdf8"/><stop offset="1" stop-color="#38bdf8" stop-opacity="0"/>
    </linearGradient>
    <linearGradient id="word" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#c4b5fd"/></linearGradient>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#7c3aed" stroke-opacity="0.08"/></pattern>
    <radialGradient id="glow" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="#8b5cf6" stop-opacity="0.45"/><stop offset="1" stop-color="#8b5cf6" stop-opacity="0"/></radialGradient>
    <filter id="soft" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="3" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <style>
      text { font-family: Inter, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
      .tag { font-size: 15px; letter-spacing: 4px; fill: #a78bfa; font-weight: 600; }
      .title { font-size: 54px; font-weight: 800; fill: url(#word); letter-spacing: 1px; }
      .sub { font-size: 21px; fill: #c9c1f0; }
      .pulse { animation: p 3.2s ease-in-out infinite; }
      @keyframes p { 0%,100% { opacity: .45; } 50% { opacity: 1; } }
      @media (prefers-reduced-motion: reduce) { .pulse { animation: none; } }
    </style>
  </defs>
  <rect width="1280" height="240" rx="20" fill="url(#bg)"/>
  <rect width="1280" height="240" rx="20" fill="url(#grid)"/>
  <rect x="1" y="1" width="1278" height="238" rx="19" fill="none" stroke="#6d28d9" stroke-opacity="0.6" stroke-width="2"/>
  <circle cx="150" cy="120" r="130" fill="url(#glow)"/>
  <circle cx="1130" cy="40" r="150" fill="url(#glow)" opacity="0.5"/>

  <g transform="translate(150 120)" filter="url(#soft)">
    <rect x="-82" y="-82" width="164" height="164" rx="34" fill="#150f3a" stroke="url(#ic)" stroke-opacity="0.7" stroke-width="2"/>
    
  <g fill="none" stroke="url(#ic)" stroke-width="4" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="-22" cy="-30" r="9" fill="#7c3aed" fill-opacity="0.25"/>
    <circle cx="-22" cy="32" r="9" fill="#7c3aed" fill-opacity="0.25"/>
    <circle cx="24" cy="-8" r="9" fill="#7c3aed" fill-opacity="0.25"/>
    <path d="M-22 -21V23"/>
    <path d="M24 1C24 14 6 14 -10 22L-18 25"/>
  </g>
  </g>

  <text x="276" y="92" class="tag">THE HYBRID  ·  PROJECT POLICIES</text>
  <text x="274" y="154" class="title">Contributing</text>
  <text x="276" y="192" class="sub">Proprietary project. Contributions by invitation.</text>

  <g class="pulse" fill="#a78bfa">
    <circle cx="1090" cy="170" r="3"/><circle cx="1140" cy="120" r="2.2"/><circle cx="1190" cy="76" r="3.4"/>
    <circle cx="1210" cy="170" r="2"/><circle cx="1050" cy="90" r="2"/>
  </g>
  <g stroke="#7c3aed" stroke-opacity="0.5" fill="none"><path d="M1090 170L1140 120L1190 76M1140 120L1210 170M1050 90L1140 120"/></g>
  <rect x="276" y="214" width="728" height="3" rx="1.5" fill="url(#line)"/>
</svg>
