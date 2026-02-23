
$ErrorActionPreference = "Stop"

Set-Location -Path (Resolve-Path "$PSScriptRoot\..")

if (-not (Get-Command vercel -ErrorAction SilentlyContinue)) {
  npm install -g vercel
}

if (-not (Test-Path .git)) {
  git init
  git remote add origin git@github.com:damianvomwege-cyber/JINU.git
}

if (-not (Test-Path .env)) {
  Copy-Item .env.example .env
}

vercel --prod
